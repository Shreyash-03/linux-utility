"""
Utility functions for the linux-sec-audit tool.

Provides common functionality including color output, privilege checking,
safe file reading, and helper functions.
"""

import os
import subprocess
from typing import List, Optional, Tuple
from enum import Enum


class Colors(Enum):
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def is_root() -> bool:
    """
    Check if the script is running with root privileges.
    
    Returns:
        bool: True if UID is 0, False otherwise.
    """
    return os.getuid() == 0


def print_banner() -> None:
    """Print the application banner."""
    banner = f"""
{Colors.BOLD.value}{Colors.CYAN.value}
=====================================
 Linux Security Audit Report (v1.0)
=====================================
{Colors.RESET.value}
    """
    print(banner)


def print_header(title: str) -> None:
    """
    Print a formatted section header.
    
    Args:
        title: The header title to print.
    """
    print(f"\n{Colors.BOLD.value}{Colors.BLUE.value}[{title}]{Colors.RESET.value}")
    print("-" * (len(title) + 2))


def print_status(message: str, color: Colors = Colors.RESET) -> None:
    """
    Print a status message with optional color.
    
    Args:
        message: The message to print.
        color: Optional color enumeration.
    """
    print(f"{color.value}{message}{Colors.RESET.value}")


def print_result(key: str, value: str, status: Optional[str] = None) -> None:
    """
    Print a key-value result with optional status indicator.
    
    Args:
        key: The result key/label.
        value: The result value.
        status: Optional status indicator ('✓', '⚠', '✗').
    """
    status_text = f" {status}" if status else ""
    print(f"  {Colors.BOLD.value}{key}:{Colors.RESET.value} {value}{status_text}")


def run_command(command: str, shell: bool = True) -> Tuple[str, str, int]:
    """
    Execute a shell command safely.
    
    Args:
        command: The command to execute.
        shell: Whether to use shell execution.
    
    Returns:
        Tuple of (stdout, stderr, return_code).
    """
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timeout", 1
    except Exception as e:
        return "", str(e), 1


def read_file(filepath: str) -> Optional[str]:
    """
    Safely read a file's contents.
    
    Args:
        filepath: Path to the file to read.
    
    Returns:
        File contents as string, or None if file doesn't exist or can't be read.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except (FileNotFoundError, PermissionError, IOError):
        return None


def read_file_lines(filepath: str) -> List[str]:
    """
    Safely read a file line by line.
    
    Args:
        filepath: Path to the file to read.
    
    Returns:
        List of file lines, or empty list if file doesn't exist.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except (FileNotFoundError, PermissionError, IOError):
        return []


def get_config_value(filepath: str, key: str) -> Optional[str]:
    """
    Extract a configuration value from a config file.
    
    Args:
        filepath: Path to the config file.
        key: The configuration key to search for.
    
    Returns:
        The configuration value, or None if not found.
    """
    lines = read_file_lines(filepath)
    for line in lines:
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        
        if line.startswith(key):
            parts = line.split(None, 1)
            if len(parts) > 1:
                return parts[1]
    
    return None


def file_exists(filepath: str) -> bool:
    """
    Check if a file exists.
    
    Args:
        filepath: Path to check.
    
    Returns:
        bool: True if file exists, False otherwise.
    """
    return os.path.exists(filepath) and os.path.isfile(filepath)


def get_file_permissions(filepath: str) -> Optional[str]:
    """
    Get file permissions in readable format.
    
    Args:
        filepath: Path to the file.
    
    Returns:
        Permission string (e.g., '644'), or None if file doesn't exist.
    """
    try:
        stat_info = os.stat(filepath)
        return oct(stat_info.st_mode)[-3:]
    except (FileNotFoundError, OSError):
        return None


def is_world_writable(filepath: str) -> bool:
    """
    Check if a file is world-writable.
    
    Args:
        filepath: Path to check.
    
    Returns:
        bool: True if world-writable, False otherwise.
    """
    try:
        stat_info = os.stat(filepath)
        return bool(stat_info.st_mode & 0o002)
    except (FileNotFoundError, OSError):
        return False


def has_suid_bit(filepath: str) -> bool:
    """
    Check if a file has the SUID bit set.
    
    Args:
        filepath: Path to check.
    
    Returns:
        bool: True if SUID bit is set, False otherwise.
    """
    try:
        stat_info = os.stat(filepath)
        return bool(stat_info.st_mode & 0o4000)
    except (FileNotFoundError, OSError):
        return False


def is_service_running(service_name: str) -> bool:
    """
    Check if a service is currently running.
    
    Args:
        service_name: Name of the service to check.
    
    Returns:
        bool: True if service is running, False otherwise.
    """
    stdout, _, returncode = run_command(f"systemctl is-active {service_name}")
    return returncode == 0 and "active" in stdout.lower()


def get_service_status(service_name: str) -> str:
    """
    Get the status of a service.
    
    Args:
        service_name: Name of the service.
    
    Returns:
        Service status string.
    """
    stdout, _, _ = run_command(f"systemctl is-active {service_name}")
    return stdout if stdout else "unknown"
