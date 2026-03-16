"""
Permission and user audit module.

Audits user permissions, detects world-writable files, SUID binaries,
and users with elevated privileges.
"""

from typing import Dict, List, Any
import pwd
import grp
import os
from . import utils


def check_uid_zero_users() -> List[str]:
    """
    Check for users with UID 0 (root privileges).
    
    Returns:
        List of usernames with UID 0.
    """
    users_with_uid_zero = []
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    username, _, uid = parts[0], parts[1], parts[2]
                    if uid == "0" and username != "root":
                        users_with_uid_zero.append(username)
    except Exception:
        pass
    
    return users_with_uid_zero


def check_users_without_passwords() -> List[str]:
    """
    Detect users with empty password fields.
    
    Returns:
        List of users without passwords.
    """
    users_no_pwd = []
    try:
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    username, pwd_field = parts[0], parts[1]
                    if pwd_field == "" or pwd_field == "!":
                        if username not in ["root", "sync", "shutdown", "halt"]:
                            users_no_pwd.append(username)
    except Exception:
        pass
    
    return users_no_pwd


def check_sudo_users() -> List[str]:
    """
    Identify users with sudo privileges.
    
    Returns:
        List of users with sudo access.
    """
    sudo_users = []
    try:
        with open("/etc/sudoers", "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if parts and parts[0] not in ["Defaults", "%"]:
                        sudo_users.append(parts[0])
    except Exception:
        pass
    
    # Also check sudoers.d
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        try:
            for filename in os.listdir(sudoers_d):
                filepath = os.path.join(sudoers_d, filename)
                try:
                    with open(filepath, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.split()
                                if parts and parts[0] not in ["Defaults", "%"]:
                                    if parts[0] not in sudo_users:
                                        sudo_users.append(parts[0])
                except Exception:
                    pass
        except Exception:
            pass
    
    return list(set(sudo_users))


def find_world_writable_files(search_path: str = "/") -> List[str]:
    """
    Find world-writable files in the system.
    
    Args:
        search_path: Root path to search (default: /).
    
    Returns:
        List of world-writable file paths.
    """
    world_writable = []
    dangerous_paths = ["/tmp", "/var/tmp", "/dev/shm", "/home"]
    
    for danger_path in dangerous_paths:
        if not os.path.exists(danger_path):
            continue
        
        try:
            for root, dirs, files in os.walk(danger_path):
                # Limit search depth to avoid timeout
                if root.count(os.sep) - danger_path.count(os.sep) > 3:
                    del dirs[:]
                    continue
                
                for filename in files[:100]:  # Limit files per directory
                    filepath = os.path.join(root, filename)
                    if utils.is_world_writable(filepath):
                        world_writable.append(filepath)
        except Exception:
            pass
    
    return world_writable[:100]  # Limit results


def find_suid_binaries(search_path: str = "/usr/bin") -> List[str]:
    """
    Find SUID binaries on the system.
    
    Args:
        search_path: Path to search for SUID binaries.
    
    Returns:
        List of SUID binary paths.
    """
    suid_binaries = []
    
    if not os.path.exists(search_path):
        return []
    
    try:
        for root, dirs, files in os.walk(search_path):
            # Limit search depth
            if root.count(os.sep) - search_path.count(os.sep) > 2:
                del dirs[:]
                continue
            
            for filename in files[:500]:  # Limit files per directory
                filepath = os.path.join(root, filename)
                if utils.has_suid_bit(filepath):
                    suid_binaries.append(filepath)
    except Exception:
        pass
    
    return suid_binaries


def check_passwd_permissions() -> Dict[str, Any]:
    """
    Check permissions of /etc/passwd and /etc/shadow.
    
    Returns:
        Dictionary with permission check results.
    """
    passwd_perm = utils.get_file_permissions("/etc/passwd")
    shadow_perm = utils.get_file_permissions("/etc/shadow")
    
    return {
        "passwd": {
            "path": "/etc/passwd",
            "permissions": passwd_perm,
            "secure": passwd_perm in ["644", "444"]
        },
        "shadow": {
            "path": "/etc/shadow",
            "permissions": shadow_perm,
            "secure": shadow_perm in ["640", "440", "000"]
        }
    }


def audit_permissions() -> Dict[str, Any]:
    """
    Perform comprehensive permission and user audit.
    
    Returns:
        Dictionary with audit results.
    """
    return {
        "uid_zero_users": check_uid_zero_users(),
        "users_without_password": check_users_without_passwords(),
        "sudo_users": check_sudo_users(),
        "world_writable_files": find_world_writable_files()[:10],
        "suid_binaries": find_suid_binaries()[:20],
        "file_permissions": check_passwd_permissions()
    }


def print_permission_report(results: Dict[str, Any]) -> None:
    """
    Print permission audit report.
    
    Args:
        results: Audit results dictionary.
    """
    # UID 0 users
    uid_zero = results.get("uid_zero_users", [])
    status = "✗" if uid_zero else "✓"
    utils.print_result("UID 0 Users (excluding root)", 
                      f"{len(uid_zero)}", status)
    if uid_zero:
        for user in uid_zero:
            print(f"    - {user}")
    
    # Users without password
    no_pwd = results.get("users_without_password", [])
    status = "✗" if no_pwd else "✓"
    utils.print_result("Users Without Password", 
                      f"{len(no_pwd)}", status)
    if no_pwd:
        for user in no_pwd[:5]:
            print(f"    - {user}")
    
    # Sudo users
    sudo_users = results.get("sudo_users", [])
    utils.print_result("Users with Sudo Access", f"{len(sudo_users)}", "•")
    if sudo_users:
        for user in sudo_users[:5]:
            print(f"    - {user}")
    
    # World writable files
    world_writable = results.get("world_writable_files", [])
    status = "⚠" if world_writable else "✓"
    utils.print_result("World Writable Files", 
                      f"{len(world_writable)}", status)
    if world_writable:
        for filepath in world_writable[:5]:
            print(f"    - {filepath}")
    
    # SUID binaries
    suid = results.get("suid_binaries", [])
    utils.print_result("SUID Binaries Found", f"{len(suid)}", "•")
    
    # File permissions
    file_perms = results.get("file_permissions", {})
    passwd_secure = file_perms.get("passwd", {}).get("secure", False)
    shadow_secure = file_perms.get("shadow", {}).get("secure", False)
    
    status = "✓" if passwd_secure else "⚠"
    utils.print_result("/etc/passwd permissions", 
                      file_perms.get("passwd", {}).get("permissions", "unknown"), status)
    
    status = "✓" if shadow_secure else "⚠"
    utils.print_result("/etc/shadow permissions", 
                      file_perms.get("shadow", {}).get("permissions", "unknown"), status)
