"""
SSH security audit module.

Checks SSH configuration for security misconfigurations including
root login, password authentication, and port settings.
"""

from typing import Dict, Any
from . import utils


SSH_CONFIG_PATH = "/etc/ssh/sshd_config"

# SSH security checks to perform
SSH_CHECKS = [
    ("PermitRootLogin", "no"),
    ("PasswordAuthentication", "no"),
    ("PubkeyAuthentication", "yes"),
    ("PermitEmptyPasswords", "no"),
]


def read_ssh_config() -> Dict[str, str]:
    """
    Read and parse SSH configuration file.
    
    Returns:
        Dictionary of SSH configuration key-value pairs.
    """
    config = {}
    lines = utils.read_file_lines(SSH_CONFIG_PATH)
    
    for line in lines:
        line = line.strip()
        
        # Skip comments and empty lines
        if line.startswith('#') or not line:
            continue
        
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            config[key.lower()] = value.lower()
    
    return config


def check_root_login() -> Dict[str, Any]:
    """
    Check if root login is enabled via SSH.
    
    Returns:
        Dictionary with check results.
    """
    config = read_ssh_config()
    root_login = config.get("permitrootlogin", "yes")
    
    is_secure = root_login.lower() in ["no", "prohibit-password", "forced-commands-only"]
    
    return {
        "name": "Root Login",
        "value": root_login,
        "secure": is_secure,
        "recommendation": "Disable root login via SSH"
    }


def check_password_auth() -> Dict[str, Any]:
    """
    Check if password authentication is enabled.
    
    Returns:
        Dictionary with check results.
    """
    config = read_ssh_config()
    pwd_auth = config.get("passwordauthentication", "yes")
    
    is_secure = pwd_auth.lower() == "no"
    
    return {
        "name": "Password Authentication",
        "value": pwd_auth,
        "secure": is_secure,
        "recommendation": "Disable password authentication, use key-based auth only"
    }


def check_pubkey_auth() -> Dict[str, Any]:
    """
    Check if public key authentication is enabled.
    
    Returns:
        Dictionary with check results.
    """
    config = read_ssh_config()
    pubkey_auth = config.get("pubkeyauthentication", "yes")
    
    is_secure = pubkey_auth.lower() == "yes"
    
    return {
        "name": "Public Key Authentication",
        "value": pubkey_auth,
        "secure": is_secure,
        "recommendation": "Enable public key authentication"
    }


def check_empty_passwords() -> Dict[str, Any]:
    """
    Check if empty passwords are permitted.
    
    Returns:
        Dictionary with check results.
    """
    config = read_ssh_config()
    empty_pwd = config.get("permitemptypasswords", "no")
    
    is_secure = empty_pwd.lower() == "no"
    
    return {
        "name": "Empty Passwords",
        "value": empty_pwd,
        "secure": is_secure,
        "recommendation": "Never permit empty passwords"
    }


def check_ssh_port() -> Dict[str, Any]:
    """
    Check SSH listening port.
    
    Returns:
        Dictionary with check results.
    """
    config = read_ssh_config()
    port = config.get("port", "22")
    
    is_default = port == "22"
    
    return {
        "name": "SSH Port",
        "value": port,
        "default": is_default,
        "recommendation": "Change SSH port from default 22 to non-standard port"
    }


def check_protocol_version() -> Dict[str, Any]:
    """
    Check SSH protocol version.
    
    Returns:
        Dictionary with check results.
    """
    config = read_ssh_config()
    protocol = config.get("protocol", "2")
    
    is_secure = protocol == "2"
    
    return {
        "name": "Protocol Version",
        "value": protocol,
        "secure": is_secure,
        "recommendation": "Use SSH Protocol 2 only"
    }


def check_ssh_security() -> Dict[str, Any]:
    """
    Perform comprehensive SSH security audit.
    
    Returns:
        Dictionary containing all SSH security check results.
    """
    if not utils.file_exists(SSH_CONFIG_PATH):
        return {
            "ssh_available": False,
            "error": f"SSH config not found at {SSH_CONFIG_PATH}"
        }
    
    return {
        "ssh_available": True,
        "config_path": SSH_CONFIG_PATH,
        "checks": {
            "root_login": check_root_login(),
            "password_auth": check_password_auth(),
            "pubkey_auth": check_pubkey_auth(),
            "empty_passwords": check_empty_passwords(),
            "port": check_ssh_port(),
            "protocol": check_protocol_version(),
        }
    }


def print_ssh_report(results: Dict[str, Any]) -> None:
    """
    Print SSH security audit report.
    
    Args:
        results: SSH audit results dictionary.
    """
    if not results.get("ssh_available"):
        utils.print_status("SSH not configured or config not found", utils.Colors.YELLOW)
        return
    
    checks = results.get("checks", {})
    
    for check_name, check_result in checks.items():
        value = check_result.get("value", "N/A")
        
        if "secure" in check_result:
            status = "✓" if check_result["secure"] else "✗"
        elif "default" in check_result:
            status = "⚠" if check_result["default"] else "✓"
        else:
            status = "•"
        
        color = utils.Colors.GREEN if check_result.get("secure", True) else utils.Colors.RED
        print(f"  {check_result['name']}: {value} {status}")
