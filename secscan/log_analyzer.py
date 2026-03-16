"""
Login attempt analysis module.

Analyzes authentication logs to detect failed login attempts,
brute force attacks, and suspicious patterns.
"""

from typing import Dict, List, Any
from collections import defaultdict
from . import utils


# Try multiple possible auth log locations
AUTH_LOG_PATHS = [
    "/var/log/auth.log",      # Debian/Ubuntu
    "/var/log/secure",        # RHEL/CentOS
    "/var/log/syslog",        # Fallback
]


def get_auth_log_path() -> str:
    """
    Find the authentication log file.
    
    Returns:
        Path to the auth log file, or empty string if not found.
    """
    for path in AUTH_LOG_PATHS:
        if utils.file_exists(path):
            return path
    return ""


def parse_auth_log() -> List[Dict[str, str]]:
    """
    Parse authentication log entries.
    
    Returns:
        List of dictionaries containing log entries.
    """
    auth_log_path = get_auth_log_path()
    
    if not auth_log_path:
        return []
    
    entries = []
    lines = utils.read_file_lines(auth_log_path)
    
    for line in lines:
        if not line.strip():
            continue
        
        entry = {
            "raw": line.strip()
        }
        
        # Extract IP addresses
        if "from" in line:
            parts = line.split("from")
            if len(parts) > 1:
                ip_part = parts[1].strip().split()[0]
                entry["ip"] = ip_part
        
        # Detect failed login attempts
        if "Failed password" in line or "Invalid user" in line:
            entry["type"] = "failed_login"
        elif "Accepted" in line:
            entry["type"] = "accepted_login"
        
        entries.append(entry)
    
    return entries


def detect_brute_force() -> Dict[str, Any]:
    """
    Detect brute force attack patterns.
    
    Returns:
        Dictionary with brute force analysis results.
    """
    entries = parse_auth_log()
    
    failed_ips = defaultdict(int)
    
    for entry in entries:
        if entry.get("type") == "failed_login" and "ip" in entry:
            failed_ips[entry["ip"]] += 1
    
    # Threshold for suspected brute force
    brute_force_threshold = 10
    suspicious_ips = {ip: count for ip, count in failed_ips.items() 
                     if count > brute_force_threshold}
    
    return {
        "failed_logins": len([e for e in entries if e.get("type") == "failed_login"]),
        "unique_failed_ips": len(failed_ips),
        "suspicious_ips": suspicious_ips,
        "brute_force_detected": len(suspicious_ips) > 0
    }


def get_top_attacking_ips(limit: int = 5) -> List[tuple]:
    """
    Get top IP addresses with failed login attempts.
    
    Args:
        limit: Number of top IPs to return.
    
    Returns:
        List of tuples (ip, count) sorted by count.
    """
    entries = parse_auth_log()
    
    failed_ips = defaultdict(int)
    for entry in entries:
        if entry.get("type") == "failed_login" and "ip" in entry:
            failed_ips[entry["ip"]] += 1
    
    # Sort by count descending
    sorted_ips = sorted(failed_ips.items(), key=lambda x: x[1], reverse=True)
    return sorted_ips[:limit]


def analyze_login_attempts() -> Dict[str, Any]:
    """
    Perform comprehensive login attempt analysis.
    
    Returns:
        Dictionary with analysis results.
    """
    auth_log_path = get_auth_log_path()
    
    if not auth_log_path:
        return {
            "available": False,
            "error": "Authentication log not found"
        }
    
    brute_force = detect_brute_force()
    top_ips = get_top_attacking_ips()
    
    return {
        "available": True,
        "log_path": auth_log_path,
        "failed_logins": brute_force["failed_logins"],
        "unique_failed_ips": brute_force["unique_failed_ips"],
        "brute_force_detected": brute_force["brute_force_detected"],
        "suspicious_ips": brute_force["suspicious_ips"],
        "top_attacking_ips": top_ips
    }


def print_login_report(results: Dict[str, Any]) -> None:
    """
    Print login attempt analysis report.
    
    Args:
        results: Analysis results dictionary.
    """
    if not results.get("available"):
        utils.print_status("Authentication log not available", utils.Colors.YELLOW)
        return
    
    failed = results.get("failed_logins", 0)
    unique_ips = results.get("unique_failed_ips", 0)
    brute_force = results.get("brute_force_detected", False)
    
    utils.print_result("Failed Login Attempts", str(failed),
                      "✗" if failed > 50 else "⚠" if failed > 10 else "✓")
    utils.print_result("Unique Failed IPs", str(unique_ips),
                      "⚠" if unique_ips > 5 else "✓")
    
    if brute_force:
        utils.print_status("⚠ Possible brute force attack detected!", utils.Colors.RED)
    
    top_ips = results.get("top_attacking_ips", [])
    if top_ips:
        print("\n  Top Attacking IP Addresses:")
        for ip, count in top_ips[:5]:
            print(f"    {ip}: {count} attempts")
