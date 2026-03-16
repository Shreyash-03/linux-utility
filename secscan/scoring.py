"""
Security scoring module.

Calculates an overall security score based on audit results.
"""

from typing import Dict, Any
from . import utils


def calculate_ssh_score(results: Dict[str, Any]) -> float:
    """Calculate SSH security score."""
    if not results.get("checks", {}).get("ssh", {}).get("ssh_available"):
        return 0.0
    
    ssh_results = results["checks"]["ssh"]
    checks = ssh_results.get("checks", {})
    
    score = 0.0
    total_checks = len(checks)
    
    if total_checks == 0:
        return 0.0
    
    for check_name, check_result in checks.items():
        if check_result.get("secure"):
            score += 1.0
    
    return (score / total_checks) * 20  # SSH is worth 20 points


def calculate_login_score(results: Dict[str, Any]) -> float:
    """Calculate login attempt security score."""
    login_results = results.get("checks", {}).get("login_attempts", {})
    
    if not login_results.get("available"):
        return 15.0  # Assume okay if not available
    
    score = 15.0
    
    # Deduct for brute force attempts
    if login_results.get("brute_force_detected"):
        score -= 10.0
    
    # Deduct based on failed login attempts
    failed = login_results.get("failed_logins", 0)
    if failed > 100:
        score -= 5.0
    elif failed > 50:
        score -= 3.0
    elif failed > 10:
        score -= 1.0
    
    return max(0.0, score)


def calculate_permission_score(results: Dict[str, Any]) -> float:
    """Calculate permission security score."""
    perm_results = results.get("checks", {}).get("permissions", {})
    
    score = 20.0
    
    # Deduct for uid 0 users
    if perm_results.get("uid_zero_users"):
        score -= 5.0
    
    # Deduct for users without password
    if perm_results.get("users_without_password"):
        score -= 5.0
    
    # Deduct for world writable files
    world_writable = perm_results.get("world_writable_files", [])
    if len(world_writable) > 10:
        score -= 5.0
    elif len(world_writable) > 0:
        score -= 2.0
    
    # Check file permissions
    file_perms = perm_results.get("file_permissions", {})
    if not file_perms.get("passwd", {}).get("secure"):
        score -= 2.0
    if not file_perms.get("shadow", {}).get("secure"):
        score -= 3.0
    
    return max(0.0, score)


def calculate_firewall_score(results: Dict[str, Any]) -> float:
    """Calculate firewall security score."""
    firewall_results = results.get("checks", {}).get("firewall", {})
    
    score = 15.0
    
    # Deduct if firewall not active
    if not firewall_results.get("firewall_active"):
        score -= 15.0
    
    # Check open ports
    ports_results = results.get("checks", {}).get("ports", {})
    open_ports = ports_results.get("open_ports_count", 0)
    
    if open_ports > 10:
        score -= 5.0
    elif open_ports > 5:
        score -= 2.0
    
    return max(0.0, score)


def calculate_service_score(results: Dict[str, Any]) -> float:
    """Calculate service security score."""
    service_results = results.get("checks", {}).get("services", {})
    
    score = 15.0
    
    # Deduct for risky services
    risky_count = service_results.get("risky_count", 0)
    if risky_count > 0:
        score -= min(10.0, risky_count * 2.0)
    
    return max(0.0, score)


def calculate_hardening_score(results: Dict[str, Any]) -> float:
    """Calculate system hardening score."""
    hardening_results = results.get("checks", {}).get("hardening", {})
    
    score = 15.0
    checks = hardening_results.get("checks", {})
    
    # Award points for hardening measures
    if checks.get("fail2ban", {}).get("installed"):
        score += 2.0
    if checks.get("auditd", {}).get("installed"):
        score += 2.0
    if checks.get("selinux", {}).get("enabled"):
        score += 3.0
    if checks.get("auto_updates", {}).get("enabled"):
        score += 3.0
    
    return min(15.0, score)


def calculate_security_score(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate overall security score from audit results.
    
    Args:
        results: Dictionary containing all scan results.
    
    Returns:
        Dictionary with score breakdown and overall score.
    """
    scores = {
        "ssh": calculate_ssh_score(results),
        "login_attempts": calculate_login_score(results),
        "permissions": calculate_permission_score(results),
        "firewall": calculate_firewall_score(results),
        "services": calculate_service_score(results),
        "hardening": calculate_hardening_score(results),
    }
    
    total_score = sum(scores.values())
    
    return {
        "total": int(total_score),
        "breakdown": scores,
        "max_score": 100
    }


def get_score_grade(score: int) -> str:
    """
    Get letter grade for security score.
    
    Args:
        score: Numerical security score.
    
    Returns:
        Letter grade.
    """
    if score >= 90:
        return "A - Excellent"
    elif score >= 80:
        return "B - Good"
    elif score >= 70:
        return "C - Fair"
    elif score >= 60:
        return "D - Poor"
    else:
        return "F - Critical"


def print_score_summary(score_data: Dict[str, Any]) -> None:
    """
    Print security score summary.
    
    Args:
        score_data: Score calculation results.
    """
    total = score_data.get("total", 0)
    breakdown = score_data.get("breakdown", {})
    
    grade = get_score_grade(total)
    
    # Determine color based on score
    if total >= 80:
        color = utils.Colors.GREEN
    elif total >= 60:
        color = utils.Colors.YELLOW
    else:
        color = utils.Colors.RED
    
    utils.print_status(f"Overall Security Score: {total}/100 ({grade})", color)
    
    print("\nScore Breakdown:")
    for category, points in breakdown.items():
        print(f"  {category.replace('_', ' ').title()}: {points:.0f} points")
