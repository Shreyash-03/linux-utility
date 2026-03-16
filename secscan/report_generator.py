"""
Report generation module.

Generates human-readable security audit reports in various formats.
"""

from typing import Dict, Any
from datetime import datetime
from . import scoring


def generate_text_report(results: Dict[str, Any]) -> str:
    """
    Generate a text-formatted security audit report.
    
    Args:
        results: Dictionary containing all scan results.
    
    Returns:
        Formatted text report.
    """
    report = []
    
    report.append("=" * 60)
    report.append("       LINUX SECURITY AUDIT REPORT")
    report.append("=" * 60)
    report.append("")
    
    # Header information
    timestamp = results.get("timestamp", "Unknown")
    scan_type = results.get("scan_type", "unknown")
    
    report.append(f"Generated: {timestamp}")
    report.append(f"Scan Type: {scan_type.upper()}")
    report.append("")
    
    # SSH Configuration
    ssh_results = results.get("checks", {}).get("ssh", {})
    if ssh_results.get("ssh_available"):
        report.append("-" * 60)
        report.append("[SSH Configuration]")
        report.append("-" * 60)
        
        checks = ssh_results.get("checks", {})
        for check_name, check_result in checks.items():
            status = "SECURE ✓" if check_result.get("secure") else "INSECURE ✗"
            report.append(f"  {check_result.get('name')}: {status}")
            report.append(f"    Value: {check_result.get('value')}")
    
    # Login Attempts
    login_results = results.get("checks", {}).get("login_attempts", {})
    if login_results.get("available"):
        report.append("")
        report.append("-" * 60)
        report.append("[Login Attempt Analysis]")
        report.append("-" * 60)
        
        failed = login_results.get("failed_logins", 0)
        unique_ips = login_results.get("unique_failed_ips", 0)
        brute_force = login_results.get("brute_force_detected", False)
        
        report.append(f"  Failed Login Attempts: {failed}")
        report.append(f"  Unique Failed IPs: {unique_ips}")
        
        if brute_force:
            report.append("  ⚠ WARNING: Possible brute force attack detected!")
        
        top_ips = login_results.get("top_attacking_ips", [])
        if top_ips:
            report.append("\n  Top Attacking IP Addresses:")
            for ip, count in top_ips[:5]:
                report.append(f"    {ip}: {count} attempts")
    
    # Permissions
    perm_results = results.get("checks", {}).get("permissions", {})
    if perm_results:
        report.append("")
        report.append("-" * 60)
        report.append("[User & Permission Audit]")
        report.append("-" * 60)
        
        uid_zero = perm_results.get("uid_zero_users", [])
        if uid_zero:
            report.append(f"  ⚠ Users with UID 0: {len(uid_zero)}")
            for user in uid_zero:
                report.append(f"    - {user}")
        
        no_pwd = perm_results.get("users_without_password", [])
        if no_pwd:
            report.append(f"  ⚠ Users without passwords: {len(no_pwd)}")
            for user in no_pwd[:5]:
                report.append(f"    - {user}")
        
        sudo_users = perm_results.get("sudo_users", [])
        report.append(f"  Sudo Users: {len(sudo_users)}")
        
        world_writable = perm_results.get("world_writable_files", [])
        report.append(f"  World Writable Files: {len(world_writable)}")
        
        suid = perm_results.get("suid_binaries", [])
        report.append(f"  SUID Binaries: {len(suid)}")
    
    # Firewall
    firewall_results = results.get("checks", {}).get("firewall", {})
    if firewall_results:
        report.append("")
        report.append("-" * 60)
        report.append("[Firewall & Network Audit]")
        report.append("-" * 60)
        
        firewall_active = firewall_results.get("firewall_active", False)
        status = "ACTIVE ✓" if firewall_active else "INACTIVE ✗"
        report.append(f"  Firewall Status: {status}")
        
        ufw = firewall_results.get("ufw", {})
        if ufw.get("installed"):
            report.append(f"  UFW: {'Active' if ufw.get('active') else 'Inactive'}")
        
        firewalld = firewall_results.get("firewalld", {})
        if firewalld.get("installed"):
            report.append(f"  Firewalld: {'Active' if firewalld.get('active') else 'Inactive'}")
        
        ports_results = results.get("checks", {}).get("ports", {})
        open_ports = ports_results.get("open_ports_count", 0)
        report.append(f"  Open Ports: {open_ports}")
    
    # Services
    service_results = results.get("checks", {}).get("services", {})
    if service_results:
        report.append("")
        report.append("-" * 60)
        report.append("[Service Inspection]")
        report.append("-" * 60)
        
        total = service_results.get("total_services", 0)
        risky = service_results.get("risky_count", 0)
        
        report.append(f"  Total Running Services: {total}")
        if risky > 0:
            report.append(f"  ⚠ Risky Services Detected: {risky}")
            for service in service_results.get("risky_services", [])[:5]:
                report.append(f"    - {service}")
    
    # System Hardening
    hardening_results = results.get("checks", {}).get("hardening", {})
    if hardening_results:
        report.append("")
        report.append("-" * 60)
        report.append("[System Hardening]")
        report.append("-" * 60)
        
        checks = hardening_results.get("checks", {})
        for check_name, check_result in checks.items():
            if check_name == "fail2ban":
                status = "Installed ✓" if check_result.get("installed") else "Not installed ✗"
                report.append(f"  Fail2Ban: {status}")
            elif check_name == "auditd":
                status = "Installed ✓" if check_result.get("installed") else "Not installed ✗"
                report.append(f"  auditd: {status}")
            elif check_name == "selinux":
                status = "Enabled ✓" if check_result.get("enabled") else "Disabled ⚠"
                report.append(f"  SELinux: {status}")
            elif check_name == "auto_updates":
                status = "Enabled ✓" if check_result.get("enabled") else "Disabled ⚠"
                report.append(f"  Automatic Updates: {status}")
    
    # Security Score
    score_data = results.get("security_score", {})
    if score_data:
        report.append("")
        report.append("=" * 60)
        report.append("[SECURITY SCORE]")
        report.append("=" * 60)
        
        total = score_data.get("total", 0)
        grade = scoring.get_score_grade(total)
        
        report.append(f"Overall Score: {total}/100")
        report.append(f"Grade: {grade}")
        
        report.append("\nBreakdown:")
        breakdown = score_data.get("breakdown", {})
        for category, points in breakdown.items():
            report.append(f"  {category.replace('_', ' ').title()}: {points:.0f} points")
    
    # Recommendations
    report.append("")
    report.append("=" * 60)
    report.append("[RECOMMENDATIONS]")
    report.append("=" * 60)
    
    recommendations = generate_recommendations(results)
    for rec in recommendations:
        report.append(f"  • {rec}")
    
    report.append("")
    report.append("=" * 60)
    report.append("End of Report")
    report.append("=" * 60)
    
    return "\n".join(report)


def generate_recommendations(results: Dict[str, Any]) -> list:
    """
    Generate security recommendations based on audit results.
    
    Args:
        results: Dictionary containing all scan results.
    
    Returns:
        List of recommendations.
    """
    recommendations = []
    
    # SSH recommendations
    ssh_results = results.get("checks", {}).get("ssh", {})
    if ssh_results.get("ssh_available"):
        checks = ssh_results.get("checks", {})
        
        if not checks.get("root_login", {}).get("secure"):
            recommendations.append("Disable root SSH login in sshd_config")
        
        if not checks.get("password_auth", {}).get("secure"):
            recommendations.append("Disable SSH password authentication; use key-based auth only")
        
        if checks.get("port", {}).get("default"):
            recommendations.append("Change SSH port from default 22 to non-standard port")
    
    # Login attempt recommendations
    login_results = results.get("checks", {}).get("login_attempts", {})
    if login_results.get("brute_force_detected"):
        recommendations.append("Implement rate limiting and install fail2ban to prevent brute force attacks")
    
    # Permission recommendations
    perm_results = results.get("checks", {}).get("permissions", {})
    if perm_results.get("uid_zero_users"):
        recommendations.append("Remove unnecessary users with UID 0 (root privileges)")
    
    if perm_results.get("users_without_password"):
        recommendations.append("Set passwords for all user accounts")
    
    world_writable = perm_results.get("world_writable_files", [])
    if len(world_writable) > 10:
        recommendations.append("Restrict permissions on world-writable files")
    
    # Firewall recommendations
    firewall_results = results.get("checks", {}).get("firewall", {})
    if not firewall_results.get("firewall_active"):
        recommendations.append("Enable and configure firewall (UFW, firewalld, or iptables)")
    
    # Service recommendations
    service_results = results.get("checks", {}).get("services", {})
    if service_results.get("risky_count", 0) > 0:
        recommendations.append("Disable or remove unnecessary and risky services")
    
    # Hardening recommendations
    hardening_results = results.get("checks", {}).get("hardening", {})
    checks = hardening_results.get("checks", {})
    
    if not checks.get("fail2ban", {}).get("installed"):
        recommendations.append("Install and configure fail2ban for intrusion prevention")
    
    if not checks.get("auditd", {}).get("installed"):
        recommendations.append("Install and enable auditd for system auditing")
    
    if not checks.get("selinux", {}).get("enabled"):
        recommendations.append("Enable SELinux or AppArmor for mandatory access control")
    
    if not checks.get("auto_updates", {}).get("enabled"):
        recommendations.append("Enable automatic security updates")
    
    if not recommendations:
        recommendations.append("System appears well-configured. Continue monitoring and regular updates.")
    
    return recommendations
