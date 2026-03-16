"""
Service inspection module.

Checks for running services, identifies risky services, and detects outdated packages.
"""

from typing import Dict, List, Any
from . import utils


RISKY_SERVICES = [
    "telnet",
    "ftp",
    "rsh",
    "rlogin",
    "nis",
    "tftp",
    "talk",
    "finger",
    "snmp",
    "nfs",
    "vsftpd",
    "bluetooth",
]

IMPORTANT_SERVICES = [
    "ssh",
    "sshd",
    "apache2",
    "nginx",
    "mysql",
    "postgresql",
    "ufw",
    "firewalld",
    "fail2ban",
]


def check_running_services() -> List[str]:
    """
    Get list of running services.
    
    Returns:
        List of running service names.
    """
    services = []
    
    stdout, _, rc = utils.run_command("systemctl list-units --type=service --state=running --no-pager | awk '{print $1}'")
    
    if rc == 0:
        for line in stdout.split('\n'):
            line = line.strip()
            if line and not line.startswith("UNIT"):
                service_name = line.split('.')[0]
                if service_name:
                    services.append(service_name)
    
    return services


def check_risky_services() -> Dict[str, Any]:
    """
    Check for potentially risky or unnecessary services.
    
    Returns:
        Dictionary with risky service information.
    """
    running_services = check_running_services()
    
    risky_running = []
    for risky in RISKY_SERVICES:
        for service in running_services:
            if risky.lower() in service.lower():
                risky_running.append(service)
    
    return {
        "total_services": len(running_services),
        "risky_services": list(set(risky_running)),
        "risky_count": len(set(risky_running))
    }


def check_system_hardening() -> Dict[str, Any]:
    """
    Check system hardening measures.
    
    Returns:
        Dictionary with hardening check results.
    """
    hardening = {
        "checks": {}
    }
    
    running_services = check_running_services()
    
    # Check for fail2ban
    fail2ban_installed = any("fail2ban" in s.lower() for s in running_services)
    hardening["checks"]["fail2ban"] = {
        "name": "Fail2Ban",
        "installed": fail2ban_installed,
        "description": "Intrusion prevention software"
    }
    
    # Check for auditd
    auditd_installed = any("audit" in s.lower() for s in running_services)
    hardening["checks"]["auditd"] = {
        "name": "auditd",
        "installed": auditd_installed,
        "description": "System audit daemon"
    }
    
    # Check for SELinux/AppArmor
    stdout, _, rc = utils.run_command("getenforce 2>/dev/null")
    selinux_enabled = rc == 0 and "enforcing" in stdout.lower()
    
    hardening["checks"]["selinux"] = {
        "name": "SELinux",
        "enabled": selinux_enabled,
        "status": stdout.strip() if rc == 0 else "Not available"
    }
    
    # Check for automatic updates
    stdout, _, rc = utils.run_command("apt-config dump APT::Periodic::Update-Package-Lists 2>/dev/null")
    auto_updates = rc == 0 and "1" in stdout
    
    hardening["checks"]["auto_updates"] = {
        "name": "Automatic Updates",
        "enabled": auto_updates,
        "description": "Automatic security updates"
    }
    
    # Check cron jobs
    stdout, _, rc = utils.run_command("cat /etc/cron.d/* 2>/dev/null | grep -c .")
    cron_jobs = 0
    if rc == 0:
        try:
            cron_jobs = int(stdout.strip())
        except ValueError:
            pass
    
    hardening["checks"]["cron"] = {
        "name": "Cron Jobs",
        "count": cron_jobs,
        "description": "Scheduled tasks"
    }
    
    return hardening


def print_service_report(results: Dict[str, Any]) -> None:
    """
    Print service check report.
    
    Args:
        results: Service check results dictionary.
    """
    total = results.get("total_services", 0)
    risky_count = results.get("risky_count", 0)
    
    status = "✗" if risky_count > 0 else "✓"
    utils.print_result("Total Running Services", str(total), "•")
    utils.print_result("Risky Services Detected", str(risky_count), status)
    
    if risky_count > 0:
        risky = results.get("risky_services", [])
        print("\n  Risky Services Running:")
        for service in risky[:10]:
            print(f"    - {service}")


def print_hardening_report(results: Dict[str, Any]) -> None:
    """
    Print system hardening report.
    
    Args:
        results: Hardening check results dictionary.
    """
    checks = results.get("checks", {})
    
    for check_name, check_result in checks.items():
        if check_name == "fail2ban":
            status = "✓" if check_result["installed"] else "⚠"
            utils.print_result(check_result["name"], 
                              "Installed" if check_result["installed"] else "Not installed", 
                              status)
        
        elif check_name == "auditd":
            status = "✓" if check_result["installed"] else "⚠"
            utils.print_result(check_result["name"], 
                              "Installed" if check_result["installed"] else "Not installed", 
                              status)
        
        elif check_name == "selinux":
            status = "✓" if check_result.get("enabled") else "⚠"
            utils.print_result(check_result["name"], 
                              check_result["status"], 
                              status)
        
        elif check_name == "auto_updates":
            status = "✓" if check_result.get("enabled") else "⚠"
            utils.print_result(check_result["name"], 
                              "Enabled" if check_result["enabled"] else "Disabled", 
                              status)
        
        elif check_name == "cron":
            count = check_result.get("count", 0)
            utils.print_result(check_result["name"], f"{count} jobs", "•")
