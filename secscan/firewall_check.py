"""
Firewall and network audit module.

Checks firewall status, listening ports, and exposed services.
"""

from typing import Dict, List, Any
from . import utils


def check_firewall_status() -> Dict[str, Any]:
    """
    Check firewall status (ufw, firewalld, iptables).
    
    Returns:
        Dictionary with firewall status information.
    """
    firewall_status = {
        "ufw": {"installed": False, "active": False},
        "firewalld": {"installed": False, "active": False},
        "iptables": {"installed": False, "rules": 0},
    }
    
    # Check UFW
    stdout, _, rc = utils.run_command("which ufw")
    if rc == 0:
        firewall_status["ufw"]["installed"] = True
        firewall_status["ufw"]["active"] = utils.is_service_running("ufw")
    
    # Check Firewalld
    stdout, _, rc = utils.run_command("which firewalld")
    if rc == 0:
        firewall_status["firewalld"]["installed"] = True
        firewall_status["firewalld"]["active"] = utils.is_service_running("firewalld")
    
    # Check iptables
    stdout, _, rc = utils.run_command("iptables -L -n | wc -l")
    if rc == 0:
        try:
            count = int(stdout.strip())
            firewall_status["iptables"]["installed"] = True
            firewall_status["iptables"]["rules"] = count
        except ValueError:
            pass
    
    # Determine overall status
    firewall_status["firewall_active"] = (
        firewall_status["ufw"]["active"] or 
        firewall_status["firewalld"]["active"] or
        firewall_status["iptables"]["rules"] > 10
    )
    
    return firewall_status


def check_listening_ports() -> Dict[str, Any]:
    """
    Check listening ports and services.
    
    Returns:
        Dictionary with listening ports information.
    """
    ports_info = {
        "listening_ports": [],
        "open_ports_count": 0
    }
    
    # Try using netstat or ss
    stdout, _, rc = utils.run_command("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    
    if rc == 0:
        lines = stdout.split('\n')
        
        for line in lines:
            if not line.strip() or "LISTEN" not in line:
                continue
            
            parts = line.split()
            
            # Extract port from address
            for part in parts:
                if ':' in part and part.split(':')[-1].isdigit():
                    port = part.split(':')[-1]
                    service = ""
                    
                    # Extract service name if available
                    if len(parts) > 0:
                        service = parts[-1].split('/')[-1]
                    
                    ports_info["listening_ports"].append({
                        "port": port,
                        "service": service
                    })
                    break
    
    # Remove duplicates
    unique_ports = []
    seen_ports = set()
    for port_info in ports_info["listening_ports"]:
        port = port_info["port"]
        if port not in seen_ports:
            unique_ports.append(port_info)
            seen_ports.add(port)
    
    ports_info["listening_ports"] = unique_ports
    ports_info["open_ports_count"] = len(unique_ports)
    
    return ports_info


def check_exposed_services() -> List[str]:
    """
    Identify potentially exposed or risky services listening on network.
    
    Returns:
        List of risky listening services.
    """
    risky_ports = {
        "23": "telnet",      # Unencrypted remote login
        "21": "ftp",         # Unencrypted file transfer
        "69": "tftp",        # Trivial FTP
        "79": "finger",      # User info service
        "135": "rpc",        # RPC endpoint
        "139": "netbios",    # NetBIOS
        "445": "smb",        # SMB/Samba
        "3389": "rdp",       # Windows RDP
    }
    
    ports = check_listening_ports()
    exposed = []
    
    for port_info in ports["listening_ports"]:
        port = port_info["port"]
        if port in risky_ports:
            exposed.append(f"{risky_ports[port]} (port {port})")
    
    return exposed


def check_firewall_status() -> Dict[str, Any]:
    """
    Check firewall status (ufw, firewalld, iptables).
    
    Returns:
        Dictionary with firewall status information.
    """
    firewall_status = {
        "ufw": {"installed": False, "active": False},
        "firewalld": {"installed": False, "active": False},
        "iptables": {"installed": False, "rules": 0},
    }
    
    # Check UFW
    stdout, _, rc = utils.run_command("which ufw")
    if rc == 0:
        firewall_status["ufw"]["installed"] = True
        firewall_status["ufw"]["active"] = utils.is_service_running("ufw")
    
    # Check Firewalld
    stdout, _, rc = utils.run_command("which firewalld")
    if rc == 0:
        firewall_status["firewalld"]["installed"] = True
        firewall_status["firewalld"]["active"] = utils.is_service_running("firewalld")
    
    # Check iptables
    stdout, _, rc = utils.run_command("iptables -L -n 2>/dev/null | wc -l")
    if rc == 0:
        try:
            count = int(stdout.strip())
            firewall_status["iptables"]["installed"] = True
            firewall_status["iptables"]["rules"] = count
        except ValueError:
            pass
    
    # Determine overall status
    firewall_status["firewall_active"] = (
        firewall_status["ufw"]["active"] or 
        firewall_status["firewalld"]["active"] or
        firewall_status["iptables"]["rules"] > 10
    )
    
    return firewall_status


def print_firewall_report(results: Dict[str, Any]) -> None:
    """
    Print firewall status report.
    
    Args:
        results: Firewall check results dictionary.
    """
    firewall_active = results.get("firewall_active", False)
    status = "✓" if firewall_active else "✗"
    
    utils.print_result("Firewall Status", "ACTIVE" if firewall_active else "INACTIVE", status)
    
    if results.get("ufw", {}).get("installed"):
        status = "✓" if results["ufw"]["active"] else "⚠"
        utils.print_result("UFW", "Active" if results["ufw"]["active"] else "Inactive", status)
    
    if results.get("firewalld", {}).get("installed"):
        status = "✓" if results["firewalld"]["active"] else "⚠"
        utils.print_result("Firewalld", "Active" if results["firewalld"]["active"] else "Inactive", status)
    
    if results.get("iptables", {}).get("installed"):
        rules = results["iptables"]["rules"]
        utils.print_result("iptables Rules", str(rules), "•")


def print_ports_report(results: Dict[str, Any]) -> None:
    """
    Print listening ports report.
    
    Args:
        results: Listening ports check results dictionary.
    """
    open_ports = results.get("open_ports_count", 0)
    status = "⚠" if open_ports > 5 else "✓"
    
    utils.print_result("Listening Ports", str(open_ports), status)
    
    ports = results.get("listening_ports", [])
    if ports:
        print("\n  Open Ports:")
        for port_info in ports[:10]:
            port = port_info["port"]
            service = port_info.get("service", "unknown")
            print(f"    Port {port}: {service}")
    
    # Check for risky services
    exposed = check_exposed_services()
    if exposed:
        print("\n  ⚠ Potentially Exposed Services:")
        for service in exposed:
            print(f"    - {service}")
