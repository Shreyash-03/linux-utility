#!/usr/bin/env python3
"""
Main entry point for the linux-sec-audit CLI tool.

Handles command-line argument parsing and orchestrates security scans.
"""

import argparse
import json
import sys
from typing import Dict, Any
from datetime import datetime

from . import ssh_audit
from . import log_analyzer
from . import permission_audit
from . import firewall_check
from . import service_check
from . import scoring
from . import report_generator
from . import utils


def check_privileges() -> bool:
    """
    Check if the script is running with root privileges.
    
    Returns:
        bool: True if running as root, False otherwise.
    """
    return utils.is_root()


def run_quick_scan() -> Dict[str, Any]:
    """
    Perform a quick security scan (basic checks only).
    
    Returns:
        Dict containing scan results.
    """
    utils.print_status("Running QUICK security scan...", utils.Colors.YELLOW)
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "quick",
        "checks": {}
    }
    
    # SSH Quick Check
    utils.print_header("SSH Configuration Check")
    ssh_results = ssh_audit.check_ssh_security()
    results["checks"]["ssh"] = ssh_results
    ssh_audit.print_ssh_report(ssh_results)
    
    # Firewall Quick Check
    utils.print_header("Firewall Status Check")
    firewall_results = firewall_check.check_firewall_status()
    results["checks"]["firewall"] = firewall_results
    firewall_check.print_firewall_report(firewall_results)
    
    # Service Quick Check
    utils.print_header("Running Services Check")
    service_results = service_check.check_risky_services()
    results["checks"]["services"] = service_results
    service_check.print_service_report(service_results)
    
    return results


def run_full_scan() -> Dict[str, Any]:
    """
    Perform a comprehensive security scan (all checks).
    
    Returns:
        Dict containing scan results.
    """
    utils.print_status("Running FULL security scan...", utils.Colors.YELLOW)
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "full",
        "checks": {}
    }
    
    # SSH Audit
    utils.print_header("SSH Security Audit")
    ssh_results = ssh_audit.check_ssh_security()
    results["checks"]["ssh"] = ssh_results
    ssh_audit.print_ssh_report(ssh_results)
    
    # Login Attempt Analysis
    utils.print_header("Login Attempt Analysis")
    try:
        login_results = log_analyzer.analyze_login_attempts()
        results["checks"]["login_attempts"] = login_results
        log_analyzer.print_login_report(login_results)
    except Exception as e:
        utils.print_status(f"Login analysis skipped: {str(e)}", utils.Colors.YELLOW)
        results["checks"]["login_attempts"] = {"error": str(e)}
    
    # Permission Audit
    utils.print_header("User & Permission Audit")
    perm_results = permission_audit.audit_permissions()
    results["checks"]["permissions"] = perm_results
    permission_audit.print_permission_report(perm_results)
    
    # Firewall Check
    utils.print_header("Firewall & Network Audit")
    firewall_results = firewall_check.check_firewall_status()
    results["checks"]["firewall"] = firewall_results
    firewall_check.print_firewall_report(firewall_results)
    
    # Listening Ports
    utils.print_header("Listening Ports Check")
    ports_results = firewall_check.check_listening_ports()
    results["checks"]["ports"] = ports_results
    firewall_check.print_ports_report(ports_results)
    
    # Service Check
    utils.print_header("Service Inspection")
    service_results = service_check.check_risky_services()
    results["checks"]["services"] = service_results
    service_check.print_service_report(service_results)
    
    # System Hardening
    utils.print_header("System Hardening Check")
    hardening_results = service_check.check_system_hardening()
    results["checks"]["hardening"] = hardening_results
    service_check.print_hardening_report(hardening_results)
    
    return results


def run_ssh_scan() -> Dict[str, Any]:
    """Run SSH security audit only."""
    utils.print_status("Running SSH security audit...", utils.Colors.YELLOW)
    results = {"timestamp": datetime.now().isoformat(), "scan_type": "ssh"}
    
    utils.print_header("SSH Security Audit")
    ssh_results = ssh_audit.check_ssh_security()
    results["checks"] = {"ssh": ssh_results}
    ssh_audit.print_ssh_report(ssh_results)
    
    return results


def run_permissions_scan() -> Dict[str, Any]:
    """Run permissions audit only."""
    utils.print_status("Running permissions audit...", utils.Colors.YELLOW)
    results = {"timestamp": datetime.now().isoformat(), "scan_type": "permissions"}
    
    utils.print_header("User & Permission Audit")
    perm_results = permission_audit.audit_permissions()
    results["checks"] = {"permissions": perm_results}
    permission_audit.print_permission_report(perm_results)
    
    return results


def run_network_scan() -> Dict[str, Any]:
    """Run network audit only."""
    utils.print_status("Running network audit...", utils.Colors.YELLOW)
    results = {"timestamp": datetime.now().isoformat(), "scan_type": "network"}
    
    utils.print_header("Firewall & Network Audit")
    firewall_results = firewall_check.check_firewall_status()
    results["checks"] = {"firewall": firewall_results}
    firewall_check.print_firewall_report(firewall_results)
    
    utils.print_header("Listening Ports Check")
    ports_results = firewall_check.check_listening_ports()
    results["checks"]["ports"] = ports_results
    firewall_check.print_ports_report(ports_results)
    
    return results


def run_logs_scan() -> Dict[str, Any]:
    """Run login attempt analysis only."""
    utils.print_status("Running log analysis...", utils.Colors.YELLOW)
    results = {"timestamp": datetime.now().isoformat(), "scan_type": "logs"}
    
    utils.print_header("Login Attempt Analysis")
    try:
        login_results = log_analyzer.analyze_login_attempts()
        results["checks"] = {"login_attempts": login_results}
        log_analyzer.print_login_report(login_results)
    except Exception as e:
        utils.print_status(f"Error: {str(e)}", utils.Colors.RED)
        results["checks"] = {"error": str(e)}
    
    return results


def generate_report(results: Dict[str, Any], json_output: bool = False, 
                   output_file: str = None) -> None:
    """
    Generate and display the security audit report.
    
    Args:
        results: Dictionary containing all scan results.
        json_output: If True, output as JSON.
        output_file: Optional file path to save the report.
    """
    if json_output:
        report_data = json.dumps(results, indent=2)
        print(report_data)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_data)
    else:
        # Generate text report
        report = report_generator.generate_text_report(results)
        print(report)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
    
    if output_file:
        utils.print_status(f"Report saved to: {output_file}", utils.Colors.GREEN)


def main() -> None:
    """Main entry point for the CLI tool."""
    parser = argparse.ArgumentParser(
        description="linux-sec-audit: Comprehensive Linux Security Auditing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 -m secscan.main --full
  sudo python3 -m secscan.main --quick
  sudo python3 -m secscan.main --ssh
  sudo python3 -m secscan.main --full --json
  sudo python3 -m secscan.main --full --output report.txt
        """
    )
    
    # Scan type arguments
    parser.add_argument('--quick', action='store_true', 
                       help='Run quick security scan (basic checks)')
    parser.add_argument('--full', action='store_true', 
                       help='Run comprehensive security scan')
    parser.add_argument('--ssh', action='store_true', 
                       help='SSH security audit only')
    parser.add_argument('--permissions', action='store_true', 
                       help='User and permission audit only')
    parser.add_argument('--network', action='store_true', 
                       help='Network and firewall audit only')
    parser.add_argument('--logs', action='store_true', 
                       help='Login attempt analysis only')
    
    # Output options
    parser.add_argument('--json', action='store_true', 
                       help='Output results in JSON format')
    parser.add_argument('--output', '-o', type=str, 
                       help='Save report to file')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    
    args = parser.parse_args()
    
    # Display banner
    utils.print_banner()
    
    # Check privileges
    if not check_privileges():
        utils.print_status("ERROR: This tool requires root privileges!", utils.Colors.RED)
        sys.exit(1)
    
    # Determine scan type
    results = None
    
    if args.quick:
        results = run_quick_scan()
    elif args.ssh:
        results = run_ssh_scan()
    elif args.permissions:
        results = run_permissions_scan()
    elif args.network:
        results = run_network_scan()
    elif args.logs:
        results = run_logs_scan()
    elif args.full:
        results = run_full_scan()
    else:
        # Default to quick scan
        results = run_quick_scan()
    
    # Calculate security score
    if results:
        score = scoring.calculate_security_score(results)
        results["security_score"] = score
        
        # Print report
        print("\n")
        generate_report(results, args.json, args.output)
        
        # Print score summary
        print("\n")
        utils.print_header("Security Score Summary")
        scoring.print_score_summary(score)


if __name__ == "__main__":
    main()
