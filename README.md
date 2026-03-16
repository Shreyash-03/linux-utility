# Linux Sec Audit

A collection of scripts for performing various security audits on Linux systems.


# linux-sec-audit

A comprehensive, lightweight, and dependency-free Linux security auditing CLI tool designed to identify security misconfigurations, suspicious activity, and weak configurations across Linux systems.

## 🎯 Features

- **SSH Security Audit**: Check SSH configuration for insecure settings (root login, weak authentication)
- **Login Attempt Analysis**: Detect brute force attacks and suspicious login patterns
- **User & Permission Audit**: Identify privileged users, world-writable files, and SUID binaries
- **Firewall & Network Audit**: Verify firewall status and identify listening ports
- **Service Inspection**: Detect risky and unnecessary services
- **System Hardening Checks**: Verify security hardening measures (fail2ban, auditd, SELinux, etc.)
- **Security Scoring**: Generate a 0-100 security score with detailed breakdown
- **Color-coded Output**: Easy-to-read terminal output with visual indicators
- **Multiple Scan Modes**: Quick scan, full scan, or targeted audits
- **JSON Export**: Export results in JSON format for automation
- **Report Generation**: Save detailed reports to file

## 📋 Requirements

- **Python 3.6+**
- **Linux Distribution**: Ubuntu, Debian, CentOS, Fedora, Kali, Arch, or any systemd-based Linux
- **Root Privileges**: Required for comprehensive security checks
- **No External Dependencies**: Pure Python implementation (uses only stdlib)

## 🚀 Installation

### Method 1: Direct Installation from Repository

```bash
git clone https://github.com/Shreyash-03/linux-utility
cd linux-utility/linux-sec-audit
sudo python3 -m secscan.main --full
```

### Method 2: Using Install Script

```bash
git clone https://github.com/Shreyash-03/linux-utility
cd linux-utility/linux-sec-audit
sudo bash install.sh
secscan --full
```

### Method 3: Manual Setup

```bash
git clone https://github.com/Shreyash-03/linux-utility
cd linux-utility/linux-sec-audit
sudo python3 setup.py install
sudo secscan --full
```

## 📖 Usage

### Basic Commands

```bash
# Quick security scan (basic checks only)
sudo python3 -m secscan.main --quick

# Full comprehensive security scan
sudo python3 -m secscan.main --full

# SSH security audit only
sudo python3 -m secscan.main --ssh

# User and permission audit only
sudo python3 -m secscan.main --permissions

# Network and firewall audit only
sudo python3 -m secscan.main --network

# Login attempt analysis only
sudo python3 -m secscan.main --logs

# Export results to JSON
sudo python3 -m secscan.main --full --json

# Save report to file
sudo python3 -m secscan.main --full --output security_report.txt

# Combined: JSON output to file
sudo python3 -m secscan.main --full --json --output report.json
```

## 📊 Example Output

```
=====================================
 Linux Security Audit Report (v1.0)
=====================================

[SSH Configuration]
Root Login: no ✓
Password Authentication: no ✓
Public Key Authentication: yes ✓
Empty Passwords: no ✓
SSH Port: 22 ⚠
Protocol Version: 2 ✓

[Login Attempt Analysis]
Failed Login Attempts: 32
Unique Failed IPs: 5
Possible brute force attack detected!

Top Attacking IP Addresses:
  192.168.1.100: 15 attempts
  192.168.1.101: 10 attempts
  192.168.1.102: 7 attempts

[User & Permission Audit]
UID 0 Users (excluding root): 0
Users Without Password: 0
Users with Sudo Access: 2
World Writable Files: 3
SUID Binaries: 28

[Firewall & Network Audit]
Firewall Status: ACTIVE ✓
UFW: Active
Open Ports: 3

Open Ports:
  Port 22: ssh
  Port 80: http
  Port 443: https

[Service Inspection]
Total Running Services: 45
Risky Services Detected: 0

[System Hardening]
Fail2Ban: Installed ✓
auditd: Installed ✓
SELinux: Enabled ✓
Automatic Updates: Enabled ✓
Cron Jobs: 12 jobs

============================================================
[SECURITY SCORE]
============================================================
Overall Score: 78/100
Grade: B - Good

Breakdown:
  Ssh: 20.0 points
  Login Attempts: 15.0 points
  Permissions: 18.0 points
  Firewall: 10.0 points
  Services: 15.0 points
  Hardening: 14.0 points

============================================================
[RECOMMENDATIONS]
============================================================
  • Change SSH port from default 22 to non-standard port
  • Implement rate limiting for SSH access
  • Consider enabling stricter firewall rules for inbound traffic
  • Review and minimize installed services
  • Enable additional monitoring services for better detection

============================================================
End of Report
============================================================
```

## 🔧 Project Structure

```
linux-sec-audit/
├── secscan/
│   ├── __init__.py              # Package initialization
│   ├── main.py                  # CLI entry point
│   ├── ssh_audit.py             # SSH security checks
│   ├── log_analyzer.py          # Login attempt analysis
│   ├── permission_audit.py      # User & permission checks
│   ├── firewall_check.py        # Firewall & network audit
│   ├── service_check.py         # Service inspection
│   ├── scoring.py               # Security scoring system
│   ├── report_generator.py      # Report generation
│   └── utils.py                 # Utility functions
├── tests/
│   ├── __init__.py
│   └── test_utils.py            # Unit tests
├── README.md                     # This file
├── LICENSE                       # MIT License
├── requirements.txt              # Python dependencies (empty)
├── setup.py                      # Python package setup
└── install.sh                    # Installation script
```

## 🔐 Security Checks Performed

### SSH Configuration
- ✓ Root login enabled/disabled
- ✓ Password authentication enabled/disabled
- ✓ Public key authentication enabled
- ✓ Empty passwords permitted
- ✓ SSH port configuration
- ✓ Protocol version

### Login Analysis
- ✓ Failed login attempt count
- ✓ Unique IP addresses with failed attempts
- ✓ Brute force detection
- ✓ Top attacking IP addresses

### User & Permissions
- ✓ Users with UID 0 (root)
- ✓ Users without passwords
- ✓ Sudo users enumeration
- ✓ World-writable files detection
- ✓ SUID binaries identification
- ✓ /etc/passwd and /etc/shadow permissions

### Firewall & Network
- ✓ UFW status and configuration
- ✓ Firewalld status and configuration
- ✓ iptables rules count
- ✓ Listening ports and services
- ✓ Exposed/risky services detection

### Services
- ✓ Running services enumeration
- ✓ Risky service detection (telnet, ftp, etc.)
- ✓ Service status verification

### System Hardening
- ✓ Fail2ban installation and status
- ✓ auditd (system audit daemon) status
- ✓ SELinux/AppArmor status
- ✓ Automatic updates configuration
- ✓ Cron jobs enumeration

## 📈 Security Scoring

The tool generates a security score out of 100 based on:

| Category | Max Points | Criteria |
|----------|-----------|----------|
| SSH Configuration | 20 | Secure SSH settings |
| Login Attempts | 15 | Absence of brute force attacks |
| Permissions | 20 | Proper user permissions and file restrictions |
| Firewall | 15 | Active firewall and port management |
| Services | 15 | Absence of risky services |
| Hardening | 15 | Security hardening measures in place |

**Grade Scale:**
- **A (90-100)**: Excellent security
- **B (80-89)**: Good security
- **C (70-79)**: Fair security
- **D (60-69)**: Poor security
- **F (<60)**: Critical security issues

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Setup

```bash
git clone https://github.com/Shreyash-03/linux-utility
cd linux-utility/linux-sec-audit
python3 -m venv venv
source venv/bin/activate
python3 -m pytest tests/
```

### Code Standards

- Follow PEP 8 style guide
- Include docstrings for all functions
- Add type hints where possible
- Write unit tests for new features

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Bug Reports

If you encounter any issues, please open an issue on GitHub with:
- Linux distribution and version
- Python version
- Command executed
- Error message/output

## ⚠️ Disclaimer

This tool is for authorized security auditing purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security audits.

## 👤 Author

**Shreyash-03**

- GitHub: [@Shreyash-03](https://github.com/Shreyash-03)

## 🙏 Acknowledgments

- Inspired by industry-standard security auditing tools
- Built for the Linux security community
- Designed with simplicity and effectiveness in mind

## 📞 Support

For questions and support:
- Open an issue on GitHub
- Check existing documentation
- Review security best practices

---

**Made with ❤️ for Linux Security Community**
