# CVE-Scanner: Comprehensive Vulnerability Detection Tool

![Network Security](https://images.unsplash.com/photo-1555949963-aa79dcee981c)

An open-source network vulnerability scanner combining Nmap integration with local CVE database lookups for comprehensive security auditing.

## Features

- **Local CVE Database** - Self-contained vulnerability database using cve-search
- **Nmap Integration** - Combines network scanning with vulnerability detection
- **Automated Setup** - One-command installation and configuration
- **Scheduled Updates** - Automatic CVE database maintenance
- **Root Privilege Handling** - Automatic escalation prompts
- **Detailed Reporting** - CVSS scores, CVE links, and service versions
- **Ethical Warnings** - Built-in authorization checks and disclaimers

## Installation

```bash
# Clone repository
git clone https://github.com/subrat243/AutoVuln-Scanner.git
cd AutoVuln-Scanner
```
```bash
# Run with root privileges
sudo python3 autovuln.py
```

**First Run Setup** (Automated):
- Installs required system packages
- Clones cve-search repository (500MB+)
- Builds local CVE database (30-60 minutes)
- Performs initial database population

## Usage

### Basic Network Scan
```bash
sudo python3 autovuln.py
```
Follow prompts to enter target and port range

### Database Update
```bash
sudo python3 autovuln.py
```
Database updates automatically when older than 7 days

### Advanced Options
| Parameter          | Description                          | Example              |
|--------------------|--------------------------------------|----------------------|
| Target Specification | IP, CIDR, or domain                | 192.168.1.0/24      |
| Port Range         | Specific ports or ranges            | 80,443,1000-2000    |
| Verbose Output     | Detailed scan progress              | Built-in logging     |

## Technical Details

### Requirements
- Python 3.6+
- 10GB+ disk space
- Root privileges
- Internet connection (initial setup)

### Components
| Component          | Role                                |
|--------------------|-------------------------------------|
| Nmap               | Network discovery and service detection |
| cve-search         | Local CVE database storage and query |
| Vulners NSE Script | Live vulnerability matching        |

## Ethical Considerations

⚠️ **Important Legal Notice**
```text
- Always obtain proper authorization before scanning
- Network scanning may trigger security alerts
- This tool should only be used on networks you own
- Respect all applicable laws and regulations
```

## Troubleshooting

### Common Issues
1. **Setup Failure**
   - Verify internet connection
   - Ensure sufficient disk space (>10GB free)
   - Check system logs in /var/log/

2. **Database Update Errors**
   ```bash
   rm -rf cve-search/data
   sudo python3 autovuln.py
   ```

3. **Scan Timeouts**
   - Use smaller port ranges
   - Limit target scope
   - Check network firewall rules

## Contribution

We welcome community contributions:
- Report bugs via Issues
- Submit feature requests
- Create pull requests
- Improve documentation

**License**: MIT

---

## References

1. [Nmap Official Documentation](https://nmap.org/docs.html)
2. [cve-search GitHub](https://github.com/cve-search/cve-search)
3. [MITRE CVE List](https://cve.mitre.org/)

```
