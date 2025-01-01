**Tool Name:** `AutoVulnScanner`

**README for GitHub:**

# AutoVulnScanner

`AutoVulnScanner` is a Python-based tool designed to automate network vulnerability scanning. The tool uses Nmap to scan a given target (IP or domain) and checks for open ports, services, and known vulnerabilities through its `vuln` script. It simplifies the process of identifying security risks on a network and can be easily customized for various scanning needs.

## Features
- **Port Scanning:** Scans all or specific ports on a target.
- **Service Detection:** Identifies services running on open ports.
- **Vulnerability Scanning:** Uses Nmap's `vuln` script to detect common vulnerabilities in services.
- **Customizable Port Range:** Allows users to specify port ranges (e.g., `1-1000`).
- **Easy-to-use Command Line Interface (CLI):** Input target IP/domain and port range directly in the terminal.

## Requirements
- Python 3.x
- `nmap` Python library (install via `pip install python-nmap`)
- Nmap installed on your system (download from [nmap.org](https://nmap.org/))

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/subrat243/AutoVulnScanner.git
    cd AutoVulnScanner
    ```

2. Install required dependencies:
    ```bash
    pip install python-nmap
    pip install shodan
    ```

3. Install Nmap on your system:
    - For Linux (Ubuntu/Debian):
      ```bash
      sudo apt install nmap
      ```

    - For Windows/macOS, follow the installation instructions at [Nmap Downloads](https://nmap.org/download.html).

## Usage
1. Run the script:
    ```bash
    python autovulnscanner.py
    ```

2. Enter the target IP address or domain when prompted.

3. Enter the port range (e.g., `1-1000` or `1-65535` for all ports).

4. The tool will display information on the target's open ports, services, and detected vulnerabilities.

## Example Output
```bash
Enter the target IP or domain: 192.168.1.1
Enter port range (e.g., 1-1000): 1-1000
Scanning 192.168.1.1 on ports 1-1000...
Host: 192.168.1.1 (router.local)
State: up
Protocol: tcp
Port: 22   State: open
Details: No vulnerabilities found
Port: 80   State: open
Details: Vulnerability found (CVE-2021-1234)
```