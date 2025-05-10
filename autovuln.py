import sys
import os
import re
import subprocess
import time
import json
from pathlib import Path

try:
    import nmap
except ImportError:
    print("Error: Install python-nmap: pip install python-nmap")
    sys.exit(1)

# Configuration
CVE_SEARCH_DIR = Path(__file__).parent / "cve-search"
CVE_SEARCH_REPO = "https://github.com/cve-search/cve-search.git"
DB_UPDATE_INTERVAL = 7 * 24 * 3600  # 7 days in seconds

def install_dependencies():
    """Install system dependencies for cve-search"""
    try:
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'python3-dev', 'python3-pip', 'libxml2-dev', 'libxslt1-dev', 'zlib1g-dev', 'build-essential', 'git'],
                       check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        sys.exit(1)

def clone_cve_search():
    """Clone cve-search repository if not exists"""
    try:
        if not CVE_SEARCH_DIR.exists():
            print("Cloning cve-search repository...")
            subprocess.run(['git', 'clone', '--depth', '1', CVE_SEARCH_REPO, str(CVE_SEARCH_DIR)],
                           check=True)
        os.chdir(CVE_SEARCH_DIR)
    except Exception as e:
        print(f"Failed to clone cve-search: {e}")
        sys.exit(1)

def setup_cve_search():
    """Full cve-search setup with database population"""
    try:
        print("Installing Python dependencies...")
        subprocess.run(['pip3', 'install', '-r', 'requirements.txt'],
                       check=True)

        print("Populating database...")
        subprocess.run(['python3', 'sbin/db_mgmt.py', '-p'],
                       check=True)
        subprocess.run(['python3', 'sbin/db_mgmt_cpe_dictionary.py'],
                       check=True)
        subprocess.run(['python3', 'sbin/db_updater.py', '-c'],
                       check=True)
    except Exception as e:
        print(f"Setup failed: {e}")
        sys.exit(1)

def check_and_update_db():
    """Check if database needs updating"""
    last_update_file = CVE_SEARCH_DIR / "last_update.txt"
    
    if not last_update_file.exists():
        return False
    
    last_update = last_update_file.stat().st_mtime
    return (time.time() - last_update) > DB_UPDATE_INTERVAL

def update_database():
    """Update CVE database"""
    try:
        os.chdir(CVE_SEARCH_DIR)
        print("Updating CVE database...")
        subprocess.run(['python3', 'sbin/db_updater.py', '-v'],
                       check=True)
        Path("last_update.txt").touch()
    except Exception as e:
        print(f"Database update failed: {e}")

def get_local_cves(product, version):
    """Query local CVE database"""
    try:
        os.chdir(CVE_SEARCH_DIR)
        result = subprocess.run(['python3', 'bin/search.py', '-p', product, '-v', version, '-o', 'json'],
                                capture_output=True, text=True)
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Local CVE lookup failed: {e}")
        return []

def scan_network(target, ports):
    nm = nmap.PortScanner()
    print(f"\nScanning {target} on ports {ports}...")
    
    try:
        nm.scan(target, ports, arguments='-sV --script vulners')
        
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname() or 'N/A'})")
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                for port in nm[host][proto].keys():
                    port_info = nm[host][proto][port]
                    print(f"\nPort: {port}/tcp".ljust(20) + f"State: {port_info['state']}")
                    
                    # Vulners script results
                    if 'script' in port_info:
                        vuln_output = port_info['script'].get('vulners', '')
                        cves = re.findall(r'(CVE-\d{4}-\d{4,})', vuln_output)
                        if cves:
                            print("\n[!] Scan Detected CVEs:")
                            for cve in set(cves):
                                print(f"  {cve}: https://nvd.nist.gov/vuln/detail/{cve}")
                    
                    # Local database check
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    if product and version:
                        print(f"\n[~] Checking local DB for {product} {version}...")
                        cves = get_local_cves(product, version)
                        if cves:
                            print("[!] Local Database Matches:")
                            for cve in cves:
                                print(f"  {cve['id']} (CVSS: {cve.get('cvss', 'N/A')})")
                                print(f"  Summary: {cve['summary'][:100]}...")
                        else:
                            print("[+] No local database matches")
                    
                    print("-" * 60)
                    
    except Exception as e:
        print(f"Scan error: {e}")

if __name__ == "__main__":
    # Verify root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    # Initial setup check
    if not CVE_SEARCH_DIR.exists() or not (CVE_SEARCH_DIR / "data").exists():
        print("First-time setup required...")
        install_dependencies()
        clone_cve_search()
        setup_cve_search()
    
    # Database maintenance
    if check_and_update_db():
        print("Database update needed")
        update_database()
    
    # Get scan parameters
    target = input("\nEnter target (IP/CIDR/domain): ").strip()
    ports = input("Enter ports (default 1-65535): ").strip() or '1-65535'
    
    scan_network(target, ports)
