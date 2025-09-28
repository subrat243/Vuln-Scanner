#!/usr/bin/env python3
"""
Network Vulnerability Scanner (clean, syntax-error free)

Example:
  sudo python3 vuln_scanner.py -t 192.168.1.0/24 -p 1-1024 --json --html -o myscan

Only run scans against systems you are authorized to test.
"""
from __future__ import annotations

import sys
import os
import re
import subprocess
import time
import json
import logging
from pathlib import Path
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Any, Optional
import shutil

try:
    import nmap  # python-nmap
except Exception:
    nmap = None  # handled later

from jinja2 import Environment, FileSystemLoader

# Configuration
CONFIG = {
    "CVE_SEARCH_DIR": Path(__file__).parent / "cve-search",
    "CVE_SEARCH_REPO": "https://github.com/cve-search/cve-search.git",
    "DB_UPDATE_INTERVAL": 7 * 24 * 3600,  # 7 days
    "LOG_FILE": "vuln_scanner.log",
    "REPORT_DIR": Path("reports"),
    "TEMPLATES_DIR": Path("templates"),
}

# Ensure directories exist
CONFIG["REPORT_DIR"].mkdir(exist_ok=True)
CONFIG["TEMPLATES_DIR"].mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(CONFIG["LOG_FILE"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def check_requirements() -> None:
    """Ensure required external binaries are available; guide user if missing."""
    missing = []
    for tool in ("git", "nmap", "python3"):
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        logger.error("Missing required tools: %s. Install them and re-run.", ", ".join(missing))
        sys.exit(1)
    if nmap is None:
        logger.error("python-nmap package missing. Install with: pip install python-nmap")
        sys.exit(1)


class CVEScanner:
    """Handles CVE database setup and queries (optional)."""

    def __init__(self):
        self.cve_dir = CONFIG["CVE_SEARCH_DIR"]
        self.last_update_file = self.cve_dir / "last_update.txt"

    @staticmethod
    def _run(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
        logger.debug("Running: %s (cwd=%s)", " ".join(cmd), cwd)
        return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check, capture_output=True, text=True)

    def clone_cve_search(self) -> None:
        try:
            if not self.cve_dir.exists():
                logger.info("Cloning cve-search repo into %s...", self.cve_dir)
                self._run(["git", "clone", "--depth", "1", CONFIG["CVE_SEARCH_REPO"], str(self.cve_dir)])
        except subprocess.CalledProcessError as e:
            logger.error("Failed to clone cve-search: %s\n%s", e, e.stderr)
            raise

    def setup_cve_search(self) -> None:
        """Attempt to install python requirements and populate DB. This may be heavy."""
        try:
            logger.info("Installing cve-search Python requirements (inside your active venv)...")
            self._run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=self.cve_dir)
            logger.info("Populating cve-search DB (this may take a while)...")
            self._run([sys.executable, "sbin/db_mgmt.py", "-p"], cwd=self.cve_dir)
            self._run([sys.executable, "sbin/db_mgmt_cpe_dictionary.py"], cwd=self.cve_dir)
            self._run([sys.executable, "sbin/db_updater.py", "-c"], cwd=self.cve_dir)
            self.last_update_file.touch()
            logger.info("cve-search setup complete.")
        except subprocess.CalledProcessError as e:
            logger.error("cve-search setup failed: %s\n%s", e, e.stderr)

    def check_and_update_db(self) -> bool:
        if not self.last_update_file.exists():
            return True
        return (time.time() - self.last_update_file.stat().st_mtime) > CONFIG["DB_UPDATE_INTERVAL"]

    def update_database(self) -> None:
        try:
            logger.info("Updating CVE DB...")
            self._run([sys.executable, "sbin/db_updater.py", "-v"], cwd=self.cve_dir)
            self.last_update_file.touch()
        except subprocess.CalledProcessError as e:
            logger.error("Database update failed: %s\n%s", e, e.stderr)

    def get_local_cves(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Query local cve-search. Returns list of dicts or empty list."""
        try:
            proc = self._run([sys.executable, "bin/search.py", "-p", product, "-v", version, "-o", "json"], cwd=self.cve_dir, check=False)
            if proc.returncode == 0 and proc.stdout:
                return json.loads(proc.stdout)
        except Exception as e:
            logger.warning("Local CVE lookup failed: %s", e)
        return []


class NetworkScanner:
    """Handles network scanning and parsing results."""

    CVE_PATTERN = re.compile(r'\b(CVE-\d{4}-\d{4,7})\b', flags=re.IGNORECASE)

    def __init__(self):
        try:
            import nmap
            self.nm = nmap.PortScanner()
        except Exception as e:
            logger.error("Failed to initialize nmap.PortScanner(): %s", e)
            raise

    def _extract_cves_from_script(self, script_output: str) -> List[str]:
        found = set()
        for m in self.CVE_PATTERN.finditer(script_output):
            found.add(m.group(1).upper())
        return sorted(found)

    def scan_target(self, target: str, ports: str) -> Dict[str, Any]:
        """Scan a single target and return structured results."""
        try:
            logger.info("Scanning target=%s ports=%s", target, ports)
            self.nm.scan(hosts=target, ports=ports, arguments='-sV --script vulners')
        except Exception as e:
            logger.error("nmap scan failed for %s: %s", target, e)
            return {"timestamp": datetime.now().isoformat(), "target": target, "hosts": []}

        results: Dict[str, Any] = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "target": target, "hosts": []}

        for host in self.nm.all_hosts():
            host_info: Dict[str, Any] = {
                "host": host,
                "hostname": self.nm[host].hostname() or "",
                "ports": []
            }

            for proto in self.nm[host].all_protocols():
                ports_data = self.nm[host][proto]
                for port in sorted(ports_data.keys()):
                    port_entry = ports_data[port]
                    service = port_entry.get('name', '')
                    version = port_entry.get('version', '') or port_entry.get('product', '')

                    port_info: Dict[str, Any] = {
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "version": version,
                        "cves": []
                    }

                    scripts = port_entry.get('script', {}) or {}
                    for script_name, script_output in scripts.items():
                        cves = self._extract_cves_from_script(str(script_output))
                        for cve in cves:
                            port_info["cves"].append({"id": cve, "source": f"nmap:{script_name}"})

                    host_info["ports"].append(port_info)

            results["hosts"].append(host_info)

        return results


# Validation helpers
IP_CIDR = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$')
DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$')
PORT_RE = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')


def validate_input(targets: str, ports: str) -> List[str]:
    """Return list of validated targets (split on comma). Raises ValueError on bad input."""
    targets_list = [t.strip() for t in targets.split(',') if t.strip()]
    if not targets_list:
        raise ValueError("No targets provided.")

    for t in targets_list:
        if not (IP_CIDR.match(t) or DOMAIN_RE.match(t)):
            raise ValueError(f"Invalid target: {t}")
    if not PORT_RE.match(ports):
        raise ValueError(f"Invalid ports specification: {ports}")
    return targets_list


def generate_json_report(results: Dict[str, Any], filename: Optional[str] = None) -> Path:
    report_dir = CONFIG["REPORT_DIR"]
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.json"
    else:
        if not filename.endswith('.json'):
            filename = filename + '.json'
    report_path = report_dir / filename
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    logger.info("JSON report written to %s", report_path)
    return report_path


def generate_html_report(results: Dict[str, Any], filename: Optional[str] = None) -> Path:
    env = Environment(loader=FileSystemLoader(str(CONFIG["TEMPLATES_DIR"])))
    template_name = "report_template.html"
    if template_name not in [p.name for p in CONFIG["TEMPLATES_DIR"].glob("*.html")]:
        create_html_template()
    template = env.get_template(template_name)

    total_hosts = len(results.get("hosts", []))
    total_ports = sum(len(h.get("ports", [])) for h in results.get("hosts", []))
    total_cves = sum(len(p.get("cves", [])) for h in results.get("hosts", []) for p in h.get("ports", []))

    html_content = template.render(
        title="Vulnerability Scan Report",
        timestamp=results.get("timestamp"),
        target=results.get("target"),
        hosts=results.get("hosts", []),
        total_hosts=total_hosts,
        total_ports=total_ports,
        total_cves=total_cves
    )

    if not filename:
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    else:
        if not filename.endswith('.html'):
            filename = filename + '.html'
    path = CONFIG["REPORT_DIR"] / filename
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    logger.info("HTML report written to %s", path)
    return path


def create_html_template() -> None:
    template_path = CONFIG["TEMPLATES_DIR"] / "report_template.html"
    if template_path.exists():
        return
    template_content = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ title }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"/>
<style>
.cve-low { color: #28a745; }
.cve-medium { color: #ffc107; }
.cve-high { color: #fd7e14; }
.cve-critical { color: #dc3545; }
.collapsible { cursor: pointer; }
</style>
</head>
<body>
<div class="container mt-4">
  <h1>{{ title }}</h1>
  <div class="card my-3"><div class="card-body">
    <p><strong>Target:</strong> {{ target }}</p>
    <p><strong>Timestamp:</strong> {{ timestamp }}</p>
    <p><strong>Hosts:</strong> {{ total_hosts }} • <strong>Open Ports:</strong> {{ total_ports }} • <strong>CVEs:</strong> {{ total_cves }}</p>
  </div></div>
  <input id="searchInput" placeholder="Search..." class="form-control mb-3"/>
  {% for host in hosts %}
  <div class="card mb-2 host-entry">
    <div class="card-header bg-secondary text-white" data-bs-toggle="collapse" data-bs-target="#host-{{ loop.index }}">
      Host: {{ host.host }} ({{ host.hostname }})
    </div>
    <div id="host-{{ loop.index }}" class="collapse show">
      <div class="card-body">
        {% for port in host.ports %}
        <div class="card mb-2">
          <div class="card-header bg-light" data-bs-toggle="collapse" data-bs-target="#port-{{ loop.index }}">
            Port: {{ port.port }}/{{ port.protocol }} — {{ port.service }} {{ port.version }} • CVEs: <span class="badge bg-danger">{{ port.cves|length }}</span>
          </div>
          <div id="port-{{ loop.index }}" class="collapse">
            <div class="card-body">
              {% if port.cves %}
              <table class="table table-sm"><thead><tr><th>CVE</th><th>Source</th></tr></thead><tbody>
                {% for cve in port.cves %}
                <tr><td><a href="https://nvd.nist.gov/vuln/detail/{{ cve.id }}" target="_blank">{{ cve.id }}</a></td><td>{{ cve.source }}</td></tr>
                {% endfor %}
              </tbody></table>
              {% else %}
              <p class="text-muted">No CVEs detected.</p>
              {% endif %}
            </div>
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>
  {% endfor %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.getElementById('searchInput').addEventListener('input', function(){
  const s = this.value.toLowerCase();
  document.querySelectorAll('.host-entry').forEach(host => {
    host.style.display = host.textContent.toLowerCase().includes(s) ? 'block' : 'none';
  });
});
</script>
</body>
</html>
"""
    with open(template_path, "w", encoding="utf-8") as fh:
        fh.write(template_content)
    logger.info("Created default template: %s", template_path)


def merge_scan_results(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge multiple scan results into a single aggregated result."""
    merged: Dict[str, Any] = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": ",".join([r.get("target", "") for r in scan_results]),
        "hosts": []
    }
    hosts_map: Dict[str, Dict[str, Any]] = {}
    for res in scan_results:
        for host in res.get("hosts", []):
            key = host.get("host")
            if key not in hosts_map:
                hosts_map[key] = host
            else:
                existing_ports = {(p["port"], p["protocol"]) for p in hosts_map[key].get("ports", [])}
                for p in host.get("ports", []):
                    if (p["port"], p["protocol"]) not in existing_ports:
                        hosts_map[key]["ports"].append(p)
    merged["hosts"] = list(hosts_map.values())
    return merged


def main() -> None:
    parser = ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target(s) IP/CIDR/domain (comma-separated)")
    parser.add_argument("-p", "--ports", default="1-65535", help="Ports to scan (e.g. 80 or 1-1024 or 22,80,443)")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("-o", "--output", help="Output filename prefix (optional)")
    parser.add_argument("--parallel", type=int, default=1, help="Parallel scans (for multiple targets)")
    parser.add_argument("--skip-cve-setup", action="store_true", help="Skip cloning/setting up local CVE DB")
    args = parser.parse_args()

    # check environment
    check_requirements()

    # validate inputs
    try:
        targets = validate_input(args.target, args.ports)
    except ValueError as e:
        logger.error("Input validation error: %s", e)
        sys.exit(1)

    if os.geteuid() != 0:
        logger.warning("Not running as root. Some nmap scans (e.g., SYN scans) may be restricted. Consider running with sudo.")

    # CVE db optional (we don't auto-setup heavy DB by default)
    cve_scanner = CVEScanner()
    if not args.skip_cve_setup:
        try:
            if not (cve_scanner.cve_dir.exists() and (cve_scanner.cve_dir / "data").exists()):
                logger.info("cve-search appears missing or unpopulated. To speed up runs, consider running cve-search setup manually.")
        except Exception:
            logger.debug("CVE scanner check skipped.")

    # create template if missing
    create_html_template()

    # scanning
    scanner = NetworkScanner()
    scan_results: List[Dict[str, Any]] = []

    if args.parallel > 1 and len(targets) > 1:
        max_workers = min(args.parallel, len(targets))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(scanner.scan_target, tgt, args.ports): tgt for tgt in targets}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    scan_results.append(res)
    else:
        for tgt in targets:
            res = scanner.scan_target(tgt, args.ports)
            scan_results.append(res)

    merged = merge_scan_results(scan_results)

    basename = args.output if args.output else f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if args.json:
        generate_json_report(merged, f"{basename}.json")
    if args.html:
        generate_html_report(merged, f"{basename}.html")
    if not args.json and not args.html:
        print(json.dumps({"summary": {"hosts": len(merged["hosts"]) }}, indent=2))
        logger.info("No report format selected. Use --json or --html to save full reports.")


if __name__ == "__main__":
    main()
