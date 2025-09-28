# Network Vulnerability Scanner

A Python-based tool to scan networks for vulnerabilities using `nmap`, with optional integration of a local CVE database via `cve-search`. This scanner is designed to help identify open ports, services, and potential vulnerabilities on target systems.

## Features

  * **Multi-Target Scanning**: Scan multiple targets simultaneously, including IPs, CIDR ranges, and domains.
  * **Customizable Scans**: Define specific port ranges for targeted scanning.
  * **Detailed Reporting**: Generate comprehensive reports in both JSON and user-friendly HTML formats.
  * **CVE Integration**: Enriches scan results with CVE information from a local `cve-search` database.
  * **Parallel Processing**: Accelerate scans on multiple targets using parallel workers.
  * **Automated CVE Database Management**: Handles the initial setup and periodic updates of the local CVE database.
  * **Comprehensive Logging**: Keeps detailed logs for debugging and tracking scan progress.

## Requirements

  * Python 3.x
  * **nmap**: Must be installed on the system.
  * **git**: Required for cloning the `cve-search` repository.
  * Python libraries: `python-nmap`, `Jinja2`

## Installation

1.  **Clone the repository or save the script**
    Save the `vuln_scanner.py` script to your local machine.

2.  **Install System Dependencies**
    Ensure `nmap` and `git` are installed. On Debian-based systems (like Ubuntu), you can use:

    ```bash
    sudo apt-get update && sudo apt-get install nmap git -y
    ```

3.  **Install Python Libraries**
    Install the required Python packages using pip:

    ```bash
    pip install python-nmap Jinja2
    ```

## Usage

Run the script from your terminal with the required arguments. **Root privileges (`sudo`) are recommended for more accurate nmap scanning.**

```bash
sudo python3 vuln_scanner.py -t <targets> -p <ports> [options]
```

### Arguments

| Argument            | Short | Description                                                               | Default                         |
| ------------------- | ----- | ------------------------------------------------------------------------- | ------------------------------- |
| `--target`          | `-t`  | **Required.** Comma-separated list of targets (e.g., `192.168.1.0/24,example.com`). | None                            |
| `--ports`           | `-p`  | Ports to scan (e.g., `80,443`, `1-1024`).                                   | `1-65535`                       |
| `--json`            |       | Generate a JSON report.                                                   | Disabled                        |
| `--html`            |       | Generate an HTML report.                                                  | Disabled                        |
| `--output`          | `-o`  | A prefix for the output report filenames.                                 | `scan_report_<timestamp>`       |
| `--parallel`        |       | Number of parallel scans for multiple targets.                            | `1`                             |
| `--skip-cve-setup`  |       | Skip cloning and setting up the local CVE database.                       | Disabled                        |

### Example

To scan the `192.168.1.0/24` network on the first 1024 ports, generate both JSON and HTML reports with the prefix `myscan`, you would run:

```bash
sudo python3 vuln_scanner.py -t 192.168.1.0/24 -p 1-1024 --json --html -o myscan
```

## CVE Database Setup (Optional)

The tool can integrate with a local instance of `cve-search` to provide detailed vulnerability information.

  * **First-Time Setup**: If you run the script without the `--skip-cve-setup` flag, it will automatically clone the `cve-search` repository and populate its database. **This process can be lengthy and consume significant disk space.**
  * **Updates**: The script checks for database updates every 7 days. You can force an update by deleting the `last_update.txt` file inside the `cve-search` directory.

## Output

The tool generates reports in the specified formats:

  * **JSON Report**: A detailed, machine-readable report saved as `<output_prefix>.json`.
  * **HTML Report**: An interactive and easy-to-read report saved as `<output_prefix>.html`, styled with Bootstrap for a clean interface.

## Logging

All scan activities, progress, and errors are logged to `vuln_scanner.log` and also printed to the console for real-time monitoring.

## Security Note

This tool is intended for educational purposes and for use by security professionals on authorized systems only. **Unauthorized scanning of networks is illegal.** Always obtain explicit permission before scanning any network or system that you do not own.

## Contributing

Feel free to open issues or submit pull requests on the repository. All contributions are welcome\!

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
