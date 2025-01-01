import nmap

def scan_network(target, ports='1-65535'):
    nm = nmap.PortScanner()
    print(f"Scanning {target} on ports {ports}...")
    try:
        nm.scan(target, ports, arguments='-sV --script vuln')
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                    print(f"Details: {nm[host][proto][port].get('script', 'No vulnerabilities found')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target = input("Enter the target IP or domain: ")
    ports = input("Enter port range (e.g., 1-1000): ")
    scan_network(target, ports)
