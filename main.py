import logging
from security_automation import scan_ports, scan_for_vulnerabilities
from security_actions import send_notification, block_ip, remediate_vulnerability

logging.basicConfig(filename='security_automation.log', level=logging.INFO)

if __name__ == "__main__":
    target_ip = "192.168.1.100"
    ports_to_scan = [80, 443, 22, 3389]

    try:
        open_ports = scan_ports(target_ip, ports_to_scan)
        if open_ports:
            logging.info(f"Open ports on {target_ip}: {', '.join(map(str, open_ports))}")
            send_notification(f"Open ports found on {target_ip}: {', '.join(map(str, open_ports))}")
        else:
            logging.info(f"No open ports found on {target_ip}")

        vulnerabilities = scan_for_vulnerabilities(target_ip)
        if vulnerabilities:
            for vuln in vulnerabilities:
                logging.info(f"Vulnerability found: {vuln['plugin_name']} (Severity: {vuln['severity']})")
                remediate_vulnerability(vuln)  # Remediate vulnerabilities
        else:
            logging.info(f"No vulnerabilities found on {target_ip}")

    except Exception as e:
        logging.error(f"Error during security scan on {target_ip}: {str(e)}")
