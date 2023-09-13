import socket

def is_port_open(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except Exception as e:
        logging.error(f"Error checking port {port} on {ip}: {str(e)}")
        return False

def scan_ports(target_ip, ports):
    open_ports = []
    for port in ports:
        if is_port_open(target_ip, port):
            open_ports.append(port)
    return open_ports

def scan_for_vulnerabilities(target_ip):
    try:
        # Integration with Tenable.io (Nessus)
        access_key = "your_access_key"
        secret_key = "your_secret_key"
        client = TenableIO(access_key, secret_key)
        scan = client.scan_instances.create("My Scan", [target_ip], scan_template="basic")
        scan.launch()
        while scan.info()['status'] != 'completed':
            scan.refresh()
        vulnerabilities = scan.vulnerabilities()
        return vulnerabilities
    except Exception as e:
        logging.error(f"Error scanning for vulnerabilities on {target_ip}: {str(e)}")
        return []
