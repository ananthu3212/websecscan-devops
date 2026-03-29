# Backend/tools/nmap.py


from urllib.parse import urlparse 
import nmap 
import socket
import re


def extract_host_from_url(target_url):
    """
    Extract hostname/IP from URL, handling both HTTP and HTTPS
    """
    # Remove protocol
    if target_url.startswith('http://'):
        host = target_url[7:]  # Remove 'http://'
    elif target_url.startswith('https://'):
        host = target_url[8:]  # Remove 'https://'
    else:
        host = target_url

    # Remove path
    if '/' in host:
        host = host.split('/')[0]

    # Remove port if specified
    if ':' in host:
        # Keep port for Nmap scanning
        return host

    return host


def scan_url(target_url):
    """
    Scan a URL with Nmap
    """
    # Extract host (Nmap doesn't need protocol)
    host = extract_host_from_url(target_url)
    print(f"🔍 Nmap scanning host: {host} (extracted from: {target_url})")

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": "Ungültige URL oder nicht auflösbar"}, 400

    # ⚙️ Starte Nmap-Scan
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024', arguments='-sV')

    results = []

    # 🔁 Alle Ergebnisse durchgehen und speichern
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                s = scanner[host][proto][port]
                result = {
                    'ip': host,
                    'port': port,
                    'protocol': proto,
                    'service': s.get('name', ''),
                    'product': s.get('product', ''),
                    'version': s.get('version', '')
                }
                results.append(result)



    return results
