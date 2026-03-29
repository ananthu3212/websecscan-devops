# Backend/tools/harvester.py

import subprocess
import json
import re
import os
from urllib.parse import urlparse
from datetime import datetime, timezone

DEFAULT_SOURCES = [
    "rapiddns",
    "crtsh",
    "hackertarget",
    "otx",
    "urlscan"
]


# ------------------------------
# Normalize input like Nikto/Nmap
# ------------------------------
def normalize_input(target: str) -> str:
    if not target:
        return target

    parsed = urlparse(target)

    if parsed.netloc:
        return parsed.netloc.lower()

    return target.lower()


# ------------------------------
# Validate domain safely
# ------------------------------
def validate_domain(domain: str) -> str:
    pattern = r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z]{2,})+$"

    if not re.match(pattern, domain):
        raise ValueError("Invalid domain format")

    return domain


# ------------------------------
# Main scan function
# ------------------------------
def run_harvester_scan(domain: str, sources=None, limit: int = 200):
    domain = normalize_input(domain)
    domain = validate_domain(domain)

    if sources is None:
        sources = DEFAULT_SOURCES

    print(f"[HARVESTER] Scanning {domain}")

    return _run_cli(domain, sources, limit)


# ------------------------------
# Run theHarvester CLI (FIXED VERSION - PARSES TEXT OUTPUT)
# ------------------------------
def _run_cli(domain: str, sources, limit):
    """
    Run theHarvester CLI inside Docker container and parse text output
    """

    # Path to theHarvester in the Docker container (from dockerfile)
    harvester_path = "/opt/theHarvester"

    # Find theHarvester executable
    harvester_bin = None

    # First, try to find theHarvester in PATH
    try:
        # Check if theHarvester is in PATH
        subprocess.run(["which", "theHarvester"], capture_output=True, check=True)
        harvester_bin = "theHarvester"
        print(f"[HARVESTER] Found theHarvester in PATH")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Not in PATH, try the full path
        potential_paths = [
            os.path.join(harvester_path, "theHarvester"),
            os.path.join(harvester_path, "theHarvester.py"),
            "/usr/local/bin/theHarvester",
            "/usr/bin/theHarvester"
        ]

        for path in potential_paths:
            if os.path.exists(path):
                harvester_bin = path
                print(f"[HARVESTER] Found theHarvester at: {path}")
                break

    if not harvester_bin:
        return {
            "status": "error",
            "error": "theHarvester not found. Looked in PATH and various locations."
        }

    # Build command - WITHOUT -f json flag since it doesn't work properly
    if isinstance(harvester_bin, list):
        cmd = harvester_bin + [
            "-d", domain,
            "-l", str(limit),
            "-b", ",".join(sources)
        ]
    else:
        cmd = [
            harvester_bin,
            "-d", domain,
            "-l", str(limit),
            "-b", ",".join(sources)
        ]

    try:
        print(f"[HARVESTER] Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")

        # Run the command
        proc = subprocess.run(
            cmd,
            cwd=harvester_path if os.path.exists(harvester_path) else None,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        print(f"[HARVESTER] Return code: {proc.returncode}")

        if proc.returncode != 0:
            error_msg = proc.stderr.strip() or "Harvester execution failed"
            print(f"[HARVESTER] Error: {error_msg}")

            return {
                "status": "error",
                "error": error_msg,
                "stderr": proc.stderr,
                "stdout": proc.stdout[:500]
            }

        # Parse the text output to extract emails, hosts, etc.
        return _parse_text_output(proc.stdout, domain)

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Harvester timeout after 300 seconds"
        }
    except Exception as e:
        print(f"[HARVESTER] Exception: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "error": str(e)
        }


# ------------------------------
# Parse text output from theHarvester
# ------------------------------
def _parse_text_output(output: str, domain: str):
    """
    Parse the text output from theHarvester to extract emails, hosts, ips, etc.
    """
    lines = output.split('\n')

    emails = []
    hosts = []
    ips = []
    urls = []

    current_section = None
    in_banner = True

    for line in lines:
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Check for section headers
        if '[*] Emails' in line or '[*] EMAILS' in line.upper():
            current_section = 'emails'
            in_banner = False
            continue
        elif '[*] Hosts' in line or '[*] HOSTS' in line.upper():
            current_section = 'hosts'
            in_banner = False
            continue
        elif '[*] IPs' in line or '[*] IPS' in line.upper():
            current_section = 'ips'
            in_banner = False
            continue
        elif '[*] Urls' in line or '[*] URLS' in line.upper() or '[*] URLs' in line:
            current_section = 'urls'
            in_banner = False
            continue
        elif '[*] Reporting started' in line or '[*] XML File saved' in line or '[*] JSON File saved' in line:
            # End of results
            current_section = None
            continue

        # Skip banner lines (contain * characters)
        if in_banner and '*' in line:
            continue

        # Skip separator lines
        if line.startswith('---') or line.startswith('***') or line.startswith('==='):
            continue

        # Skip lines that are just counters or metadata
        if line.startswith('[*]') and 'found' in line.lower():
            continue

        # Add items based on current section
        if current_section == 'emails':
            # Look for email addresses
            if '@' in line and not line.startswith('['):
                # Extract email from line (remove any prefixes)
                email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
                if email_match:
                    emails.append(email_match.group(0))
                else:
                    # If no regex match but contains @, add the whole line if it looks like an email
                    if line.count('@') == 1 and '.' in line.split('@')[1]:
                        emails.append(line)

        elif current_section == 'hosts':
            # Look for hostnames/domains
            if line and not line.startswith('[') and not line.startswith('*'):
                # Remove any port numbers
                host = line.split(':')[0].strip()
                # Check if it looks like a domain
                if '.' in host and not host.startswith('http'):
                    hosts.append(host)

        elif current_section == 'ips':
            # Look for IP addresses
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ips.append(ip_match.group(0))
            elif line.count('.') == 3 and all(part.isdigit() for part in line.split('.')):
                ips.append(line)

        elif current_section == 'urls':
            # Look for URLs
            if line.startswith('http://') or line.startswith('https://'):
                urls.append(line)

    # Deduplicate all lists
    emails = list(set(emails))
    hosts = list(set(hosts))
    ips = list(set(ips))
    urls = list(set(urls))

    # Extract clean subdomains from hosts
    subdomains = set()
    for host in hosts:
        # Check if host ends with the target domain
        if host.endswith(domain):
            subdomains.add(host)
        # Also check if it's a subdomain (contains domain but not equal to domain)
        elif domain in host and host != domain:
            subdomains.add(host)

    subdomains = list(subdomains)

    # If we didn't find anything with the parsing, try a more aggressive approach
    if not emails and not hosts and not ips and not urls:
        # Fallback: try to extract everything that looks like relevant data
        for line in lines:
            line = line.strip()

            # Skip banner and separator lines
            if not line or line.startswith('*') or line.startswith('-') or line.startswith('='):
                continue

            # Check for emails
            if '@' in line and '.' in line:
                email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
                if email_match:
                    emails.append(email_match.group(0))

            # Check for IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ips.append(ip_match.group(0))

            # Check for hosts/domains (simple heuristic)
            if '.' in line and not line.startswith('http') and not line.startswith('*'):
                words = line.split()
                for word in words:
                    # Clean the word
                    word = word.strip('.,:;!?[](){}')
                    if '.' in word and len(word) > 3 and ' ' not in word:
                        # Check if it might be a domain
                        parts = word.split('.')
                        if len(parts) >= 2 and all(len(p) > 1 for p in parts[-2:]):
                            hosts.append(word)

        # Deduplicate again
        emails = list(set(emails))
        hosts = list(set(hosts))
        ips = list(set(ips))
        urls = list(set(urls))
        subdomains = [h for h in hosts if domain in h]
        subdomains = list(set(subdomains))

    summary = {
        "emails_count": len(emails),
        "hosts_count": len(hosts),
        "ips_count": len(ips),
        "subdomains_count": len(subdomains),
        "urls_count": len(urls),
    }

    print(f"[HARVESTER] Parsed results: {summary}")

    return {
        "status": "success",
        "domain": domain,
        "results": {
            "emails": emails[:50],  # Limit to 50 to avoid huge responses
            "hosts": hosts[:50],
            "ips": ips[:50],
            "subdomains": subdomains[:50],
            "urls": urls[:50],
        },
        "summary": summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------
# Clean & Deduplicate results (legacy function, kept for compatibility)
# ------------------------------
def _clean_results(data: dict, domain: str):
    """
    Legacy function for JSON output - kept for compatibility
    """
    emails = list(set(data.get("emails", [])))
    hosts = list(set(data.get("hosts", [])))
    ips = list(set(data.get("ips", [])))
    urls = list(set(data.get("urls", [])))

    # Extract clean subdomains
    subdomains = set()

    for h in hosts:
        # Handle hosts that might include ports
        clean = h.split(":")[0].strip()
        if clean.endswith(domain):
            subdomains.add(clean)

    subdomains = list(subdomains)

    summary = {
        "emails_count": len(emails),
        "hosts_count": len(hosts),
        "ips_count": len(ips),
        "subdomains_count": len(subdomains),
        "urls_count": len(urls),
    }

    return {
        "status": "success",
        "domain": domain,
        "results": {
            "emails": emails,
            "hosts": hosts,
            "ips": ips,
            "subdomains": subdomains,
            "urls": urls,
        },
        "summary": summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------
# Test function (for debugging)
# ------------------------------
if __name__ == "__main__":
    # Test the harvester
    import sys

    if len(sys.argv) > 1:
        test_domain = sys.argv[1]
    else:
        test_domain = "example.com"

    print(f"Testing harvester with domain: {test_domain}")
    result = run_harvester_scan(test_domain)
    print(json.dumps(result, indent=2))