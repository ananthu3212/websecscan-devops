# services/harvester_scan_services.py
from Backend.tools.harvester import run_harvester_scan


def harvester_scan(domain: str):
    """
    Führt einen erweiterten Harvester-Scan für eine Domain aus.
    """
    print(f"[HARVESTER SERVICE] Starting scan for domain: {domain}")

    # Run harvester scan
    result = run_harvester_scan(domain)

    print(f"[HARVESTER SERVICE] Scan status: {result.get('status')}")
    print(f"[HARVESTER SERVICE] Summary: {result.get('summary', {})}")

    return result