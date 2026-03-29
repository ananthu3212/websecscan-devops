# Backend/tools/__init__.py
from .nmap import scan_url
from .whatweb import run_whatweb_scan
from .nikto import run_nikto_scan  # This is correct
from .zap import initialize_zap_scanner
from .harvester import run_harvester_scan
from .cve_data_api_helper import fetch_cve_data

__all__ = [
    'scan_url',
    'run_whatweb_scan',
    'run_nikto_scan',  # This is correct
    'initialize_zap_scanner',
    'run_harvester_scan',
    'fetch_cve_data'
]