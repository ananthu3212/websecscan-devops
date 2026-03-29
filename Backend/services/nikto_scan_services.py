# services/nikto_scan_services.py
from Backend.tools.nikto import run_nikto_scan  # ADD THIS IMPORT


def normalize_target_for_nikto(target_url):
    """
    Normalize target URL for Nikto - force HTTP for local targets
    """
    if not target_url:
        return target_url

    original_url = target_url

    # Force HTTP for local targets
    if 'localhost' in target_url or '127.0.0.1' in target_url or '0.0.0.0' in target_url:
        if target_url.startswith('https://'):
            target_url = target_url.replace('https://', 'http://')
        elif not target_url.startswith('http://'):
            target_url = f'http://{target_url}'

    if original_url != target_url:
        print(f"🔧 Nikto: Normalized URL: {original_url} → {target_url}")

    return target_url


def nikto_scan(target_url):
    """
    Executes a Nikto scan against the target URL.
    Returns the scan results or raises an exception on failure.
    """
    # Normalize URL for HTTP
    target_url = normalize_target_for_nikto(target_url)
    print(f"🔍 Nikto scanning: {target_url}")

    # Call the actual tool function - ADD THIS LINE
    return run_nikto_scan(target_url)  # THIS WAS MISSING