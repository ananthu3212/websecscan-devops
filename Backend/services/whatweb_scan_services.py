# services/whatweb_scan_services.py

from Backend.tools.whatweb import run_whatweb_scan


def normalize_target_for_whatweb(target_url):
    """
    Normalize target URL for WhatWeb - force HTTP for local targets
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
        print(f"🔧 WhatWeb: Normalized URL: {original_url} → {target_url}")

    return target_url


def start_whatweb_scan(target_url):
    # Normalize URL first
    target_url = normalize_target_for_whatweb(target_url)
    print(f"🔍 WhatWeb scanning: {target_url}")
    return run_whatweb_scan(target_url)