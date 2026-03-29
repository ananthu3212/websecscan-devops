# services/zap_scan_service.py

import time
import requests
from tools.zap import initialize_zap_scanner


def run_zap_scan(target_url, zap_scanner_instance):
    """
    Executes a ZAP scan against the target URL with a custom, highly selective policy.
    Returns the scan results (alerts) or raises an exception on failure.
    """
    if not zap_scanner_instance:
        raise ConnectionError("ZAP scanner is not available.")

    try:
        # Step 1: Adjust ZAP's connection timeout.
        print("Adjusting ZAP connection timeout to 120 seconds...")
        zap_scanner_instance.core.set_option_timeout_in_secs(integer='120')

        # Step 2: Use ZAP as a proxy to ensure the URL is in the Sites tree.
        zap_proxy = {'http': 'http://zap:8080', 'https': 'http://zap:8080'}
        print("Forcing ZAP to register the target URL via a proxy request...")
        requests.get(target_url, proxies=zap_proxy, verify=False)

        # Step 3: Configure a custom policy with only a few critical rules.
        fast_policy_name = 'Minimal Scan Policy'
        print(f"Creating a minimal scan policy '{fast_policy_name}'...")

        # Disable all scanners first
        zap_scanner_instance.ascan.add_scan_policy(scanpolicyname=fast_policy_name)
        zap_scanner_instance.ascan.disable_all_scanners(scanpolicyname=fast_policy_name)

        # Then, enable a few specific, high-priority rules
        zap_scanner_instance.ascan.enable_scanners(
            scanpolicyname=fast_policy_name,
            # Common rules you want to check for quickly
            ids='40018,40019,40020,40021,40022,40023,40024,40025,40026,40027,40028,40029,40030,40031,40032,40033,40034,40035,40036'
        )

        # Set low attack strength and threshold for the enabled rules
        zap_scanner_instance.ascan.update_scan_policy(
            scanpolicyname=fast_policy_name,
            attackstrength='LOW',
            alertthreshold='LOW'
        )

        # Step 4: Start the spider scan and wait for it to complete.
        print(f"Starting spider on target: {target_url}")
        spider_id = zap_scanner_instance.spider.scan(target_url)
        while int(zap_scanner_instance.spider.status(spider_id)) < 100:
            print(f'Spider progress: {zap_scanner_instance.spider.status(spider_id)}%')
            time.sleep(5)
        print("Spidering complete.")

        # Step 5: Run the active scan with the minimal policy and wait for it to complete.
        print("Starting active scan with minimal policy...")
        scan_id = zap_scanner_instance.ascan.scan(target_url, scanpolicyname=fast_policy_name)
        while int(zap_scanner_instance.ascan.status(scan_id)) < 100:
            print(f'Active Scan progress: {zap_scanner_instance.ascan.status(scan_id)}%')
            time.sleep(5)
        print("Active Scan complete.")

        # Step 6: Get and return the results.
        print("Getting results...")
        return zap_scanner_instance.core.alerts()

    except Exception as e:
        raise Exception(f"ZAP scan failed: {str(e)}")