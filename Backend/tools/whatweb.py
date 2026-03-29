# Backend/tools/whatweb.py

import subprocess
import json
import re


def normalize_whatweb_target(target_url):
    """
    Normalize target for WhatWeb - ensure HTTP protocol
    """
    if not target_url:
        return target_url

    # Remove any protocol to check content
    clean_url = re.sub(r'^https?://', '', target_url)

    # Force HTTP for local targets
    if any(term in clean_url for term in ['localhost', '127.0.0.1', '0.0.0.0', 'app:', 'websecscan_']):
        if target_url.startswith('https://'):
            target_url = target_url.replace('https://', 'http://')
        elif not target_url.startswith('http://'):
            target_url = f'http://{target_url}'

    return target_url


def run_whatweb_scan(target_url):
    """
    Runs WhatWeb scan on the target URL and returns the results as JSON.
    """
    # Normalize URL first
    target_url = normalize_whatweb_target(target_url)
    print(f"🔍 WhatWeb executing scan on: {target_url}")

    try:
        # Run WhatWeb with JSON output format
        command = ['whatweb', '--color=never', '--log-json=-', target_url]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            # Check if it's an SSL/TLS error
            if any(term in error_msg.lower() for term in ['ssl', 'tls', 'certificate']):
                error_msg = f"WhatWeb SSL/TLS Error: {error_msg}. Try using HTTP:// instead of HTTPS://"

            return {
                "status": "error",
                "message": f"WhatWeb scan failed: {error_msg}",
                "target": target_url,
                "plugins": [],
                "raw_output": result.stderr
            }

        # Parse JSON output
        try:
            output_lines = result.stdout.strip().split('\n')

            # Filter out empty lines
            output_lines = [line for line in output_lines if line.strip()]

            if output_lines:
                # Try to parse each line as JSON
                json_output = None
                for line in output_lines:
                    try:
                        json_output = json.loads(line)
                        break  # Stop at first valid JSON
                    except json.JSONDecodeError:
                        continue

                if json_output is None:
                    # No valid JSON found
                    return {
                        "status": "ok",
                        "target": target_url,
                        "plugins": [],
                        "raw_output": result.stdout,
                        "message": "No valid JSON found in output"
                    }

                # Handle array response from WhatWeb
                if isinstance(json_output, list):
                    if len(json_output) > 0:
                        # Take the first element if it's an array with content
                        json_output = json_output[0]
                    else:
                        # Empty array - return empty plugins
                        return {
                            "status": "ok",
                            "target": target_url,
                            "plugins": [],
                            "raw_output": []
                        }

                # Extract plugins from the response
                plugins = []
                if isinstance(json_output, dict):
                    # Different possible structures
                    if 'plugins' in json_output:
                        plugins = json_output.get('plugins', [])
                    elif 'technologies' in json_output:
                        plugins = json_output.get('technologies', [])
                    else:
                        # If no plugins array, create a list of detected technologies
                        for key, value in json_output.items():
                            if key not in ['target', 'http_status', 'ip', 'title']:
                                if isinstance(value, dict) or isinstance(value, list):
                                    plugins.append({key: value})

                return {
                    "status": "ok",
                    "target": target_url,
                    "plugins": plugins,
                    "raw_output": json_output
                }
            else:
                # Empty output - return success with empty plugins
                return {
                    "status": "ok",
                    "target": target_url,
                    "plugins": [],
                    "raw_output": {},
                    "message": "WhatWeb returned empty output"
                }

        except json.JSONDecodeError as e:
            # If JSON parsing fails, try to extract any useful information from the output
            print(f"[WHATWEB] JSON parse error: {e}")
            print(f"[WHATWEB] Raw output: {result.stdout[:200]}")

            # Check if output contains any technology information
            plugins = []
            lines = result.stdout.split('\n')
            for line in lines:
                # Look for common technology indicators
                if '[' in line and ']' in line and any(
                        x in line.lower() for x in ['php', 'nginx', 'apache', 'jquery', 'bootstrap']):
                    # Extract technology name
                    match = re.search(r'\[([^\]]+)\]', line)
                    if match:
                        tech = match.group(1)
                        plugins.append({"name": tech})

            return {
                "status": "ok",
                "target": target_url,
                "plugins": plugins,
                "raw_output": result.stdout,
                "message": f"Parsed from text output: {e}"
            }

    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "message": "WhatWeb scan timed out after 300 seconds",
            "target": target_url,
            "plugins": []
        }
    except Exception as e:
        print(f"[WHATWEB] Exception: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": f"WhatWeb scan exception: {str(e)}",
            "target": target_url,
            "plugins": []
        }


# Optional: Add a test function
if __name__ == "__main__":
    # Test the whatweb scanner
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    print(f"Testing WhatWeb with: {test_url}")
    result = run_whatweb_scan(test_url)
    print(json.dumps(result, indent=2))