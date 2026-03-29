# Backend/tools/nikto.py

import os
import re
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlparse
import time


# ---------- helpers ----------
def _norm(u: str) -> str:
    """Normalize URL to ensure it has a scheme (http/https)."""
    if not u:
        return u
    return u if urlparse(u).scheme else "http://" + u


def _which_nikto() -> str | None:
    """Find the Nikto binary in the system path or environment."""
    candidates = [
        "/usr/local/bin/nikto",
        "/usr/bin/nikto",
        "/opt/homebrew/bin/nikto",
    ]
    candidates = [c for c in candidates if c]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c
    return None


def _read_text(path: str) -> str:
    """Read the contents of a file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception as e:
        return f"(could not read report) {e}"


def _clean_refs(refs):
    """Trim trailing punctuation from URLs."""
    out = []
    for r in refs:
        out.append(r.rstrip("):.,;"))
    return out


def _txt_to_json(txt: str) -> dict:
    """Normalize Nikto TXT report into a simple JSON structure."""
    vulns, host, port = [], None, None
    try:
        for raw in (txt or "").splitlines():
            line = raw.strip()
            if line.startswith("+ Target Host:"):
                host = line.split(":", 1)[1].strip()
            elif line.startswith("+ Target Port:"):
                port = line.split(":", 1)[1].strip()
            elif line.startswith("+ "):
                payload = line[2:].strip()
                path = None
                m = re.match(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\S+)\s*:(.*)$", payload, re.I)
                if m:
                    path = m.group(2).strip()
                    desc = (m.group(3) or "").strip() or payload
                    title = f"{m.group(1).upper()} {path}"
                else:
                    desc = payload
                    title = (payload.split(":", 1)[0] or "nikto finding").strip()
                refs = _clean_refs(re.findall(r"(https?://\S+)", payload))
                vulns.append({
                    "name": title,
                    "severity": "info",
                    "description": desc,
                    "url": path,
                    "references": refs
                })
        return {"host": host, "port": port, "vulnerabilities": vulns}
    except Exception as e:
        return {"error": f"Failed to parse Nikto output: {str(e)}"}


def _safe_unlink(path: str):
    try:
        if path and os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def _classify_warnings(*stderr_texts: str) -> list:
    """Return list of warning strings detected in stderr outputs."""
    warnings = []
    patterns = [
        ("Error limit", r"error limit\s*\(\d+\)\s*reached"),
        ("Read timeout", r"read\s+timed\s*out|timeout"),
        ("HTTP read error", r"error\s+reading\s+http\s+response"),
        ("Connection reset/refused", r"connection\s+(reset|refused)"),
        ("DNS/Resolve issue", r"unable\s+to\s+resolve|no\s+such\s+host"),
    ]
    text = " | ".join([t or "" for t in stderr_texts]).lower()
    for label, rx in patterns:
        if re.search(rx, text):
            warnings.append(label)
    return sorted(set(warnings))


def _derive_status(proc_rc: int, has_warnings: bool, finding_count: int) -> str:
    """
    Business rule:
    - Findings > 0  => 'ok' (Warnings are Info, not Fail)
    - Otherwise: warnings/rc != 0 => 'warning', else 'ok'
    """
    if finding_count > 0:
        return "ok"
    if proc_rc != 0 or has_warnings:
        return "warning"
    return "ok"


# ---------- main ----------
def run_nikto_scan(url: str, retries=3, delay=5) -> dict:
    """
    Run Nikto scan with retry logic and robust stderr handling.
    - Prefer JSON output; fallback/override with TXT normalization if JSON is sparse.
    - Adds 'warnings' when stderr indicates transient/host-side issues.
    - Adds 'meta' with error_limit_seen, port, scheme.
    """
    print(f"=== NIKTO TOOL DEBUG: Starting scan for {url} ===")
    url = _norm(url)
    parsed = urlparse(url)
    is_https = (parsed.scheme or "").lower() == "https"
    host = parsed.hostname or parsed.netloc or url
    port = 443 if is_https else 80

    nikto_bin = _which_nikto()

    if not nikto_bin:
        return {
            "status": "error",
            "engine": "unknown",
            "target": url,
            "error": "Nikto not found. Install nikto or set NIKTO_PATH (binary) or NIKTO_PERL (nikto.pl)."
        }

    txt_file = None
    result = None
    engine = "binary"

    for attempt in range(retries):
        try:

            with tempfile.NamedTemporaryFile(prefix="nikto_", suffix=".txt", delete=False) as tf:
                txt_file = tf.name

            # commands (no '-v', explicit host/port, -ssl only for https, with timeout)
            base = [nikto_bin]
            common = ["-h", host, "-port", str(port), "-ask", "no", "-nointeractive", "-timeout", "30", "-Option",
                      "FAILURES=100"]

            cmd_txt = base + common + ["-output", txt_file, "-Format", "txt"]
            if is_https:
                cmd_txt.append("-ssl")

            # run Nikto
            proc_txt = subprocess.run(cmd_txt, capture_output=True, text=True)
            txt_stderr = (proc_txt.stderr or "").strip()
            txt = _read_text(txt_file)
            txt_norm = _txt_to_json(txt)

            txt_count = len((txt_norm or {}).get("vulnerabilities", [])) if isinstance(txt_norm, dict) else 0

            warnings = _classify_warnings(txt_stderr)

            status = _derive_status(proc_txt.returncode, bool(warnings), txt_count)
            result = {
                "status": status,
                "engine": engine,
                "target": url,
                "report_json": txt_norm.get("vulnerabilities"),  # richer normalization from TXT
                "report_txt": txt,
                "stderr": txt_stderr,
                "warnings": warnings,
                "meta": {
                    "error_limit_seen": "fix",
                    "port": port,
                    "scheme": "https" if is_https else "http",
                },
                "command": f"{' '.join(cmd_txt)}"
            }

            break  # Success path

        except Exception as e:
            if attempt < retries - 1:
                print(f"[nikto] Attempt {attempt + 1}/{retries} failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                return {
                    "status": "error",
                    "engine": engine,
                    "target": url,
                    "error": f"Exception while running Nikto after {retries} attempts: {e}"
                }
        finally:
            # REMOVED: _safe_unlink(json_file) - json_file was never defined
            _safe_unlink(txt_file)

    # Add debug before returning
    print(f"=== NIKTO TOOL DEBUG: Final result status: {result.get('status')} ===")
    if result.get('report_json') and isinstance(result['report_json'], dict):
        vulns = result['report_json'].get('vulnerabilities', [])
        print(f"=== NIKTO TOOL DEBUG: Vulnerabilities count: {len(vulns)} ===")
        if vulns:
            print(f"=== NIKTO TOOL DEBUG: First vulnerability: {vulns[0]} ===")
    else:
        print(f"=== NIKTO TOOL DEBUG: No report_json or not a dict ===")
        print(f"=== NIKTO TOOL DEBUG: report_json: {result.get('report_json')} ===")

    return result