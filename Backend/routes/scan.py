from datetime import datetime, timezone
from Backend.db import SessionLocal
from Backend import crud
from Backend.tools.nmap import scan_url
from Backend.services.whatweb_scan_services import start_whatweb_scan
from Backend.services.nikto_scan_services import nikto_scan
from Backend.services.zap_scan_services import run_zap_scan
from Backend.tools.zap import initialize_zap_scanner
from Backend.tools.harvester import run_harvester_scan
from Backend.tools.cve_data_api_helper import fetch_cve_data
import requests
import json
import time
import threading

# ZAP-Scanner einmalig initialisieren
_ZAP = initialize_zap_scanner()


def execute_unified_scan(data: dict, user_id: int | None = None):
    """
    Führt den kombinierten Scan aus und liefert (payload, http_status_code).
    Jetzt mit VOLLER CVE-Datenbank-Scanning (komplette Datenbank).
    """
    target_url = data.get("target")
    if not target_url:
        return {"error": "Target URL is required"}, 400

    db = SessionLocal()
    scan = None

    try:
        # -------------------------------------------------
        # 1) ScanMain anlegen
        # -------------------------------------------------
        scan = crud.create_scan(db, target=target_url, user_id=user_id)
        scan_id = scan.id  # Store scan_id for background thread

        # -------------------------------------------------
        # 2) Start FULL CVE Scan in background thread
        # -------------------------------------------------
        # First create pending CVE entry
        pending_cve = {
            "status": "scanning",
            "message": "Full CVE database scan in progress...",
            "total_cves": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "scan_started": datetime.now(timezone.utc).isoformat()
        }
        crud.add_cve_finding(db, scan_id, pending_cve)
        db.commit()

        # Start background CVE scan
        def run_full_cve_scan(scan_id_param):
            cve_scan_start = time.time()
            try:
                print(f"[CVE-SCAN] Starting FULL CVE database scan for scan_id: {scan_id_param}")

                # Get ALL CVEs from database - USE SEPARATE SESSION
                from sqlalchemy.orm import Session
                from Backend.db import SessionLocal as NewSessionLocal
                from Backend.models import CVE

                # Create a NEW session for the background thread
                scan_db = NewSessionLocal()
                try:
                    all_cves = scan_db.query(CVE).all()
                    print(f"[CVE-SCAN] Found {len(all_cves)} CVEs in database")

                    # Analyze CVEs
                    high_risk = 0
                    medium_risk = 0
                    low_risk = 0
                    cve_details = {}

                    for cve in all_cves:
                        # Classify by severity
                        severity = cve.severity.upper() if cve.severity else "UNKNOWN"
                        if severity in ["CRITICAL", "HIGH"]:
                            high_risk += 1
                        elif severity == "MEDIUM":
                            medium_risk += 1
                        elif severity in ["LOW", "NONE"]:
                            low_risk += 1

                        # Store basic details
                        cve_details[cve.cve_id] = {
                            "description": cve.description[:200] + "..." if cve.description and len(
                                cve.description) > 200 else cve.description,
                            "cvss_score": cve.cvss_score,
                            "severity": severity,
                            "published_date": cve.published_date.isoformat() if cve.published_date else None
                        }

                    # Create final results
                    cve_scan_results = {
                        "status": "completed",
                        "message": f"Full CVE scan completed in {time.time() - cve_scan_start:.2f} seconds",
                        "total_cves": len(all_cves),
                        "high_risk": high_risk,
                        "medium_risk": medium_risk,
                        "low_risk": low_risk,
                        "cve_details": cve_details,
                        "scan_time_seconds": round(time.time() - cve_scan_start, 2),
                        "scan_method": "full_database_scan"
                    }

                    # Update database
                    crud.update_cve_finding(scan_db, scan_id_param, cve_scan_results)
                    scan_db.commit()

                    print(f"[CVE-SCAN] CVE scan completed: {len(all_cves)} CVEs analyzed")

                except Exception as e:
                    print(f"[CVE-SCAN] Error in full CVE scan: {e}")
                    import traceback
                    traceback.print_exc()
                    try:
                        error_results = {
                            "status": "error",
                            "error": str(e),
                            "message": "CVE scan failed",
                            "scan_method": "full_database_scan"
                        }
                        crud.update_cve_finding(scan_db, scan_id_param, error_results)
                        scan_db.commit()
                    except:
                        pass
                finally:
                    scan_db.close()

            except Exception as e:
                print(f"[CVE-SCAN] Outer error in full CVE scan: {e}")
                import traceback
                traceback.print_exc()

        # Start CVE scan in background
        cve_thread = threading.Thread(target=run_full_cve_scan, args=(scan_id,), daemon=True)
        cve_thread.start()

        # -------------------------------------------------
        # 3) Harvester Scan
        # -------------------------------------------------
        try:
            print(f"[SCAN] Starting Harvester scan for: {target_url}")
            harvester_results = run_harvester_scan(target_url)
            print(f"[SCAN] Harvester results: {harvester_results.get('status')}")
        except Exception as e:
            print(f"[SCAN] Harvester failed: {e}")
            harvester_results = {
                "status": "error",
                "error": str(e),
                "summary": {
                    "emails_count": 0,
                    "hosts_count": 0,
                    "ips_count": 0,
                    "subdomains_count": 0,
                    "urls_count": 0
                }
            }

        # Save Harvester results to database
        crud.add_harvester(db, scan.id, harvester_results)

        # -------------------------------------------------
        # 4) WhatWeb Scan
        # -------------------------------------------------
        try:
            print(f"[SCAN] Starting WhatWeb scan")
            whatweb_results = start_whatweb_scan(target_url)
            print(f"[SCAN] WhatWeb results: {whatweb_results.get('status', 'unknown')}")
        except Exception as e:
            print(f"[SCAN] WhatWeb failed: {e}")
            whatweb_results = {"status": "error", "error": str(e)}

        crud.add_whatweb(db, scan.id, whatweb_results)

        # -------------------------------------------------
        # 5) Nmap Scan
        # -------------------------------------------------
        try:
            print(f"[SCAN] Starting Nmap scan")
            nmap_results = scan_url(target_url)
            print(f"[SCAN] Nmap completed with {len(nmap_results) if isinstance(nmap_results, list) else 0} results")
        except Exception as e:
            print(f"[SCAN] Nmap failed: {e}")
            nmap_results = {"error": str(e)}

        crud.add_nmap(db, scan.id, nmap_results)

        # -------------------------------------------------
        # 6) Nikto Scan
        # -------------------------------------------------
        try:
            print(f"[SCAN] Starting Nikto scan")
            nikto_results = nikto_scan(target_url)
            print(f"[SCAN] Nikto results: {nikto_results.get('status', 'unknown')}")
        except Exception as e:
            print(f"[SCAN] Nikto failed: {e}")
            nikto_results = {"status": "error", "error": str(e)}

        crud.add_nikto(db, scan.id, nikto_results)

        # -------------------------------------------------
        # 7) ZAP Scan
        # -------------------------------------------------
        zap_results = {"status": "skipped", "alerts": []}
        if _ZAP:
            try:
                print(f"[SCAN] Starting ZAP scan")
                zr = run_zap_scan(target_url, _ZAP)
                if isinstance(zr, list):
                    zap_results = {"status": "ok", "alerts": zr}
                    print(f"[SCAN] ZAP found {len(zr)} alerts")
                elif isinstance(zr, dict):
                    zap_results = zr
                    zap_results.setdefault("alerts", [])
                    print(f"[SCAN] ZAP completed with status: {zap_results.get('status', 'unknown')}")
            except Exception as e:
                print(f"[SCAN] ZAP failed: {e}")
                zap_results = {"status": "error", "error": str(e), "alerts": []}
        else:
            print("[SCAN] ZAP scanner not available, skipping")

        crud.add_zap(db, scan.id, zap_results)

        # -------------------------------------------------
        # 8) Scan abschließen
        # -------------------------------------------------
        crud.finish_scan(db, scan, status="ok")

        # -------------------------------------------------
        # 9) Get current CVE status
        # -------------------------------------------------
        current_cve = crud.get_cve_finding(db, scan.id)
        if not current_cve:
            current_cve = {
                "status": "scanning",
                "message": "CVE scan in progress...",
                "scan_method": "full_database_scan"
            }

        # -------------------------------------------------
        # 10) Response-Payload
        # -------------------------------------------------
        response_payload = {
            "status": "success",
            "message": "scan completed (CVE scan running in background)",
            "scan_id": scan.id,
            "user_id": user_id,
            "target": target_url,
            "harvester": harvester_results,
            "whatweb": whatweb_results,
            "nmap": nmap_results,
            "nikto": nikto_results,
            "zap": zap_results,
            "cve": current_cve,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "CVE database scan is running in background. Check scan results later using /api/scan/{scan_id}"
        }

        print(f"[SCAN] Scan {scan.id} completed successfully")
        return response_payload, 200

    except Exception as e:
        print(f"[SCAN] Critical error during scan: {e}")
        import traceback
        traceback.print_exc()
        if scan:
            try:
                crud.finish_scan(db, scan, status="error")
            except Exception:
                db.rollback()

        return {
            "status": "failed",
            "message": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, 500

    finally:
        db.close()