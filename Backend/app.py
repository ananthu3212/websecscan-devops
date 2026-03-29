from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail
from Backend.db import engine
from Backend.models import Base
from routes.scan import execute_unified_scan
from routes.history import build_history_response, get_delta_history
from auth_routes import auth_bp, decode_token_optional
from Backend.routes.delta_analysis import delta_bp
import os
import sys
import warnings
import threading

# 📨 Global Mail object (also for auth_routes)
mail = Mail()


def create_app():
    app = Flask(__name__)
    CORS(app)  # 🌍 Allow API access from frontend/Postman

    # Suppress SSL warnings
    warnings.filterwarnings("ignore", message=".*SSL.*")
    warnings.filterwarnings("ignore", message=".*HTTPS.*")

    # Set environment to prevent HTTPS
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # ==============================================
    # 🔥 CRITICAL: LOG ALL REQUESTS TO IDENTIFY SSL/TLS SOURCE
    # ==============================================
    @app.before_request
    def log_all_requests():
        """Log all incoming requests to identify SSL/TLS source"""
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        path = request.path
        method = request.method

        # Check first bytes for SSL/TLS
        is_ssl = False
        if request.data and len(request.data) >= 3:
            is_ssl = (request.data[0:3] == b'\x16\x03')

        if is_ssl:
            print(f"🚨 DETECTED SSL/TLS HANDSHAKE!")
            print(f"   From IP: {client_ip}")
            print(f"   User-Agent: {user_agent}")
            print(f"   Method: {method} {path}")
            print(f"   First 10 bytes (hex): {request.data[:10].hex()}")
            print(f"   Data length: {len(request.data)} bytes")
        else:
            # Log normal HTTP requests too
            print(f"📥 HTTP Request: {client_ip} {method} {path}")

    # ==============================================
    # 🔥 CRITICAL: BLOCK ALL SSL/TLS HANDSHAKES
    # ==============================================
    @app.before_request
    def block_ssl_traffic():
        """Block ALL SSL/TLS handshakes with detailed logging"""
        # Get client IP
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')

        # Check for SSL/TLS handshake (starts with \x16\x03)
        if request.data and len(request.data) >= 3:
            if request.data[0:3] == b'\x16\x03':
                # Log detailed information
                app.logger.error(f"🚫 BLOCKED SSL/TLS handshake from {client_ip}")
                app.logger.error(f"   User-Agent: {user_agent}")
                app.logger.error(f"   Path: {request.path}")
                app.logger.error(f"   Method: {request.method}")

                # Return a VERY clear error message
                return jsonify({
                    "error": "SSL_TLS_HANDSHAKE_BLOCKED",
                    "message": "This server accepts HTTP only. SSL/TLS handshakes are rejected.",
                    "solution": "Use HTTP:// not HTTPS://",
                    "correct_url": f"http://{request.host}",
                    "client_ip": client_ip,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }), 400

        # Also check if request came via HTTPS proxy
        forwarded_proto = request.headers.get('X-Forwarded-Proto', '').lower()
        if forwarded_proto == 'https':
            app.logger.error(f"🚫 HTTPS via proxy from {client_ip}")
            return jsonify({
                "error": "HTTPS_VIA_PROXY",
                "message": "Your request came via HTTPS proxy. Configure proxy to use HTTP.",
                "client_ip": client_ip,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 400

    # ----------------------------
    # 📧 Mail configuration
    # ----------------------------
    app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "sandbox.smtp.mailtrap.io")
    app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "2525"))
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "")
    app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
    app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "no-reply@websecscan.com")
    mail.init_app(app)

    # ----------------------------
    # 🗄️ Create database tables if not present
    # ----------------------------
    Base.metadata.create_all(bind=engine)

    # ----------------------------
    # 🔐 Enable authentication
    # ----------------------------
    app.register_blueprint(auth_bp)

    # ----------------------------
    # 🧠 Enable Delta comparisons
    # ----------------------------
    app.register_blueprint(delta_bp)

    # ----------------------------
    # 🚀 API: Start scan
    # ----------------------------
    @app.post("/api/scan")
    def api_scan():
        data = request.get_json(silent=True) or {}
        user_id = decode_token_optional(request)

        try:
            payload, code = execute_unified_scan(data, user_id=user_id)
            return jsonify(payload), code
        except Exception as e:
            return jsonify({
                "status": "failed",
                "message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 500

    # ---- API: Get Scan by ID (COMPLETE FIXED VERSION) ----
    @app.get("/api/scan/<int:scan_id>")
    def api_get_scan_by_id(scan_id):
        """Get scan details by ID - COMPLETE FIXED VERSION"""
        from Backend import crud
        from sqlalchemy.orm import Session
        from Backend.models import CVEFinding, WhatwebFinding, NmapFinding, NiktoFinding, ZapFinding, HarvesterFinding

        db = Session(engine)
        try:
            # Use crud.get_scan_by_id
            scan = crud.get_scan_by_id(db, scan_id)
            if not scan:
                return jsonify({"error": "Scan not found"}), 404

            # Initialize results structure
            results = {
                "scan_id": scan.id,
                "target": scan.target,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "user_id": scan.user_id,
                "nmap": [],
                "whatweb": {"output": {}},
                "nikto": {"findings": []},
                "zap": {"alerts": []},
                "harvester": {"results": {}, "summary": {}},
                "cve": {}
            }

            # Get Nmap findings
            nmap_findings = db.query(NmapFinding).filter(NmapFinding.scan_id == scan_id).all()
            if nmap_findings:
                for finding in nmap_findings:
                    if finding.raw:
                        if isinstance(finding.raw, list):
                            results["nmap"].extend(finding.raw)
                        elif isinstance(finding.raw, dict):
                            results["nmap"].append(finding.raw)

            # Get WhatWeb findings
            whatweb_findings = db.query(WhatwebFinding).filter(WhatwebFinding.scan_id == scan_id).all()
            if whatweb_findings:
                for finding in whatweb_findings:
                    if finding.raw and isinstance(finding.raw, dict):
                        results["whatweb"] = finding.raw
                        # Ensure output exists
                        if "output" not in results["whatweb"]:
                            results["whatweb"]["output"] = {}
                        break

            # Get Nikto findings
            nikto_findings = db.query(NiktoFinding).filter(NiktoFinding.scan_id == scan_id).all()
            if nikto_findings:
                for finding in nikto_findings:
                    if finding.raw and isinstance(finding.raw, dict):
                        # Check for different Nikto structures
                        if "findings" in finding.raw:
                            results["nikto"] = finding.raw
                        elif "entries" in finding.raw:
                            results["nikto"] = {"findings": finding.raw.get("entries", [])}
                        else:
                            results["nikto"] = {"findings": [], "status": "no data"}
                        break

            # Get ZAP findings
            zap_findings = db.query(ZapFinding).filter(ZapFinding.scan_id == scan_id).all()
            if zap_findings:
                for finding in zap_findings:
                    if finding.raw and isinstance(finding.raw, dict):
                        if "alerts" in finding.raw:
                            results["zap"] = finding.raw
                        else:
                            # Create alerts array from raw data
                            alerts = []
                            if isinstance(finding.raw.get("alerts"), list):
                                alerts = finding.raw.get("alerts", [])
                            results["zap"] = {
                                "alerts": alerts,
                                "status": finding.raw.get("status", "ok")
                            }
                        break

            # Get Harvester findings
            harvester_findings = db.query(HarvesterFinding).filter(HarvesterFinding.scan_id == scan_id).all()
            if harvester_findings:
                for finding in harvester_findings:
                    if finding.raw and isinstance(finding.raw, dict):
                        results["harvester"] = finding.raw
                        # Ensure results and summary exist
                        if "results" not in results["harvester"]:
                            results["harvester"]["results"] = {}
                        if "summary" not in results["harvester"]:
                            results["harvester"]["summary"] = {
                                "emails_count": finding.emails_count if hasattr(finding, 'emails_count') else 0,
                                "hosts_count": finding.hosts_count if hasattr(finding, 'hosts_count') else 0,
                                "ips_count": finding.ips_count if hasattr(finding, 'ips_count') else 0,
                                "subdomains_count": finding.subdomains_count if hasattr(finding,
                                                                                        'subdomains_count') else 0,
                                "urls_count": finding.urls_count if hasattr(finding, 'urls_count') else 0
                            }
                        break

            # Get CVE findings
            cve_findings = db.query(CVEFinding).filter(CVEFinding.scan_id == scan_id).first()
            if cve_findings:
                if hasattr(cve_findings, 'to_dict'):
                    results["cve"] = cve_findings.to_dict()
                elif cve_findings.raw and isinstance(cve_findings.raw, dict):
                    results["cve"] = cve_findings.raw
                else:
                    results["cve"] = {
                        "status": getattr(cve_findings, 'status', 'unknown'),
                        "total_cves": getattr(cve_findings, 'total_cves', 0),
                        "high_risk": getattr(cve_findings, 'high_risk', 0),
                        "medium_risk": getattr(cve_findings, 'medium_risk', 0),
                        "low_risk": getattr(cve_findings, 'low_risk', 0),
                        "message": "CVE scan results"
                    }
            else:
                results["cve"] = {
                    "status": "no data",
                    "message": "No CVE scan performed",
                    "total_cves": 0,
                    "high_risk": 0,
                    "medium_risk": 0,
                    "low_risk": 0
                }

            return jsonify(results), 200
        except Exception as e:
            print(f"Error getting scan {scan_id}: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500
        finally:
            db.close()

    # ---- API: History ----
    @app.post("/api/history")
    def api_history():
        data = request.get_json(silent=True) or {}
        try:
            payload, code = build_history_response(data)
            return jsonify(payload), code
        except Exception as e:
            return jsonify({
                "status": "error",
                "data": None,
                "error": {"code": type(e).__name__, "message": str(e)}
            }), 500

    # ---- API: CVE Data ----
    @app.get("/api/cve/<cve_id>")
    def api_cve(cve_id):
        try:
            from Backend import crud
            from sqlalchemy.orm import Session

            db = Session(engine)
            cve = crud.get_cve_by_id(db, cve_id)
            db.close()

            if not cve:
                return jsonify({"error": "CVE not found"}), 404

            return jsonify(cve.to_dict()), 200
        except Exception as e:
            return jsonify({
                "status": "failed",
                "message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 500

    # ---- DEBUG API: Test Scan Only ----
    @app.post("/api/debug-scan")
    def api_debug_scan():
        data = request.get_json(silent=True) or {}
        try:
            print("=== DEBUG: Starting scan ===")

            # Test JUST the scan part
            scan_payload, code = execute_unified_scan(data)
            print(f"=== DEBUG: Scan completed with code: {code} ===")

            return jsonify({
                "status": "scan_complete",
                "scan_code": code,
                "message": "Scan finished successfully"
            }), 200

        except Exception as e:
            print(f"=== DEBUG: Exception in scan: {e} ===")
            return jsonify({"status": "scan_failed", "message": str(e)}), 500

    # ---- NEW API: Scan with Vulnerabilities ----
    @app.post("/api/scan-with-vulnerabilities")
    def api_scan_with_vulnerabilities():
        data = request.get_json(silent=True) or {}
        try:
            # Run normal scan
            scan_payload, code = execute_unified_scan(data)

            if code != 200:
                return jsonify(scan_payload), code

            # Get CVE data DIRECTLY from database
            from sqlalchemy.orm import Session
            from Backend.models import CVE

            with Session(engine) as session:
                cves = session.query(CVE).all()
                cve_ids = [cve.cve_id for cve in cves]

                # Use CVE data directly from database
                vulnerability_data = {}
                for cve in cves:
                    vulnerability_data[cve.cve_id] = cve.to_dict()

            # Create unified scan results
            unified_scan_results = create_unified_scan_results(scan_payload, data.get("target", "unknown"))

            return jsonify({
                "scan_results": unified_scan_results,
                "vulnerability_analysis": vulnerability_data,
                "found_cves": cve_ids,
                "total_vulnerabilities": len(cve_ids),
                "status": "success",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200

        except Exception as e:
            return jsonify({
                "status": "failed",
                "message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 500

    # ---- SERVER INFO ENDPOINT (for health checks) ----
    @app.get("/api/server-info")
    def server_info():
        """Return server configuration info - used for health checks"""
        return jsonify({
            "status": "running",
            "server": "websecscan_app",
            "protocol": "HTTP",
            "port": 5001,
            "ssl_enabled": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Flask app is running on HTTP only"
        }), 200

    # ---- DEBUG ENDPOINT: Check request info ----
    @app.get("/api/request-info")
    def request_info():
        """Debug endpoint to see request details"""
        return jsonify({
            "remote_addr": request.remote_addr,
            "scheme": request.scheme,
            "method": request.method,
            "path": request.path,
            "headers": dict(request.headers),
            "has_data": len(request.data) > 0 if request.data else False,
            "data_length": len(request.data) if request.data else 0,
            "is_ssl_handshake": (request.data[:3] == b'\x16\x03') if request.data and len(request.data) >= 3 else False,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    # ---- ROOT ENDPOINT ----
    @app.get("/")
    def root():
        return jsonify({
            "name": "WebSecScan API",
            "version": "1.0.0",
            "status": "operational",
            "endpoints": {
                "scan": "/api/scan",
                "scan_by_id": "/api/scan/{scan_id}",
                "history": "/api/history",
                "server_info": "/api/server-info",
                "request_info": "/api/request-info"
            },
            "protocol": "HTTP ONLY",
            "warning": "HTTPS/SSL is NOT supported. Use http:// protocol only."
        }), 200

    # Global error handling
    @app.errorhandler(Exception)
    def handle_exception(e):
        return jsonify({"status": "error", "message": str(e)}), 500

    return app


def create_unified_scan_results(scan_payload, target):
    """
    Create unified scan results from individual tool results
    REQUIRED: Transform individual tool results into unified format
    """
    # Extract basic information from scan results
    nmap_data = scan_payload.get('nmap_data', [])
    whatweb_data = scan_payload.get('whatweb_data', {})
    zap_data = scan_payload.get('zap_data', {})
    nikto_data = scan_payload.get('nikto_data', {})

    # Create unified results structure
    unified_results = {
        "target": target,
        "scan_summary": {
            "open_ports": len(nmap_data),
            "web_technologies": len(whatweb_data.get('plugins', [])),
            "security_alerts": len(zap_data.get('alerts', [])),
            "vulnerability_findings": len(nikto_data.get('findings', []))
        },
        "services": [],
        "technologies": [],
        "security_issues": {
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0
        }
    }

    # Add services from Nmap
    if isinstance(nmap_data, list):
        for item in nmap_data:
            if isinstance(item, dict) and item.get('port'):
                unified_results["services"].append({
                    "port": item.get('port'),
                    "service": item.get('service'),
                    "version": item.get('version')
                })

    # Add technologies from WhatWeb
    plugins = whatweb_data.get('plugins', [])
    if isinstance(plugins, list):
        for plugin in plugins:
            if isinstance(plugin, dict):
                unified_results["technologies"].append({
                    "name": plugin.get('name'),
                    "version": plugin.get('version')
                })

    return unified_results


if __name__ == "__main__":
    try:
        print("=" * 60)
        print("🚀 WebSecScan Flask App Starting...")
        print("📡 Protocol: HTTP ONLY (HTTPS disabled)")
        print("📂 Working directory:", os.getcwd())
        print("📦 Python path:", sys.path)
        print("🌐 Access URLs:")
        print("   • http://localhost:5001")
        print("   • http://127.0.0.1:5001")
        print("   • http://0.0.0.0:5001")
        print("=" * 60)
        print("🔒 SSL/TLS handshakes will be BLOCKED and logged")
        print("=" * 60)

        app = create_app()

        # 🔥 CRITICAL: Keep Flask running
        print("✅ Flask app initialized. Starting server...")
        app.run(
            debug=True,
            host="0.0.0.0",
            port=5001,
            use_reloader=False,  # Prevents double execution in Docker
            threaded=True
        )

    except Exception as e:
        print(f"❌ CRITICAL ERROR in Flask app: {e}")
        import traceback

        traceback.print_exc()
        print("⚠️  Container will stay alive for debugging...")
        # Keep container alive to see the error
        import time

        while True:
            time.sleep(3600)  # Sleep for 1 hour