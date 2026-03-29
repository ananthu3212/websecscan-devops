# -----------------------------------------------------------
# Modul: delta_analysis.py  (COMPLETELY FIXED)
# -----------------------------------------------------------

from flask import Blueprint, request, jsonify
from sqlalchemy.orm import Session
from Backend.db import SessionLocal
from Backend.models import (
    WhatwebFinding, NmapFinding, NiktoFinding, ZapFinding,
    HarvesterFinding, ScanDelta, ScanMain, ScanCVE
)
from datetime import datetime, timezone
import json

delta_bp = Blueprint("delta_bp", __name__, url_prefix="/api")


@delta_bp.post("/delta/scan")
def compare_scans():
    data = request.get_json()
    old_scan_id = data.get("old_scan_id")
    new_scan_id = data.get("new_scan_id")

    if not old_scan_id or not new_scan_id:
        return jsonify({"error": "Bitte old_scan_id und new_scan_id angeben"}), 400

    session: Session = SessionLocal()
    result = {}

    try:
        old_scan = session.query(ScanMain).get(old_scan_id)
        new_scan = session.query(ScanMain).get(new_scan_id)

        old_target = old_scan.target if old_scan else None
        new_target = new_scan.target if new_scan else None

        # ============================================================
        # 🔍 HARVESTER DELTA
        # ============================================================

        def extract_harvester_items(record: HarvesterFinding):
            items = []

            # Always include summary even if 0
            items.append({
                "type": "summary",
                "value": f"emails:{record.emails_count or 0}",
                "explanation": f"Email addresses found: {record.emails_count or 0}"
            })
            items.append({
                "type": "summary",
                "value": f"hosts:{record.hosts_count or 0}",
                "explanation": f"Hosts found: {record.hosts_count or 0}"
            })
            items.append({
                "type": "summary",
                "value": f"ips:{record.ips_count or 0}",
                "explanation": f"IP addresses found: {record.ips_count or 0}"
            })
            items.append({
                "type": "summary",
                "value": f"total:{record.total_findings or 0}",
                "explanation": f"Total OSINT findings: {record.total_findings or 0}"
            })

            # Extract from raw data
            if record.raw:
                try:
                    raw = record.raw if isinstance(record.raw, dict) else json.loads(str(record.raw))
                    results = raw.get("results", {})

                    for e in results.get("emails", []):
                        if e and str(e).strip():
                            items.append({
                                "type": "email",
                                "value": str(e).strip(),
                                "explanation": f"Email address: {e}"
                            })
                    for h in results.get("hosts", []):
                        if h and str(h).strip():
                            items.append({
                                "type": "host",
                                "value": str(h).strip(),
                                "explanation": f"Host/Subdomain: {h}"
                            })
                    for i in results.get("ips", []):
                        if i and str(i).strip():
                            items.append({
                                "type": "ip",
                                "value": str(i).strip(),
                                "explanation": f"IP address: {i}"
                            })
                except:
                    pass

            return items

        old_h = []
        new_h = []

        old_harvester = session.query(HarvesterFinding).filter_by(scan_id=old_scan_id).first()
        new_harvester = session.query(HarvesterFinding).filter_by(scan_id=new_scan_id).first()

        if old_harvester:
            old_h = extract_harvester_items(old_harvester)
        if new_harvester:
            new_h = extract_harvester_items(new_harvester)

        # Create unique keys for comparison
        def harvester_key(item):
            return f"{item.get('type', '')}:{item.get('value', '')}"

        old_harvester_dict = {harvester_key(item): item for item in old_h}
        new_harvester_dict = {harvester_key(item): item for item in new_h}

        old_harvester_keys = set(old_harvester_dict.keys())
        new_harvester_keys = set(new_harvester_dict.keys())

        result["harvester"] = {
            "old_scan": old_h,
            "new_scan": new_h,
            "added": [new_harvester_dict[key] for key in new_harvester_keys - old_harvester_keys],
            "removed": [old_harvester_dict[key] for key in old_harvester_keys - new_harvester_keys]
        }

        # ============================================================
        # 🔍 CVE DELTA
        # ============================================================

        old_cves = [
            link.cve.cve_id
            for link in session.query(ScanCVE).filter_by(scan_id=old_scan_id)
            if link.cve and link.cve.cve_id
        ]

        new_cves = [
            link.cve.cve_id
            for link in session.query(ScanCVE).filter_by(scan_id=new_scan_id)
            if link.cve and link.cve.cve_id
        ]

        old_cves_set = set(old_cves)
        new_cves_set = set(new_cves)

        result["cve"] = {
            "old_scan": [{"cve": c, "explanation": f"CVE: {c}"} for c in old_cves],
            "new_scan": [{"cve": c, "explanation": f"CVE: {c}"} for c in new_cves],
            "added": [
                {"cve": c, "explanation": f"New CVE detected: {c}"}
                for c in new_cves_set - old_cves_set
            ],
            "removed": [
                {"cve": c, "explanation": f"CVE no longer present: {c}"}
                for c in old_cves_set - new_cves_set
            ]
        }

        # ============================================================
        # 🔍 WHATWEB DELTA - COMPLETELY FIXED
        # ============================================================

        def extract_whatweb_data(f: WhatwebFinding):
            # Start with basic fields
            server = (f.server or "").strip()
            title = (f.title or "").strip()
            ip = (f.ip or "").strip()
            http_status = f.http_status

            # Try to extract more data from raw field
            if not server and f.raw:
                try:
                    raw_data = f.raw if isinstance(f.raw, dict) else json.loads(str(f.raw))
                    if not server and 'plugins' in raw_data:
                        plugins = raw_data.get('plugins', {})
                        for plugin_name, plugin_data in plugins.items():
                            if isinstance(plugin_data, dict) and 'string' in plugin_data:
                                server = plugin_data.get('string', '')
                                break
                    if not title and 'title' in raw_data:
                        title = raw_data.get('title', '')
                except:
                    pass

            # Build meaningful explanation
            explanation_parts = []
            if server:
                explanation_parts.append(f"Server: {server}")
            else:
                server = "Web Server"

            if title:
                explanation_parts.append(f"Title: {title}")
            else:
                title = "Website"

            if http_status:
                explanation_parts.append(f"Status: {http_status}")
            if ip:
                explanation_parts.append(f"IP: {ip}")

            explanation = "WhatWeb: " + (" | ".join(explanation_parts) if explanation_parts else "Web technology scan")

            return {
                "ip": ip,
                "server": server,
                "title": title,
                "http_status": http_status,
                "explanation": explanation
            }

        def ww_key(f: WhatwebFinding):
            return f"{f.ip or ''}:{f.server or ''}:{f.title or ''}:{f.http_status or ''}"

        old_ww = session.query(WhatwebFinding).filter_by(scan_id=old_scan_id).all()
        new_ww = session.query(WhatwebFinding).filter_by(scan_id=new_scan_id).all()

        old_ww_dict = {ww_key(f): extract_whatweb_data(f) for f in old_ww}
        new_ww_dict = {ww_key(f): extract_whatweb_data(f) for f in new_ww}

        old_ww_keys = set(old_ww_dict.keys())
        new_ww_keys = set(new_ww_dict.keys())

        result["whatweb"] = {
            "old_scan": [extract_whatweb_data(f) for f in old_ww],
            "new_scan": [extract_whatweb_data(f) for f in new_ww],
            "added": [new_ww_dict[key] for key in new_ww_keys - old_ww_keys],
            "removed": [old_ww_dict[key] for key in old_ww_keys - new_ww_keys]
        }

        # ============================================================
        # 🔍 NMAP DELTA
        # ============================================================

        def extract_nmap_data(f: NmapFinding):
            service = (f.service or "").strip()
            product = (f.product or "").strip()
            version = (f.version or "").strip()
            port = f.port or ""
            protocol = (f.protocol or "tcp").strip()
            ip = (f.ip or "").strip()

            # Build description
            desc_parts = []
            if service:
                desc_parts.append(service)
            if product:
                desc_parts.append(product)
            if version:
                desc_parts.append(f"v{version}")
            desc = " ".join(desc_parts) if desc_parts else "Service"

            explanation = f"Port {port}/{protocol}: {desc}"
            if ip:
                explanation = f"{ip}:{port}/{protocol}: {desc}"

            return {
                "ip": ip,
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "protocol": protocol,
                "explanation": explanation
            }

        def nm_key(f: NmapFinding):
            return f"{f.ip or ''}:{f.port or ''}:{f.service or ''}:{f.protocol or ''}"

        old_nm = session.query(NmapFinding).filter_by(scan_id=old_scan_id).all()
        new_nm = session.query(NmapFinding).filter_by(scan_id=new_scan_id).all()

        old_nm_dict = {nm_key(f): extract_nmap_data(f) for f in old_nm}
        new_nm_dict = {nm_key(f): extract_nmap_data(f) for f in new_nm}

        old_nm_keys = set(old_nm_dict.keys())
        new_nm_keys = set(new_nm_dict.keys())

        result["nmap"] = {
            "old_scan": [extract_nmap_data(f) for f in old_nm],
            "new_scan": [extract_nmap_data(f) for f in new_nm],
            "added": [new_nm_dict[key] for key in new_nm_keys - old_nm_keys],
            "removed": [old_nm_dict[key] for key in old_nm_keys - new_nm_keys]
        }

        # ============================================================
        # 🔍 NIKTO DELTA
        # ============================================================

        def extract_nikto_data(f: NiktoFinding):
            host = (f.host or "").strip()
            port = f.port or 80
            high = f.high or 0
            medium = f.medium or 0
            low = f.low or 0
            total = f.findings_count or (high + medium + low)

            # Determine risk level
            risk_level = ""
            if high > 0:
                risk_level = f"High risk ({high} issues)"
            elif medium > 0:
                risk_level = f"Medium risk ({medium} issues)"
            elif low > 0:
                risk_level = f"Low risk ({low} issues)"
            else:
                risk_level = "No security issues"

            explanation = f"Nikto: {host}:{port} - {risk_level}"

            return {
                "host": host,
                "port": port,
                "high": high,
                "medium": medium,
                "low": low,
                "total_findings": total,
                "explanation": explanation
            }

        def nk_key(f: NiktoFinding):
            return f"{f.host or ''}:{f.port or ''}"

        old_nk = session.query(NiktoFinding).filter_by(scan_id=old_scan_id).all()
        new_nk = session.query(NiktoFinding).filter_by(scan_id=new_scan_id).all()

        old_nk_dict = {nk_key(f): extract_nikto_data(f) for f in old_nk}
        new_nk_dict = {nk_key(f): extract_nikto_data(f) for f in new_nk}

        old_nk_keys = set(old_nk_dict.keys())
        new_nk_keys = set(new_nk_dict.keys())

        result["nikto"] = {
            "old_scan": [extract_nikto_data(f) for f in old_nk],
            "new_scan": [extract_nikto_data(f) for f in new_nk],
            "added": [new_nk_dict[key] for key in new_nk_keys - old_nk_keys],
            "removed": [old_nk_dict[key] for key in old_nk_keys - new_nk_keys]
        }

        # ============================================================
        # 🔍 ZAP DELTA
        # ============================================================

        def extract_zap_data(f: ZapFinding):
            target = (f.target or new_target or "").strip()
            high = f.risk_high or 0
            medium = f.risk_medium or 0
            low = f.risk_low or 0
            info = f.risk_info or 0
            total = f.alerts_count or (high + medium + low + info)

            # Determine alert level
            alert_level = ""
            if high > 0:
                alert_level = f"High alerts ({high})"
            elif medium > 0:
                alert_level = f"Medium alerts ({medium})"
            elif low > 0:
                alert_level = f"Low alerts ({low})"
            elif info > 0:
                alert_level = f"Info alerts ({info})"
            else:
                alert_level = "No alerts"

            explanation = f"ZAP: {target} - {alert_level} (Total: {total})"

            return {
                "target": target,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "total_alerts": total,
                "explanation": explanation
            }

        def zp_key(f: ZapFinding):
            return f.target or ""

        old_zp = session.query(ZapFinding).filter_by(scan_id=old_scan_id).all()
        new_zp = session.query(ZapFinding).filter_by(scan_id=new_scan_id).all()

        old_zp_dict = {zp_key(f): extract_zap_data(f) for f in old_zp}
        new_zp_dict = {zp_key(f): extract_zap_data(f) for f in new_zp}

        old_zp_keys = set(old_zp_dict.keys())
        new_zp_keys = set(new_zp_dict.keys())

        result["zap"] = {
            "old_scan": [extract_zap_data(f) for f in old_zp],
            "new_scan": [extract_zap_data(f) for f in new_zp],
            "added": [new_zp_dict[key] for key in new_zp_keys - old_zp_keys],
            "removed": [old_zp_dict[key] for key in old_zp_keys - new_zp_keys]
        }

        # ============================================================
        # 💾 SAVE DELTAS TO DATABASE
        # ============================================================

        for tool, delta_data in result.items():
            session.add(
                ScanDelta(
                    old_scan_id=old_scan_id,
                    new_scan_id=new_scan_id,
                    tool=tool,
                    added=delta_data.get("added", []),
                    removed=delta_data.get("removed", []),
                    created_at=datetime.now(timezone.utc)
                )
            )

        session.commit()

    except Exception as e:
        session.rollback()
        import traceback
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500

    finally:
        session.close()

    return jsonify({
        "status": "ok",
        "message": "Delta comparison completed successfully.",
        "delta": result,
        "scan_info": {
            "old_scan_id": old_scan_id,
            "new_scan_id": new_scan_id,
            "old_target": old_target,
            "new_target": new_target
        }
    }), 200


@delta_bp.get("/delta/history")
def get_delta_history():
    """Get delta comparison history"""
    session: Session = SessionLocal()
    try:
        deltas = session.query(ScanDelta).order_by(ScanDelta.created_at.desc()).limit(50).all()

        history = []
        for delta in deltas:
            history.append({
                "id": delta.id,
                "old_scan_id": delta.old_scan_id,
                "new_scan_id": delta.new_scan_id,
                "tool": delta.tool,
                "added_count": len(delta.added) if delta.added else 0,
                "removed_count": len(delta.removed) if delta.removed else 0,
                "created_at": delta.created_at.isoformat() if delta.created_at else None
            })

        return jsonify({
            "status": "ok",
            "history": history,
            "total": len(history)
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@delta_bp.get("/delta/<int:delta_id>")
def get_delta_details(delta_id):
    """Get detailed delta comparison by ID"""
    session: Session = SessionLocal()
    try:
        delta = session.query(ScanDelta).get(delta_id)

        if not delta:
            return jsonify({"error": "Delta comparison not found"}), 404

        return jsonify({
            "status": "ok",
            "delta": {
                "id": delta.id,
                "old_scan_id": delta.old_scan_id,
                "new_scan_id": delta.new_scan_id,
                "tool": delta.tool,
                "added": delta.added or [],
                "removed": delta.removed or [],
                "created_at": delta.created_at.isoformat() if delta.created_at else None
            }
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()