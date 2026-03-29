# routes/scan_results.py
from sqlalchemy.orm import Session
from sqlalchemy import desc
from Backend.db import SessionLocal
from Backend.models import ScanMain, WhatwebFinding, NmapFinding, NiktoFinding, ZapFinding
import json


def get_scan_by_id(scan_id):
    """
    Get scan details by ID
    Returns: (response_dict, status_code)
    """
    try:
        with SessionLocal() as session:
            # Get main scan info
            scan = session.query(ScanMain).filter_by(id=scan_id).first()
            if not scan:
                return {"status": "error", "message": "Scan not found"}, 404

            # Initialize result structure matching frontend expectations
            result = {
                "status": "success",
                "target": scan.target,
                "scan_id": scan.id,
                "created_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "whatweb": {"output": {"technologies": {}, "target": scan.target}},
                "nmap": [],
                "nikto": {"findings": []},
                "zap": {"alerts": []}
            }

            # Get WhatWeb findings
            whatweb_findings = session.query(WhatwebFinding).filter_by(scan_id=scan_id).all()
            for finding in whatweb_findings:
                if finding.raw:
                    try:
                        if isinstance(finding.raw, dict):
                            for key, value in finding.raw.items():
                                if key not in ["target", "http_status", "ip", "title"]:
                                    result["whatweb_data"]["output"]["technologies"][key] = value
                        elif isinstance(finding.raw, str):
                            parsed = json.loads(finding.raw)
                            if isinstance(parsed, dict):
                                for key, value in parsed.items():
                                    if key not in ["target", "http_status", "ip", "title"]:
                                        result["whatweb"]["output"]["technologies"][key] = value
                    except:
                        pass

            # Get Nmap findings
            nmap_findings = session.query(NmapFinding).filter_by(scan_id=scan_id).all()
            for finding in nmap_findings:
                if finding.raw:
                    try:
                        if isinstance(finding.raw, dict):
                            nmap_item = {
                                "port": finding.raw.get("port", finding.port),
                                "service": finding.raw.get("service", finding.service),
                                "version": finding.raw.get("version", finding.version),
                                "protocol": finding.raw.get("protocol", finding.protocol or "tcp"),
                                "ip": finding.raw.get("ip", finding.ip)
                            }
                            result["nmap"].append(nmap_item)
                        elif isinstance(finding.raw, str):
                            parsed = json.loads(finding.raw)
                            if isinstance(parsed, dict):
                                result["nmap"].append(parsed)
                    except:
                        pass
                elif finding.port:
                    result["nmap"].append({
                        "port": finding.port,
                        "service": finding.service or "unknown",
                        "version": finding.version or "",
                        "protocol": finding.protocol or "tcp",
                        "ip": finding.ip or ""
                    })

            # Get Nikto findings
            nikto_findings = session.query(NiktoFinding).filter_by(scan_id=scan_id).all()
            for finding in nikto_findings:
                if finding.raw:
                    try:
                        if isinstance(finding.raw, dict):
                            raw_data = finding.raw
                        elif isinstance(finding.raw, str):
                            raw_data = json.loads(finding.raw)
                        else:
                            raw_data = {}

                        if "findings" in raw_data and isinstance(raw_data["findings"], list):
                            for item in raw_data["findings"]:
                                if isinstance(item, dict):
                                    nikto_item = {
                                        "name": item.get("name", "Nikto Finding"),
                                        "description": item.get("description", ""),
                                        "severity": item.get("severity", "info"),
                                        "url": item.get("url"),
                                        "references": item.get("references", [])
                                    }
                                    result["nikto"]["findings"].append(nikto_item)
                        else:
                            nikto_item = {
                                "name": raw_data.get("name", "Nikto Finding"),
                                "description": raw_data.get("description", ""),
                                "severity": raw_data.get("severity", "info"),
                                "url": raw_data.get("url"),
                                "references": raw_data.get("references", [])
                            }
                            result["nikto"]["findings"].append(nikto_item)

                    except:
                        result["nikto"]["findings"].append({
                            "name": f"Nikto Scan on {finding.host or 'unknown'}:{finding.port or 80}",
                            "description": f"Vulnerabilities found: High={finding.high or 0}, Medium={finding.medium or 0}, Low={finding.low or 0}",
                            "severity": "medium" if (finding.medium or 0) > 0 else "low" if (
                                                                                                        finding.low or 0) > 0 else "info",
                            "url": f"http://{finding.host}:{finding.port}" if finding.host and finding.port else None,
                            "references": []
                        })
                else:
                    if finding.high or finding.medium or finding.low:
                        for i in range(finding.high or 0):
                            result["nikto"]["findings"].append({
                                "name": "High Severity Vulnerability",
                                "description": "High severity vulnerability detected by Nikto",
                                "severity": "high",
                                "url": f"http://{finding.host}:{finding.port}" if finding.host and finding.port else None,
                                "references": []
                            })
                        for i in range(finding.medium or 0):
                            result["nikto"]["findings"].append({
                                "name": "Medium Severity Vulnerability",
                                "description": "Medium severity vulnerability detected by Nikto",
                                "severity": "medium",
                                "url": f"http://{finding.host}:{finding.port}" if finding.host and finding.port else None,
                                "references": []
                            })
                        for i in range(finding.low or 0):
                            result["nikto"]["findings"].append({
                                "name": "Low Severity Vulnerability",
                                "description": "Low severity vulnerability detected by Nikto",
                                "severity": "low",
                                "url": f"http://{finding.host}:{finding.port}" if finding.host and finding.port else None,
                                "references": []
                            })

            # Get ZAP findings
            zap_findings = session.query(ZapFinding).filter_by(scan_id=scan_id).all()
            for finding in zap_findings:
                if finding.raw:
                    try:
                        if isinstance(finding.raw, dict):
                            raw_data = finding.raw
                        elif isinstance(finding.raw, str):
                            raw_data = json.loads(finding.raw)
                        else:
                            raw_data = {}

                        if "alerts" in raw_data and isinstance(raw_data["alerts"], list):
                            for alert in raw_data["alerts"]:
                                if isinstance(alert, dict):
                                    zap_alert = {
                                        "name": alert.get("name", "ZAP Alert"),
                                        "description": alert.get("description", ""),
                                        "risk": alert.get("risk", "Medium"),
                                        "url": alert.get("url"),
                                        "reference": alert.get("reference"),
                                        "pluginId": alert.get("pluginId"),
                                        "confidence": alert.get("confidence"),
                                        "solution": alert.get("solution")
                                    }
                                    result["zap"]["alerts"].append(zap_alert)
                        else:
                            zap_alert = {
                                "name": raw_data.get("name", "ZAP Alert"),
                                "description": raw_data.get("description", ""),
                                "risk": raw_data.get("risk", "Medium"),
                                "url": raw_data.get("url"),
                                "reference": raw_data.get("reference"),
                                "pluginId": raw_data.get("pluginId"),
                                "confidence": raw_data.get("confidence"),
                                "solution": raw_data.get("solution")
                            }
                            result["zap"]["alerts"].append(zap_alert)

                    except:
                        pass
                elif finding.alerts_count and finding.alerts_count > 0:
                    for i in range(finding.risk_high or 0):
                        result["zap"]["alerts"].append({
                            "name": "High Risk Security Alert",
                            "description": "High risk security vulnerability detected",
                            "risk": "High",
                            "url": finding.target or scan.target,
                            "reference": "",
                            "pluginId": None,
                            "confidence": "High",
                            "solution": "Review and fix the vulnerability"
                        })
                    for i in range(finding.risk_medium or 0):
                        result["zap"]["alerts"].append({
                            "name": "Medium Risk Security Alert",
                            "description": "Medium risk security vulnerability detected",
                            "risk": "Medium",
                            "url": finding.target or scan.target,
                            "reference": "",
                            "pluginId": None,
                            "confidence": "Medium",
                            "solution": "Review and fix the vulnerability"
                        })
                    for i in range(finding.risk_low or 0):
                        result["zap"]["alerts"].append({
                            "name": "Low Risk Security Alert",
                            "description": "Low risk security vulnerability detected",
                            "risk": "Low",
                            "url": finding.target or scan.target,
                            "reference": "",
                            "pluginId": None,
                            "confidence": "Low",
                            "solution": "Review and consider fixing the vulnerability"
                        })

            return result, 200

    except Exception as e:
        return {"status": "error", "message": str(e)}, 500
