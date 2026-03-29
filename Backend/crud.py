# Backend/crud.py
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_
from .models import ScanMain, WhatwebFinding, NmapFinding, NiktoFinding, ZapFinding, HarvesterFinding, CVE, ScanCVE, \
    CVEFinding, User


# -------------------------------
# SCAN MAIN
# -------------------------------
def create_scan(db: Session, target: str, user_id: int | None = None) -> ScanMain:
    """
    Erstellt einen neuen Eintrag in scan_main (Status=running).
    - target: Ziel-URL oder IP
    - user_id: optional, wenn der Scan einem eingeloggten User gehört
    """
    scan = ScanMain(
        target=target,
        status="running",
        user_id=user_id,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def finish_scan(db: Session, scan: ScanMain, status: str = "ok") -> ScanMain:
    """Setzt Status + Endzeitpunkt für einen Scan."""
    scan.status = status
    scan.finished_at = datetime.now(timezone.utc)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(scan)
    return scan


def get_scan_by_id(db: Session, scan_id: int) -> ScanMain:
    """Holt einen Scan anhand seiner ID."""
    return db.query(ScanMain).filter(ScanMain.id == scan_id).first()


# -------------------------------
# WHATWEB
# -------------------------------
def add_whatweb(db: Session, scan_id: int, ww_dict: dict) -> WhatwebFinding:
    """
    Speichert WhatWeb-Ergebnisse.
    """
    out = (ww_dict or {}).get("output") or {}
    headers = out.get("headers") or {}

    item = WhatwebFinding(
        scan_id=scan_id,
        raw=ww_dict,
        http_status=out.get("http_status"),
        ip=out.get("ip"),
        server=out.get("server"),
        title=out.get("title"),
        plugins_count=(len(out.get("plugins")) if isinstance(out.get("plugins"), list) else None),
        powered_by=headers.get("X-Powered-By"),
        created_at=datetime.now(timezone.utc),
    )
    try:
        db.add(item)
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(item)
    return item


def get_whatweb_findings(db: Session, scan_id: int):
    """Get WhatWeb findings for a scan"""
    return db.query(WhatwebFinding).filter(WhatwebFinding.scan_id == scan_id).all()


# -------------------------------
# NMAP
# -------------------------------
def add_nmap(db: Session, scan_id: int, nmap_list: list) -> NmapFinding:
    """
    Speichert Nmap-Ergebnisse.
    """
    ip = port = service = product = version = protocol = None
    open_ports = None
    error_text = None

    try:
        if isinstance(nmap_list, dict):
            if "error" in nmap_list:
                error_text = str(nmap_list.get("error"))
        elif isinstance(nmap_list, list):
            if nmap_list and isinstance(nmap_list[0], dict):
                if "error" in nmap_list[0]:
                    error_text = str(nmap_list[0].get("error"))
                else:
                    first = nmap_list[0]
                    ip = first.get("ip")
                    port = first.get("port")
                    service = first.get("service")
                    product = first.get("product")
                    version = first.get("version")
                    protocol = first.get("protocol")
                    open_ports = len(
                        [x for x in nmap_list if isinstance(x, dict) and x.get("port") is not None]
                    )
            else:
                open_ports = 0
        else:
            error_text = "Unexpected Nmap result format"
    except Exception as e:
        error_text = f"parse_error: {e}"

    item = NmapFinding(
        scan_id=scan_id,
        raw=nmap_list,
        ip=ip,
        port=port,
        service=service,
        product=product,
        version=version,
        protocol=protocol,
        open_ports=open_ports,
        error=error_text,
        created_at=datetime.now(timezone.utc),
    )
    try:
        db.add(item)
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(item)
    return item


def get_nmap_findings(db: Session, scan_id: int):
    """Get Nmap findings for a scan"""
    return db.query(NmapFinding).filter(NmapFinding.scan_id == scan_id).all()


# -------------------------------
# NIKTO
# -------------------------------
def add_nikto(db: Session, scan_id: int, nikto_dict: dict) -> NiktoFinding:
    """
    Speichert Nikto-Ergebnisse.
    """
    raw = nikto_dict or {}
    host = raw.get("host")
    ip = raw.get("ip")
    port = raw.get("port")

    findings = raw.get("findings") or raw.get("entries") or []
    findings_count = len(findings) if isinstance(findings, list) else None

    high = medium = low = None
    if isinstance(findings, list):
        def norm_sev(v) -> str:
            s = "" if v is None else str(v).strip().lower()
            if s in ("3", "high", "hoch", "kritisch", "critical"):
                return "high"
            if s in ("2", "medium", "mittel"):
                return "medium"
            if s in ("1", "low", "gering"):
                return "low"
            return ""

        h = m = l = 0
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = f.get("severity") or f.get("risk") or f.get("level")
            cat = norm_sev(sev)
            if cat == "high":
                h += 1
            elif cat == "medium":
                m += 1
            elif cat == "low":
                l += 1
        high, medium, low = h, m, l

    error_text = raw.get("error")

    item = NiktoFinding(
        scan_id=scan_id,
        raw=raw,
        report_path=raw.get("report_txt") or raw.get("report_path"),
        host=host,
        ip=ip,
        port=port,
        findings_count=findings_count,
        high=high,
        medium=medium,
        low=low,
        error=error_text,
        created_at=datetime.now(timezone.utc),
    )
    try:
        db.add(item)
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(item)
    return item


def get_nikto_findings(db: Session, scan_id: int):
    """Get Nikto findings for a scan"""
    return db.query(NiktoFinding).filter(NiktoFinding.scan_id == scan_id).all()


# -------------------------------
# OWASP ZAP
# -------------------------------
def add_zap(db: Session, scan_id: int, zap_dict: dict) -> ZapFinding:
    """
    Speichert ZAP-Ergebnisse.
    """
    raw = zap_dict or {}
    alerts = raw.get("alerts") or []
    target = raw.get("site") or raw.get("target")

    h = m = l = i = 0

    def norm_risk(v) -> str:
        s = "" if v is None else str(v).strip().lower()
        if "high" in s or "hoch" in s or s == "3":
            return "high"
        if "medium" in s or "mittel" in s or s == "2":
            return "medium"
        if "low" in s or "gering" in s or s == "1":
            return "low"
        return "info"

    if isinstance(alerts, list):
        for a in alerts:
            if not isinstance(a, dict):
                i += 1
                continue
            r = a.get("risk") or a.get("riskDesc")
            cat = norm_risk(r)
            if cat == "high":
                h += 1
            elif cat == "medium":
                m += 1
            elif cat == "low":
                l += 1
            else:
                i += 1

    item = ZapFinding(
        scan_id=scan_id,
        raw=raw,
        alerts_count=(len(alerts) if isinstance(alerts, list) else 0),
        target=target,
        risk_high=h,
        risk_medium=m,
        risk_low=l,
        risk_info=i,
        created_at=datetime.now(timezone.utc),
    )
    try:
        db.add(item)
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(item)
    return item


def get_zap_findings(db: Session, scan_id: int):
    """Get ZAP findings for a scan"""
    return db.query(ZapFinding).filter(ZapFinding.scan_id == scan_id).all()


# -------------------------------
# HARVESTER
# -------------------------------
def add_harvester(db: Session, scan_id: int, harvester_data: dict) -> HarvesterFinding:
    """
    Speichert Harvester-Ergebnisse (OSINT).
    """
    data = harvester_data or {}
    results = data.get("results") or {}
    summary = data.get("summary") or {}

    # Calculate total findings
    total = (
            summary.get("emails_count", 0) +
            summary.get("hosts_count", 0) +
            summary.get("ips_count", 0) +
            summary.get("subdomains_count", 0) +
            summary.get("urls_count", 0)
    )

    item = HarvesterFinding(
        scan_id=scan_id,
        raw=data,
        domain=data.get("domain"),
        status=data.get("status", "unknown"),
        emails_count=summary.get("emails_count", 0),
        hosts_count=summary.get("hosts_count", 0),
        ips_count=summary.get("ips_count", 0),
        subdomains_count=summary.get("subdomains_count", 0),
        urls_count=summary.get("urls_count", 0),
        total_findings=total,
        error=data.get("error"),
        created_at=datetime.now(timezone.utc),
    )
    try:
        db.add(item)
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(item)
    return item


def get_harvester_findings(db: Session, scan_id: int):
    """Get Harvester findings for a scan"""
    return db.query(HarvesterFinding).filter(HarvesterFinding.scan_id == scan_id).all()


# -------------------------------
# CVE FINDINGS (NEW TABLE - CVEFinding)
# -------------------------------
def add_cve_finding(db: Session, scan_id: int, data: dict):
    """
    Add CVE scan results to the new CVEFinding table
    """
    # Extract summary from data
    total_cves = data.get('total_cves', 0)
    high_risk = data.get('high_risk', 0)
    medium_risk = data.get('medium_risk', 0)
    low_risk = data.get('low_risk', 0)
    status = data.get('status', 'pending')
    error = data.get('error')

    item = CVEFinding(
        scan_id=scan_id,
        raw=data,
        total_cves=total_cves,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        status=status,
        error=error,
        created_at=datetime.now(timezone.utc),
    )
    try:
        db.add(item)
        db.commit()
        db.refresh(item)
        return item
    except Exception as e:
        db.rollback()
        print(f"Error adding CVE finding: {e}")
        return None


def update_cve_finding(db: Session, scan_id: int, data: dict):
    """
    Update CVE finding in database
    """
    cve_finding = db.query(CVEFinding).filter(CVEFinding.scan_id == scan_id).first()
    if not cve_finding:
        # Create new if doesn't exist
        return add_cve_finding(db, scan_id, data)

    # Update existing
    cve_finding.raw = data
    cve_finding.total_cves = data.get('total_cves', cve_finding.total_cves)
    cve_finding.high_risk = data.get('high_risk', cve_finding.high_risk)
    cve_finding.medium_risk = data.get('medium_risk', cve_finding.medium_risk)
    cve_finding.low_risk = data.get('low_risk', cve_finding.low_risk)
    cve_finding.status = data.get('status', cve_finding.status)
    cve_finding.error = data.get('error', cve_finding.error)

    try:
        db.commit()
        db.refresh(cve_finding)
        return cve_finding
    except Exception as e:
        db.rollback()
        print(f"Error updating CVE finding: {e}")
        return None


def get_cve_finding(db: Session, scan_id: int):
    """Get single CVE finding for a scan"""
    cve = db.query(CVEFinding).filter(CVEFinding.scan_id == scan_id).first()
    if cve:
        return cve.to_dict()
    return None


def get_cve_findings(db: Session, scan_id: int):
    """Get all CVE findings for a scan"""
    return db.query(CVEFinding).filter(CVEFinding.scan_id == scan_id).all()


# -------------------------------
# CVE DATABASE OPERATIONS
# -------------------------------
def get_cve_by_id(db: Session, cve_id: str) -> CVE:
    """Holt ein CVE anhand seiner ID (z.B. 'CVE-2021-44228')."""
    return db.query(CVE).filter(CVE.cve_id == cve_id).first()


def save_cve_data(db: Session, cve_data: dict):
    """
    Save CVE data to the CVE database table
    """
    cve_id = cve_data.get('cve_id')
    if not cve_id:
        return None

    # Check if CVE already exists
    existing_cve = get_cve_by_id(db, cve_id)

    if existing_cve:
        # Update existing
        existing_cve.description = cve_data.get('description', existing_cve.description)
        existing_cve.cvss_score = cve_data.get('cvss_score', existing_cve.cvss_score)
        existing_cve.severity = cve_data.get('severity', existing_cve.severity)
        existing_cve.published_date = cve_data.get('published_date', existing_cve.published_date)
        existing_cve.last_modified = cve_data.get('last_modified', existing_cve.last_modified)
        existing_cve.epss_score = cve_data.get('epss_score', existing_cve.epss_score)
        existing_cve.services = cve_data.get('services', existing_cve.services)
        cve = existing_cve
    else:
        # Create new
        cve = CVE(
            cve_id=cve_id,
            description=cve_data.get('description'),
            cvss_score=cve_data.get('cvss_score'),
            severity=cve_data.get('severity'),
            published_date=cve_data.get('published_date'),
            last_modified=cve_data.get('last_modified'),
            epss_score=cve_data.get('epss_score'),
            services=cve_data.get('services')
        )
        db.add(cve)

    try:
        db.commit()
        db.refresh(cve)
        return cve
    except Exception as e:
        db.rollback()
        print(f"Error saving CVE data: {e}")
        return None


def get_all_cves(db: Session, limit: int = 1000):
    """Get all CVEs from database"""
    return db.query(CVE).order_by(CVE.published_date.desc()).limit(limit).all()


def search_cves_by_keyword(db: Session, keyword: str, limit: int = 100):
    """Search CVEs by keyword in description"""
    return db.query(CVE).filter(
        or_(
            CVE.cve_id.ilike(f'%{keyword}%'),
            CVE.description.ilike(f'%{keyword}%')
        )
    ).order_by(CVE.cvss_score.desc()).limit(limit).all()


def get_high_risk_cves(db: Session, limit: int = 100):
    """Get high and critical risk CVEs"""
    return db.query(CVE).filter(
        or_(
            CVE.severity == 'CRITICAL',
            CVE.severity == 'HIGH'
        )
    ).order_by(CVE.cvss_score.desc()).limit(limit).all()


def link_cve_to_scan(db: Session, scan_id: int, cve_id: str, additional_data: dict = None):
    """
    Link a CVE to a specific scan
    """
    # Get CVE from database
    cve = get_cve_by_id(db, cve_id)
    if not cve:
        # CVE doesn't exist in database
        return False

    # Check if already linked
    existing_link = db.query(ScanCVE).filter_by(
        scan_id=scan_id,
        cve_id=cve.id
    ).first()

    if existing_link:
        return True  # Already linked

    # Create new link
    scan_cve = ScanCVE(
        scan_id=scan_id,
        cve_id=cve.id,
        created_at=datetime.now(timezone.utc)
    )

    try:
        db.add(scan_cve)
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        print(f"Error linking CVE to scan: {e}")
        return False


def get_scan_cves(db: Session, scan_id: int):
    """Get all CVEs linked to a scan"""
    scan_cves = db.query(ScanCVE).filter(ScanCVE.scan_id == scan_id).all()
    cve_ids = [sc.cve_id for sc in scan_cves]

    if not cve_ids:
        return []

    return db.query(CVE).filter(CVE.id.in_(cve_ids)).all()


# -------------------------------
# USER OPERATIONS
# -------------------------------
def get_user_by_username(db: Session, username: str) -> User:
    """Holt einen Benutzer anhand des Benutzernamens."""
    return db.query(User).filter(User.username == username).first()


def get_user_by_email(db: Session, email: str) -> User:
    """Holt einen Benutzer anhand der E-Mail."""
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> User:
    """Holt einen Benutzer anhand der ID."""
    return db.query(User).filter(User.id == user_id).first()


def create_user(db: Session, username: str, email: str, password: str) -> User:
    """Erstellt einen neuen Benutzer."""
    user = User(username=username, email=email)
    user.set_password(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# -------------------------------
# HISTORY/REPORT FUNCTIONS
# -------------------------------
def get_scan_with_findings(db: Session, scan_id: int) -> dict:
    """
    Holt einen Scan mit allen zugehörigen Findings.
    """
    scan = get_scan_by_id(db, scan_id)
    if not scan:
        return None

    # Get all findings for this scan
    whatweb_findings = get_whatweb_findings(db, scan_id)
    nmap_findings = get_nmap_findings(db, scan_id)
    nikto_findings = get_nikto_findings(db, scan_id)
    zap_findings = get_zap_findings(db, scan_id)
    harvester_findings = get_harvester_findings(db, scan_id)
    cve_findings = get_cve_findings(db, scan_id)
    linked_cves = get_scan_cves(db, scan_id)

    return {
        "scan": scan,
        "whatweb": whatweb_findings,
        "nmap": nmap_findings,
        "nikto": nikto_findings,
        "zap": zap_findings,
        "harvester": harvester_findings,
        "cve_findings": cve_findings,
        "linked_cves": linked_cves
    }


def get_scans_by_user(db: Session, user_id: int, limit: int = 100, offset: int = 0):
    """
    Holt Scans für einen bestimmten Benutzer.
    """
    scans = db.query(ScanMain) \
        .filter(ScanMain.user_id == user_id) \
        .order_by(ScanMain.started_at.desc()) \
        .offset(offset) \
        .limit(limit) \
        .all()

    total = db.query(ScanMain) \
        .filter(ScanMain.user_id == user_id) \
        .count()

    return {
        "scans": scans,
        "total": total,
        "limit": limit,
        "offset": offset
    }


def delete_scan(db: Session, scan_id: int) -> bool:
    """
    Löscht einen Scan und alle zugehörigen Findings.
    """
    scan = get_scan_by_id(db, scan_id)
    if not scan:
        return False

    try:
        # Cascade delete will handle related findings
        db.delete(scan)
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def update_scan_status(db: Session, scan_id: int, status: str) -> ScanMain:
    """
    Aktualisiert den Status eines Scans.
    """
    scan = get_scan_by_id(db, scan_id)
    if not scan:
        return None

    scan.status = status
    if status in ["completed", "failed", "error"]:
        scan.finished_at = datetime.now(timezone.utc)

    try:
        db.commit()
        db.refresh(scan)
        return scan
    except Exception:
        db.rollback()
        return None


def get_recent_scans(db: Session, limit: int = 50):
    """
    Get recent scans ordered by start time
    """
    return db.query(ScanMain) \
        .order_by(ScanMain.started_at.desc()) \
        .limit(limit) \
        .all()


def get_scans_by_status(db: Session, status: str, limit: int = 100):
    """
    Get scans by status
    """
    return db.query(ScanMain) \
        .filter(ScanMain.status == status) \
        .order_by(ScanMain.started_at.desc()) \
        .limit(limit) \
        .all()


def count_scans(db: Session, user_id: int = None):
    """
    Count total scans (optionally for a specific user)
    """
    query = db.query(ScanMain)
    if user_id:
        query = query.filter(ScanMain.user_id == user_id)
    return query.count()


def count_completed_scans(db: Session, user_id: int = None):
    """
    Count completed scans (optionally for a specific user)
    """
    query = db.query(ScanMain).filter(ScanMain.status == "ok")
    if user_id:
        query = query.filter(ScanMain.user_id == user_id)
    return query.count()