# ---------------------------------------------------------
# Modelle für alle Datenbanktabellen – FINAL MERGED VERSION
# Kombiniert eure Modelle + Team 2 Modelle
# Enthält:
#   - ScanMain (mit user_id)
#   - WhatWeb, Nmap, Nikto, ZAP, Harvester
#   - Benutzer/User-Modell + Passwort-Hashing
#   - ScanDelta (Scan-Vergleich)
#   - BlacklistedToken (Logout/JWT-Handling)
#   - CVE Modelle
# ---------------------------------------------------------

from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Text,
    Boolean, Float, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
import bcrypt

Base = declarative_base()


# ============================================================
# USER-MODELL (aus Team 2) – benötigt für user_id in ScanMain
# ============================================================

class User(Base):
    """
    Benutzer-Modell mit Passwort-Hashing.
    Wird für Authentifizierung + ScanMain.user_id benötigt.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    active = Column(Boolean(), default=False)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)

    scans = relationship("ScanMain", backref="user", passive_deletes=True)

    def set_password(self, password: str):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))
        except Exception:
            return False

    def __repr__(self):
        return f"<User id={self.id} username={self.username}>"


# ============================================================
# SCAN MAIN
# ============================================================

class ScanMain(Base):
    """
    Zentraltabelle für jeden Scan.
    Enthält Target, Status, Zeitstempel und Verknüpfungen zu allen Tools.
    """
    __tablename__ = "scan_main"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(2048), nullable=False, index=True)

    # Verbindung zum Benutzer (falls eingeloggt)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)

    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    status = Column(String(32), default="running", nullable=False)
    notes = Column(Text, nullable=True)

    # Beziehungen zu den Ergebnistabellen
    whatweb = relationship("WhatwebFinding", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    nmap = relationship("NmapFinding", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    nikto = relationship("NiktoFinding", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    zap = relationship("ZapFinding", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)
    harvester_findings = relationship("HarvesterFinding", back_populates="scan", cascade="all, delete-orphan",
                                      passive_deletes=True)
    cve_findings = relationship("CVEFinding", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)

    def __repr__(self):
        return f"<ScanMain id={self.id} target={self.target} status={self.status}>"


# ============================================================
# WHATWEB
# ============================================================

class WhatwebFinding(Base):
    """
    Ergebnisse von WhatWeb.
    Enthält Rohdaten + Schlüsselspalten für UI/Filter.
    """
    __tablename__ = "whatweb_findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), index=True, nullable=False)

    raw = Column(JSONB, nullable=True)

    http_status = Column(Integer, nullable=True, index=True)
    ip = Column(String(128), nullable=True, index=True)
    server = Column(String(256), nullable=True)
    title = Column(String(512), nullable=True)
    plugins_count = Column(Integer, nullable=True)
    powered_by = Column(String(256), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanMain", back_populates="whatweb", passive_deletes=True)


# ============================================================
# NMAP
# ============================================================

class NmapFinding(Base):
    """
    Ergebnisse von Nmap inkl. Ports/Services.
    """
    __tablename__ = "nmap_findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), index=True, nullable=False)

    raw = Column(JSONB, nullable=True)

    ip = Column(String(128), nullable=True, index=True)
    port = Column(Integer, nullable=True, index=True)
    service = Column(String(128), nullable=True, index=True)
    product = Column(String(256), nullable=True)
    version = Column(String(128), nullable=True)
    protocol = Column(String(16), nullable=True)

    open_ports = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanMain", back_populates="nmap", passive_deletes=True)


# ============================================================
# NIKTO
# ============================================================

class NiktoFinding(Base):
    """
    Ergebnisse von Nikto (inkl. TXT/JSON-Report).
    """
    __tablename__ = "nikto_findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), index=True, nullable=False)

    raw = Column(JSONB, nullable=True)
    report_path = Column(Text, nullable=True)

    host = Column(String(256), nullable=True)
    ip = Column(String(128), nullable=True, index=True)
    port = Column(Integer, nullable=True, index=True)

    findings_count = Column(Integer, nullable=True)
    high = Column(Integer, nullable=True)
    medium = Column(Integer, nullable=True)
    low = Column(Integer, nullable=True)

    error = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanMain", back_populates="nikto", passive_deletes=True)


# ============================================================
# ZAP
# ============================================================

class ZapFinding(Base):
    """
    Ergebnisse von OWASP ZAP.
    """
    __tablename__ = "zap_findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), index=True, nullable=False)

    raw = Column(JSONB, nullable=True)
    alerts_count = Column(Integer, nullable=True)

    target = Column(String(512), nullable=True)
    risk_high = Column(Integer, nullable=True)
    risk_medium = Column(Integer, nullable=True)
    risk_low = Column(Integer, nullable=True)
    risk_info = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanMain", back_populates="zap", passive_deletes=True)


# ============================================================
# HARVESTER
# ============================================================

class HarvesterFinding(Base):
    """
    Ergebnisse von TheHarvester (OSINT).
    Enthält Rohdaten + Zählungen der gefundenen Infos.
    """
    __tablename__ = "harvester_findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), index=True, nullable=False)

    raw = Column(JSONB, nullable=True)

    domain = Column(String(256), nullable=True, index=True)
    status = Column(String(32), nullable=True)

    emails_count = Column(Integer, default=0)
    hosts_count = Column(Integer, default=0)
    ips_count = Column(Integer, default=0)
    subdomains_count = Column(Integer, default=0)
    urls_count = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)

    error = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanMain", back_populates="harvester_findings", passive_deletes=True)


# ============================================================
# CVE FINDINGS TABLE (for scan results) - ADD THIS
# ============================================================

class CVEFinding(Base):
    """
    Stores CVE scan results for each scan
    """
    __tablename__ = "cve_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), index=True, nullable=False)

    # CVE results as JSON
    raw = Column(JSONB, nullable=True)

    # Summary fields
    total_cves = Column(Integer, default=0)
    high_risk = Column(Integer, default=0)
    medium_risk = Column(Integer, default=0)
    low_risk = Column(Integer, default=0)

    status = Column(String(32), default="pending")
    error = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanMain", back_populates="cve_findings", passive_deletes=True)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "total_cves": self.total_cves,
            "high_risk": self.high_risk,
            "medium_risk": self.medium_risk,
            "low_risk": self.low_risk,
            "status": self.status,
            "error": self.error,
            "raw": self.raw or {},
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


# ============================================================
# CVE DATABASE TABLE
# ============================================================

class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    description = Column(Text)
    cvss_score = Column(Float)
    severity = Column(String)
    published_date = Column(DateTime)
    last_modified = Column(DateTime, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    epss_score = Column(Float, nullable=True)
    services = Column(JSONB, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'description': self.description,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'epss_score': self.epss_score,
            'services': self.services
        }


# ============================================================
# SCAN <-> CVE Link (pro Scan die gefundenen CVEs)
# ============================================================

class ScanCVE(Base):
    __tablename__ = "scan_cves"
    __table_args__ = (
        UniqueConstraint("scan_id", "cve_id", name="uq_scan_cve"),
    )

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan = relationship("ScanMain", foreign_keys=[scan_id])
    cve = relationship("CVE", foreign_keys=[cve_id])

    def __repr__(self):
        return f"<ScanCVE scan={self.scan_id} cve={self.cve_id}>"


# ============================================================
# SCAN DELTA (Vergleich zwischen zwei Scans)
# ============================================================

class ScanDelta(Base):
    __tablename__ = "scan_deltas"

    id = Column(Integer, primary_key=True)
    old_scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), nullable=False)
    new_scan_id = Column(Integer, ForeignKey("scan_main.id", ondelete="CASCADE"), nullable=False)
    tool = Column(String(50), nullable=False)
    added = Column(JSONB, nullable=True)
    removed = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    old_scan = relationship("ScanMain", foreign_keys=[old_scan_id])
    new_scan = relationship("ScanMain", foreign_keys=[new_scan_id])

    def __repr__(self):
        return f"<ScanDelta {self.tool} old={self.old_scan_id} new={self.new_scan_id}>"


# ============================================================
# BLACKLISTED TOKENS
# ============================================================

class BlacklistedToken(Base):
    """
    Speicherung von ungültigen JWTs (Logout).
    """
    __tablename__ = "blacklisted_tokens"

    id = Column(Integer, primary_key=True)
    token = Column(String(512), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"<BlacklistedToken {self.token}>"