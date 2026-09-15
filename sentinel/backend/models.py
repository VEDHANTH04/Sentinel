from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Text
from sqlalchemy.sql import func
from .database import Base


class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    url = Column(String)
    protected = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    started_at = Column(DateTime, server_default=func.now())
    finished_at = Column(DateTime)
    files_scanned = Column(Integer, default=0)
    lines_scanned = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)
    status = Column(String, default="completed")
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    file_path = Column(String, nullable=False)
    line_number = Column(Integer)
    secret_type = Column(String)
    severity = Column(String)
    confidence_percent = Column(Integer)
    risk_score = Column(Integer)
    detection_signals = Column(JSON)
    redacted_preview = Column(String)   # never store raw secret
    fingerprint = Column(String, index=True)
    status = Column(String, default="open")
    first_detected = Column(DateTime, server_default=func.now())
    last_detected = Column(DateTime, server_default=func.now())


class Commit(Base):
    __tablename__ = "commits"
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    commit_hash = Column(String)
    author = Column(String)
    message = Column(Text)
    blocked = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    slug = Column(String, unique=True)
    pattern = Column(String)
    metadata_json = Column(JSON)


class ComplianceMetric(Base):
    __tablename__ = "compliance_metrics"
    id = Column(Integer, primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    computed_at = Column(DateTime, server_default=func.now())
    compliance_score = Column(Integer)
    unresolved_findings = Column(Integer)
    blocked_commits = Column(Integer)
