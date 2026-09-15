from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime


class FindingIn(BaseModel):
    file_path: str
    line_number: int
    secret_type: str
    severity: str
    confidence_percent: int
    risk_score: int
    detection_signals: dict
    redacted_preview: str
    fingerprint: str
    status: str = "open"


class ScanIn(BaseModel):
    repository_id: Optional[int] = None
    files_scanned: int
    total_findings: int
    blocking_findings: int
    findings: list[FindingIn] = []


class FindingOut(FindingIn):
    id: int
    scan_id: int
    first_detected: Optional[datetime]
    last_detected: Optional[datetime]

    class Config:
        from_attributes = True
