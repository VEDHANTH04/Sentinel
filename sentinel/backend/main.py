from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from . import models, schemas
from .database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SENTINEL API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DEMO_REPO_ID = 1


@app.on_event("startup")
def seed():
    db = next(get_db())
    if not db.query(models.Repository).first():
        db.add(models.Repository(id=DEMO_REPO_ID, name="sentinel-demo-repo",
                                  url="local://demo_repo", protected=True))
        db.commit()


@app.post("/api/v1/scan")
def create_scan(payload: schemas.ScanIn, db: Session = Depends(get_db)):
    repo_id = payload.repository_id or DEMO_REPO_ID
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in payload.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    scan = models.Scan(
        repository_id=repo_id, files_scanned=payload.files_scanned,
        total_findings=payload.total_findings, status="completed",
        critical_count=counts["Critical"], high_count=counts["High"],
        medium_count=counts["Medium"], low_count=counts["Low"],
    )
    db.add(scan)
    db.commit()

    for f in payload.findings:
        existing = db.query(models.Finding).filter_by(fingerprint=f.fingerprint,
                                                        file_path=f.file_path).first()
        if existing:
            existing.last_detected = func.now()
            existing.risk_score = f.risk_score
        else:
            db.add(models.Finding(scan_id=scan.id, repository_id=repo_id, **f.dict()))
    db.commit()
    return {"scan_id": scan.id, "blocking_findings": payload.blocking_findings}


@app.get("/api/v1/scans")
def list_scans(db: Session = Depends(get_db)):
    return db.query(models.Scan).order_by(models.Scan.id.desc()).all()


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


@app.get("/api/v1/findings", response_model=list[schemas.FindingOut])
def list_findings(status: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Finding)
    if status:
        q = q.filter(models.Finding.status == status)
    return q.order_by(models.Finding.id.desc()).all()


@app.get("/api/v1/findings/{finding_id}", response_model=schemas.FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(models.Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@app.post("/api/v1/findings/{finding_id}/resolve")
def resolve_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(models.Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    f.status = "resolved"
    db.commit()
    return {"id": finding_id, "status": "resolved"}


@app.get("/api/v1/repositories")
def list_repositories(db: Session = Depends(get_db)):
    return db.query(models.Repository).all()


@app.get("/api/v1/repositories/{repo_id}")
def get_repository(repo_id: int, db: Session = Depends(get_db)):
    r = db.get(models.Repository, repo_id)
    if not r:
        raise HTTPException(404, "repository not found")
    return r


@app.get("/api/v1/metrics")
def metrics(db: Session = Depends(get_db)):
    total_scans = db.query(models.Scan).count()
    total_findings = db.query(models.Finding).count()
    unresolved = db.query(models.Finding).filter(models.Finding.status == "open").count()
    blocked_commits = db.query(models.Commit).filter(models.Commit.blocked == True).count()  # noqa: E712
    by_type = dict(db.query(models.Finding.secret_type, func.count(models.Finding.id))
                   .group_by(models.Finding.secret_type).all())
    compliance_score = 100 if total_findings == 0 else max(0, 100 - unresolved * 5)
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "unresolved_findings": unresolved,
        "blocked_commits": blocked_commits,
        "secret_type_distribution": by_type,
        "compliance_score": compliance_score,
    }


@app.post("/api/v1/hooks/commit-event")
def commit_event(payload: dict, db: Session = Depends(get_db)):
    c = models.Commit(
        repository_id=payload.get("repository_id", DEMO_REPO_ID),
        commit_hash=payload.get("commit_hash", "unknown"),
        author=payload.get("author", "unknown"),
        message=payload.get("message", ""),
        blocked=payload.get("blocked", False),
    )
    db.add(c)
    db.commit()
    return {"id": c.id}
