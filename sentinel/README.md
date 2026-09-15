# SENTINEL — Secret Leak Detection System

## Layout
```
scanner/   core: rules.py, entropy.py, context.py, risk.py, redact.py, scan.py
cli/       sentinel CLI (init, scan)
rules/     YAML detection rules
backend/   FastAPI + SQLAlchemy (Postgres, sqlite fallback for demo_mode)
database/  raw SQL migration
frontend/  static dashboard (Chart.js + Three.js w/ reduced-motion fallback)
demo_repo/ fake-credential demo files
tests/     pytest unit + integration tests
```

## Quickstart (local demo, no Docker)
```bash
pip install -r requirements.txt

# 1. Backend (sqlite fallback auto-used if DATABASE_URL unset)
uvicorn backend.main:app --reload --port 8000 &

# 2. Frontend — just open frontend/index.html in a browser
python -m http.server 5500 --directory frontend &

# 3. Install pre-commit hook into demo repo
cd demo_repo && git init -q
python ../cli/main.py init

# 4. Trigger a blocked commit (fake AWS key + github token present)
git add .
export SENTINEL_API_URL=http://localhost:8000/api/v1/scan
python ../cli/main.py scan --staged   # exits 1, prints redacted banner, blocks commit
```

## Quickstart (Docker Postgres)
```bash
docker compose up -d db
psql postgresql://sentinel:sentinel@localhost:5432/sentinel -f database/migration_001_init.sql
export DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinel
uvicorn backend.main:app --port 8000
```

## Run tests
```bash
pytest tests/ -v
```

## Acceptance checklist
- [x] Pre-commit hook via `sentinel init` → `.git/hooks/pre-commit`
- [x] Staged-file scanning via `git diff --cached`
- [x] Extensions: .py .js .ts .java .env .yml .yaml .json .xml .conf
- [x] Binary detection (null-byte scan) → skipped
- [x] Ignore rules: node_modules/, .git/, dist/, build/, target/, vendor/, coverage/, __pycache__/
- [x] Regex rule engine (rules/default_rules.yaml, extend via custom_rules_path)
- [x] Shannon entropy signal (scanner/entropy.py)
- [x] Context heuristics (scanner/context.py): var names, env files, placeholders, test/docs paths
- [x] Risk engine 0–100 + Low/Medium/High/Critical (scanner/risk.py), labeled "SENTINEL Risk Score"
- [x] Terminal redaction — masked preview only, never full secret
- [x] Commit blocked when risk_score >= blocking_threshold (exit code 1)
- [x] Dashboard: scans, findings, blocked commits, compliance %, secret-type distribution, history, unresolved
- [x] Demo repo with fake credentials only (demo_repo/)
- [x] Postgres schema + sqlite fallback for demo_mode
- [x] Unit + integration tests (tests/) covering true/false positives, redaction, risk, binary/ignore filtering
