CREATE TABLE repositories (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT,
    protected BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER REFERENCES repositories(id),
    started_at TIMESTAMPTZ DEFAULT now(),
    finished_at TIMESTAMPTZ,
    files_scanned INTEGER DEFAULT 0,
    lines_scanned INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    status TEXT DEFAULT 'completed',
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0
);

CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    repository_id INTEGER REFERENCES repositories(id),
    file_path TEXT NOT NULL,
    line_number INTEGER,
    secret_type TEXT,
    severity TEXT,
    confidence_percent INTEGER,
    risk_score INTEGER,
    detection_signals JSONB,
    redacted_preview TEXT,
    fingerprint TEXT,
    status TEXT DEFAULT 'open',
    first_detected TIMESTAMPTZ DEFAULT now(),
    last_detected TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);

CREATE TABLE commits (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER REFERENCES repositories(id),
    commit_hash TEXT,
    author TEXT,
    message TEXT,
    blocked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE detection_rules (
    id SERIAL PRIMARY KEY,
    name TEXT,
    slug TEXT UNIQUE,
    pattern TEXT,
    metadata_json JSONB
);

CREATE TABLE developers (
    id SERIAL PRIMARY KEY,
    name TEXT,
    email TEXT,
    role TEXT
);

CREATE TABLE compliance_metrics (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER REFERENCES repositories(id),
    computed_at TIMESTAMPTZ DEFAULT now(),
    compliance_score INTEGER,
    unresolved_findings INTEGER,
    blocked_commits INTEGER
);
