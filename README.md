# 🛡️ Sentinel — Secret Leak Detector

Sentinel is a security-focused secret detection system designed to identify sensitive credentials accidentally committed to source-code repositories.

It scans files and staged Git changes for potentially exposed secrets such as API keys, access tokens, passwords, private keys, and other credential-like values.

The system combines pattern-based detection, entropy analysis, contextual signals, risk scoring, and configurable security rules to identify potentially dangerous secrets before they reach a repository.

---

## 🚀 Key Features

- 🔍 Secret detection in source-code files
- 🧪 Scanning of staged Git changes before commit
- 🔐 Detection of common credential types
- 📊 Risk scoring based on multiple detection signals
- 🧠 Entropy-based analysis for suspicious values
- 🎯 Context-aware detection
- 📝 Redacted previews of detected secrets
- 🔑 Secret fingerprinting without exposing the complete secret
- ⚙️ Custom YAML-based detection rules
- 🚦 Configurable blocking threshold
- 🌐 REST API powered by FastAPI
- 📚 Interactive Swagger API documentation
- 🗄️ Persistent scan and finding data
- 🐳 Docker support
- 🧪 Automated testing support

---

## 🏗️ Architecture

```text
                         ┌──────────────────────┐
                         │      Developer       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Sentinel CLI       │
                         │  scan --staged       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    Scanner Engine    │
                         ├──────────────────────┤
                         │ Pattern Detection    │
                         │ Entropy Analysis     │
                         │ Context Analysis     │
                         │ Risk Scoring         │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    Rule Engine       │
                         │    YAML Rules        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Findings / Results   │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
          ┌──────────────────┐             ┌──────────────────┐
          │   Sentinel API   │             │   Git Workflow   │
          │    FastAPI       │             │ Commit Blocking  │
          └────────┬─────────┘             └──────────────────┘
                   │
                   ▼
          ┌──────────────────┐
          │ Swagger / OpenAPI│
          │   Dashboard API  │
          └──────────────────┘
```

---

## 📁 Project Structure

```text
sentinel/
│
├── backend/
│   └── main.py
│
├── cli/
│   └── main.py
│
├── scanner/
│   ├── scan.py
│   └── rules.py
│
├── rules/
│   └── default_rules.yaml
│
├── database/
│
├── frontend/
│
├── tests/
│
├── demo_repo/
│   └── Test repository used for secret scanning
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── sentinel.config.yaml
├── README.md
└── .gitignore
```

---

## 🔎 Detection Approach

Sentinel does not rely on a single detection technique.

### 1. Pattern Matching

Detection rules identify known credential formats.

Examples include:

```text
AWS Access Key IDs
GitHub Personal Access Tokens
Private Keys
API Keys
Passwords
Authentication Tokens
```

---

### 2. Entropy Analysis

Random-looking strings often have higher entropy.

Sentinel uses normalized entropy as an additional signal when evaluating suspicious values.

This helps identify secrets that may not have a well-known fixed pattern.

---

### 3. Context Analysis

The surrounding code and file context can increase or decrease the confidence of a detection.

Examples of suspicious context:

```text
password =
secret =
api_key =
token =
authorization =
credentials =
```

---

### 4. Risk Scoring

Each detection receives a risk score based on multiple signals.

Conceptually:

```text
Risk Score =
    Pattern Weight
    + Entropy Signal
    + Context Signal
```

The resulting score is used to classify the finding and determine whether it should block a commit.

---

## 🚦 Severity Levels

Sentinel supports configurable severity thresholds.

Example configuration:

```yaml
severity_thresholds:
  critical: 85
  high: 65
  medium: 40
  low: 0
```

The blocking threshold can also be configured.

---

## 🛑 Git Staged Scanning

Sentinel can scan files that are currently staged in Git.

Example:

```powershell
python ..\cli\main.py scan --staged
```

If a blocking secret is detected, the commit can be prevented.

Example result:

```text
Scanned 1 file(s). 1 finding(s), 1 blocking.

Blocking secret detected.
Commit blocked.
```

If no blocking secret is found:

```text
Scanned 1 file(s). 0 finding(s), 0 blocking.

No blocking secrets found. Commit allowed.
```

---

## ⚙️ Configuration

Sentinel uses:

```text
sentinel.config.yaml
```

Example:

```yaml
severity_thresholds:
  critical: 85
  high: 65
  medium: 40
  low: 0

custom_rules_path: rules/

false_positive_exclusions: []

max_file_size: 2000000

scan_file_extensions:
  - .py
  - .js
  - .ts
  - .java
  - .env
  - .yml
  - .yaml
  - .json
  - .xml
  - .conf

demo_mode: true
```

Detection rules are stored in:

```text
rules/default_rules.yaml
```

Custom rules can be added without changing the scanner engine.

---

# 🌐 REST API

Sentinel exposes a REST API using FastAPI.

Start the API with:

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

The API will be available at:

```text
http://localhost:8000
```

Interactive API documentation:

```text
http://localhost:8000/docs
```

---

## 📡 Available API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/scan` | Create a scan |
| GET | `/api/v1/scans` | List scans |
| GET | `/api/v1/scans/{scan_id}` | Get scan details |
| GET | `/api/v1/findings` | List detected findings |
| GET | `/api/v1/findings/{finding_id}` | Get finding details |
| POST | `/api/v1/findings/{finding_id}/resolve` | Resolve a finding |
| GET | `/api/v1/repositories` | List repositories |
| GET | `/api/v1/repositories/{repo_id}` | Get repository details |
| GET | `/api/v1/metrics` | Get security metrics |
| POST | `/api/v1/hooks/commit-event` | Process commit events |

---

# 🛠️ Installation

## Requirements

- Python 3.10+
- Git
- pip
- Windows / Linux / macOS

---

## 1. Clone the Repository

```bash
git clone https://github.com/VEDHANTH04/Sentinel.git
cd Sentinel
```

---

## 2. Create a Virtual Environment

### Windows PowerShell

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 3. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

---

# ▶️ Running Sentinel

## Start the API

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

Then open:

```text
http://localhost:8000/docs
```

---

## Run a Staged Scan

From the demo repository:

```powershell
cd demo_repo
```

Stage a file:

```powershell
git add test-secret.txt
```

Run Sentinel:

```powershell
python ..\cli\main.py scan --staged
```

---

# 🧪 Testing

Run the test suite using:

```powershell
pytest
```

---

# 🔐 Security

Sentinel is designed to reduce accidental credential exposure.

Detected secrets should never be treated as safe merely because they are detected by a scanner.

If a real credential is accidentally committed:

1. Revoke the credential immediately.
2. Rotate the credential.
3. Remove it from the repository.
4. Check repository history for previous exposure.
5. Store the replacement credential in a secure secret manager or environment variable.

### ⚠️ Important

The credentials used in the demo repository are **fake test credentials**.

Never place real production credentials in this repository.

---

# 🐳 Docker

Sentinel also includes Docker configuration.

Build and run using:

```bash
docker compose up --build
```

---

# 🎯 Use Cases

Sentinel can be used for:

- Developer pre-commit security checks
- CI/CD secret scanning
- Repository security auditing
- Detecting accidentally committed credentials
- Security education and demonstrations
- Automated Git security workflows

---

# 🔮 Future Improvements

Potential future enhancements include:

- GitHub/GitLab integration
- Pull request scanning
- CI/CD pipeline integration
- More credential detection rules
- Advanced false-positive reduction
- Repository history scanning
- Secret rotation integrations
- Security dashboard
- Notifications and alerts
- Machine-learning assisted detection
- Enterprise secret-management integrations

---

# 🏆 Hackathon Project

Sentinel was developed as a security-focused solution for detecting and preventing accidental secret exposure in software repositories.

The project focuses on combining:

```text
Pattern Detection
        +
Entropy Analysis
        +
Context Analysis
        +
Risk Scoring
        +
Git Integration
        +
REST API
```

to provide a practical developer-oriented secret detection workflow.

---

## 📜 License

This project is intended for educational, development, and security research purposes.
