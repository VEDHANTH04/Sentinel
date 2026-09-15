import subprocess
import os
import fnmatch
import yaml
import json
from .rules import load_rules
from .entropy import normalized_entropy
from .context import context_score, context_flags
from .risk import compute_risk
from .redact import redacted_preview, fingerprint

SUPPORTED_EXT = {".py", ".js", ".ts", ".java", ".env", ".yml", ".yaml", ".json", ".xml", ".conf"}
DEFAULT_IGNORE = ["node_modules/", ".git/", "dist/", "build/", "target/", "vendor/", "coverage/", "__pycache__/"]


def load_config(path="sentinel.config.yaml"):
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def is_binary(path: str, sample_size: int = 4096) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        return b"\x00" in chunk
    except OSError:
        return True


def is_ignored(path: str, ignore_paths) -> bool:
    return any(fnmatch.fnmatch(path, f"*{pat}*") or path.startswith(pat) for pat in ignore_paths)


def staged_files():
    out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                          capture_output=True, text=True)
    return [f for f in out.stdout.splitlines() if f]


def staged_content(path: str) -> str:
    out = subprocess.run(["git", "show", f":{path}"], capture_output=True, text=True)
    return out.stdout


def scan_files(file_list, config, rules):
    ignore_paths = config.get("ignore_paths", []) + DEFAULT_IGNORE
    max_size = config.get("max_file_size", 2_000_000)
    findings = []

    for path in file_list:
        if is_ignored(path, ignore_paths):
            continue
        ext = os.path.splitext(path)[1]
        if ext not in SUPPORTED_EXT:
            continue
        if not os.path.exists(path):
            continue
        if os.path.getsize(path) > max_size:
            continue
        if is_binary(path):
            continue

        try:
            content = staged_content(path) or open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for rule in rules:
                for m in rule.match(line):
                    secret_val = m.group(0)
                    ent = normalized_entropy(secret_val)
                    ctx_mod = context_score(path, line)
                    risk = compute_risk(rule.weight, ent, ctx_mod)
                    findings.append({
                        "file_path": path,
                        "line_number": lineno,
                        "secret_type": rule.secret_type,
                        "rule_id": rule.id,
                        "severity": risk["severity"],
                        "confidence_percent": risk["confidence_percent"],
                        "risk_score": risk["risk_score"],
                        "detection_signals": {
                            "pattern_weight": rule.weight,
                            "entropy_norm": round(ent, 3),
                            "context": context_flags(path, line),
                        },
                        "redacted_preview": redacted_preview(secret_val),
                        "fingerprint": fingerprint(secret_val),
                        "status": "open",
                    })
    return findings


def print_finding_banner(finding):
    print("=" * 60)
    print("SENTINEL BLOCKED COMMIT — potential secret detected")
    print(f"File:       {finding['file_path']}:{finding['line_number']}")
    print(f"Type:       {finding['secret_type']}")
    print(f"Severity:   {finding['severity']}")
    print(f"Confidence: {finding['confidence_percent']}%")
    print(f"SENTINEL Risk Score: {finding['risk_score']}/100")
    print(f"Preview:    {finding['redacted_preview']}")
    print(f"Fingerprint:{finding['fingerprint'][:16]}...")
    print("=" * 60)


def run_staged_scan(config_path="sentinel.config.yaml", rules_dir="rules"):
    config = load_config(config_path)
    rules = load_rules(rules_dir)
    files = staged_files()
    findings = scan_files(files, config, rules)
    threshold = config.get("blocking_threshold", 75)
    blocking = [f for f in findings if f["risk_score"] >= threshold]

    for f in findings:
        print_finding_banner(f)

    result = {
        "files_scanned": len(files),
        "total_findings": len(findings),
        "blocking_findings": len(blocking),
        "findings": findings,
    }
    return result, blocking
