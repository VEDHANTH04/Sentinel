#!/usr/bin/env python3
import argparse
import os
import stat
import sys
import json
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.scan import run_staged_scan  # noqa: E402

HOOK_TEMPLATE = """#!/usr/bin/env python3
# Installed by SENTINEL — do not edit directly, re-run `sentinel init` to update
import subprocess, sys
sys.exit(subprocess.call([sys.executable, "-m", "cli.main", "scan", "--staged"]))
"""


def cmd_init(args):
    hooks_dir = os.path.join(".git", "hooks")
    if not os.path.isdir(hooks_dir):
        print("Not a git repository (no .git/hooks found).")
        return 1
    hook_path = os.path.join(hooks_dir, "pre-commit")
    with open(hook_path, "w") as f:
        f.write(HOOK_TEMPLATE)
    st = os.stat(hook_path)
    os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(f"SENTINEL pre-commit hook installed at {hook_path}")
    return 0


def cmd_scan(args):
    result, blocking = run_staged_scan(config_path=args.config, rules_dir=args.rules_dir)
    print(f"\nScanned {result['files_scanned']} file(s). "
          f"{result['total_findings']} finding(s), {result['blocking_findings']} blocking.")

    if args.report_url:
        try:
            data = json.dumps(result).encode()
            req = urllib.request.Request(args.report_url, data=data,
                                          headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"Warning: could not report to backend ({e})")

    if blocking:
        print("Commit BLOCKED by SENTINEL. Fix or exclude the finding(s) above.")
        return 1
    print("No blocking secrets found. Commit allowed.")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Install pre-commit hook").set_defaults(func=cmd_init)

    p_scan = sub.add_parser("scan", help="Scan staged (or all) files")
    p_scan.add_argument("--staged", action="store_true", default=True)
    p_scan.add_argument("--config", default="sentinel.config.yaml")
    p_scan.add_argument("--rules-dir", default="rules")
    p_scan.add_argument("--report-url", default=os.environ.get("SENTINEL_API_URL"))
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
