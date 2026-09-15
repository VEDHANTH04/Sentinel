import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.scan import scan_files, load_config
from scanner.rules import load_rules

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")

def test_true_positive_aws_key_blocks(tmp_path, monkeypatch):
    # use a relative path with no "test" substring — pytest's tmp_path itself
    # contains the test name, which would otherwise trigger the test-path
    # context heuristic and unfairly lower the score.
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "conf.env"
    f.write_text("AWS_ACCESS_KEY_ID=AKIAFAKEDEMOKEY12345\n")
    rules = load_rules(RULES_DIR)
    config = {"blocking_threshold": 75, "max_file_size": 2_000_000}
    findings = scan_files(["conf.env"], config, rules)
    assert any(x["risk_score"] >= 75 for x in findings)

def test_false_positive_placeholder_does_not_block(tmp_path):
    f = tmp_path / "example.py"
    f.write_text('api_key = "changeme_placeholder_value"\n')
    rules = load_rules(RULES_DIR)
    config = {"blocking_threshold": 75, "max_file_size": 2_000_000}
    findings = scan_files([str(f)], config, rules)
    blocking = [x for x in findings if x["risk_score"] >= 75]
    assert len(blocking) == 0

def test_binary_files_skipped(tmp_path):
    f = tmp_path / "image.py"
    f.write_bytes(b"\x00\x01\x02AKIAFAKEDEMO12345X")
    from scanner.scan import is_binary
    assert is_binary(str(f)) is True

def test_ignored_paths_skip_node_modules(tmp_path):
    from scanner.scan import is_ignored
    assert is_ignored("node_modules/pkg/index.js", ["node_modules/"]) is True
    assert is_ignored("src/app.py", ["node_modules/"]) is False
