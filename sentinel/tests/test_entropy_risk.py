import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.entropy import shannon_entropy, normalized_entropy
from scanner.risk import compute_risk
from scanner.redact import redacted_preview, fingerprint


def test_shannon_entropy_low_for_repeated_chars():
    assert shannon_entropy("aaaaaaaa") == 0.0

def test_shannon_entropy_high_for_random_string():
    assert shannon_entropy("aB3$kZ9!qP2") > 2.5

def test_normalized_entropy_bounds():
    assert 0.0 <= normalized_entropy("some_random_secret_value_123") <= 1.0

def test_risk_engine_critical_for_high_signals():
    r = compute_risk(pattern_weight=95, entropy_norm=0.9, context_mod=15)
    assert r["severity"] in ("Critical", "High")
    assert 0 <= r["risk_score"] <= 100

def test_risk_engine_low_for_placeholder_context():
    r = compute_risk(pattern_weight=55, entropy_norm=0.3, context_mod=-30)
    assert r["severity"] in ("Low", "Medium")

def test_redacted_preview_never_full_secret():
    secret = "ghp_realsecrettoken1234567890"
    preview = redacted_preview(secret)
    assert secret not in preview
    assert "*" in preview

def test_fingerprint_deterministic_no_raw_value():
    secret = "AKIAFAKEDEMOKEY12345"
    fp1 = fingerprint(secret)
    fp2 = fingerprint(secret)
    assert fp1 == fp2
    assert secret not in fp1
