import re

PLACEHOLDER_TOKENS = re.compile(r"(example|placeholder|xxxx|dummy|changeme|<.*?>|\$\{.*?\})", re.I)
SENSITIVE_VAR_NAMES = re.compile(r"(secret|token|api[_-]?key|password|passwd|pwd|credential|private[_-]?key)", re.I)
TEST_PATH = re.compile(r"(test|spec|__tests__|fixtures?|mocks?)", re.I)
DOCS_PATH = re.compile(r"(docs?/|readme|\.md$|\.rst$)", re.I)
ENV_FILE = re.compile(r"\.env")

def context_score(file_path: str, line: str) -> float:
    """Returns a modifier in range [-30, +25] applied to base score."""
    score = 0.0
    if SENSITIVE_VAR_NAMES.search(line):
        score += 15
    if ENV_FILE.search(file_path):
        score += 10
    if PLACEHOLDER_TOKENS.search(line):
        score -= 30
    if TEST_PATH.search(file_path):
        score -= 15
    if DOCS_PATH.search(file_path):
        score -= 20
    return score

def context_flags(file_path: str, line: str) -> dict:
    return {
        "sensitive_var_name": bool(SENSITIVE_VAR_NAMES.search(line)),
        "env_file": bool(ENV_FILE.search(file_path)),
        "placeholder": bool(PLACEHOLDER_TOKENS.search(line)),
        "test_path": bool(TEST_PATH.search(file_path)),
        "docs_path": bool(DOCS_PATH.search(file_path)),
    }
