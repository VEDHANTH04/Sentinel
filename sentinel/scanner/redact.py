import hmac
import hashlib
import os

SERVER_KEY = os.environ.get("SENTINEL_HMAC_KEY", "dev-only-change-me").encode()

def redacted_preview(secret: str) -> str:
    """Show only first 3 and last 2 chars, mask the rest. Never log full value."""
    if len(secret) <= 6:
        return "*" * len(secret)
    return f"{secret[:3]}{'*' * (len(secret) - 5)}{secret[-2:]}"

def fingerprint(secret: str) -> str:
    """HMAC-SHA256 fingerprint using server-side key. Raw secret never stored."""
    return hmac.new(SERVER_KEY, secret.encode(), hashlib.sha256).hexdigest()
