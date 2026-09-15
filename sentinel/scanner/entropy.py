import math
from collections import Counter

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def normalized_entropy(s: str) -> float:
    """Map entropy to 0-1 using max possible entropy for alphabet size present."""
    if not s:
        return 0.0
    ent = shannon_entropy(s)
    alphabet_size = len(set(s))
    max_ent = math.log2(alphabet_size) if alphabet_size > 1 else 1.0
    return min(1.0, ent / max_ent) if max_ent else 0.0
