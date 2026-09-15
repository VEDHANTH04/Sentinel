def compute_risk(pattern_weight: float, entropy_norm: float, context_mod: float) -> dict:
    """
    score = clamp( pattern_weight*0.5 + entropy_norm*100*0.3 + context_mod , 0, 100 )
    pattern_weight: 0-100 (rule's own weight)
    entropy_norm: 0-1
    context_mod: -30..+25
    """
    raw = pattern_weight * 0.5 + entropy_norm * 100 * 0.3 + context_mod
    score = max(0, min(100, round(raw)))
    if score >= 85:
        severity = "Critical"
    elif score >= 65:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    else:
        severity = "Low"
    return {"risk_score": score, "severity": severity, "confidence_percent": score}
