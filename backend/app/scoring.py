"""
PhishShield – Risk Scoring Engine.

Combines results from all pipeline stages into a weighted 0-100 risk score.
Applies hard overrides for critical security failures.
"""
from __future__ import annotations

from dataclasses import dataclass

# ─── Factor Weights ───────────────────────────────────────────────────────────
# Must sum to 100
WEIGHTS = {
    "auth": 25,        # SPF + DKIM + DMARC results
    "url": 20,         # URL analysis findings
    "attachment": 15,  # Attachment analysis
    "ml": 25,          # ML phishing probability
    "header": 10,      # Spoofing / header anomalies
    "crypto": 5,       # Signature / HMAC / hash checks
}

assert sum(WEIGHTS.values()) == 100, "Risk weights must sum to 100"


@dataclass
class RiskInput:
    """All inputs to the risk scoring engine."""

    # Auth scores (each 0-1: 0=fail, 0.5=partial, 1=pass)
    spf_result: str = "none"       # 'pass', 'fail', 'softfail', 'neutral', 'none', 'error'
    dkim_result: str = "none"
    dmarc_result: str = "none"

    # URL analysis (0-100 raw score)
    url_risk_score: float = 0.0

    # Attachment (0-100 raw score)
    attachment_risk_score: float = 0.0

    # ML (0-1 phishing probability)
    ml_probability: float = 0.0

    # Header / spoofing (0-100 raw score)
    header_risk_score: float = 0.0

    # Crypto
    signature_claimed: bool = False    # email claims to be signed
    signature_valid: bool | None = None
    hmac_claimed: bool = False
    hmac_valid: bool | None = None
    hash_match: bool | None = None
    replay_detected: bool = False

    # Known-malicious attachment hash
    malicious_hash_detected: bool = False


@dataclass
class RiskOutput:
    """Risk scoring result."""
    total: float          # 0-100
    auth_score: float
    url_score: float
    attachment_score: float
    ml_score: float
    header_score: float
    crypto_score: float
    hard_override: bool
    override_reason: str | None
    verdict: str          # 'LEGITIMATE', 'SUSPICIOUS', 'MALICIOUS'
    explanation: dict


def _auth_factor(inp: RiskInput) -> float:
    """Convert auth results to a 0-100 risk contribution."""
    spf_map = {"pass": 0, "none": 30, "neutral": 40, "softfail": 60, "fail": 100, "error": 50}
    dkim_map = {"pass": 0, "none": 40, "fail": 100, "error": 50}
    dmarc_map = {"pass": 0, "none": 30, "fail": 100, "error": 50}

    spf = spf_map.get(inp.spf_result.lower(), 50)
    dkim = dkim_map.get(inp.dkim_result.lower(), 50)
    dmarc = dmarc_map.get(inp.dmarc_result.lower(), 50)
    return (spf + dkim + dmarc) / 3.0


def _crypto_factor(inp: RiskInput) -> float:
    """Convert crypto verification results to 0-100 risk."""
    score = 0.0

    # Signature check
    if inp.signature_claimed:
        if inp.signature_valid is False:
            score = 100.0  # Claimed but invalid → very suspicious
        elif inp.signature_valid is True:
            score = 0.0
        else:
            score = 20.0   # Claimed but not verified
    else:
        score = 10.0  # No signature (neutral)

    # HMAC check
    if inp.hmac_claimed:
        if inp.hmac_valid is False:
            score = max(score, 100.0)
        elif inp.hmac_valid is True:
            score = min(score, 0.0)

    # Hash check
    if inp.hash_match is False:
        score = max(score, 80.0)

    # Replay
    if inp.replay_detected:
        score = 100.0

    return min(score, 100.0)


def compute_risk_score(inp: RiskInput, thresholds: dict | None = None) -> RiskOutput:
    """
    Compute a weighted 0-100 risk score from all pipeline factors.

    Hard overrides force score to 100 (MALICIOUS) for:
    - Failed signature on a claimed-signed message
    - Replay attack detected
    - Known-malicious attachment hash

    Args:
        inp:        RiskInput with all factor scores.
        thresholds: dict with 'suspicious' and 'malicious' int keys.

    Returns:
        RiskOutput with score, breakdown, verdict, and explanation.
    """
    if thresholds is None:
        thresholds = {"suspicious": 41, "malicious": 71}

    # ── Compute individual factor scores (each 0-100) ─────────────────────────
    auth_raw = _auth_factor(inp)
    url_raw = min(inp.url_risk_score, 100.0)
    attach_raw = min(inp.attachment_risk_score, 100.0)
    ml_raw = inp.ml_probability * 100.0
    header_raw = min(inp.header_risk_score, 100.0)
    crypto_raw = _crypto_factor(inp)

    # ── Weighted total ─────────────────────────────────────────────────────────
    total = (
        auth_raw * WEIGHTS["auth"] / 100.0
        + url_raw * WEIGHTS["url"] / 100.0
        + attach_raw * WEIGHTS["attachment"] / 100.0
        + ml_raw * WEIGHTS["ml"] / 100.0
        + header_raw * WEIGHTS["header"] / 100.0
        + crypto_raw * WEIGHTS["crypto"] / 100.0
    )

    # ── Hard overrides ─────────────────────────────────────────────────────────
    override = False
    override_reason: str | None = None

    if inp.signature_claimed and inp.signature_valid is False:
        total = 100.0
        override = True
        override_reason = "Digital signature verification failed on a signed message"

    if inp.replay_detected:
        total = 100.0
        override = True
        override_reason = "Replay attack detected: nonce already used"

    if inp.malicious_hash_detected:
        total = 100.0
        override = True
        override_reason = "Known-malicious attachment hash detected"

    # Correlation rule: Failed SPF/DMARC combined with sender/header spoofing is high-risk
    if (inp.spf_result in ("fail", "softfail") or inp.dmarc_result == "fail") and inp.header_risk_score >= 30.0:
        total = max(total, 65.0)

    total = round(min(total, 100.0), 2)

    # ── Verdict ───────────────────────────────────────────────────────────────
    if total >= thresholds["malicious"]:
        verdict = "MALICIOUS"
    elif total >= thresholds["suspicious"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    # ── Explanation ───────────────────────────────────────────────────────────
    explanation = {
        "factors": {
            "auth": {
                "score": round(auth_raw, 1),
                "weight": WEIGHTS["auth"],
                "contribution": round(auth_raw * WEIGHTS["auth"] / 100.0, 2),
                "details": {
                    "spf": inp.spf_result,
                    "dkim": inp.dkim_result,
                    "dmarc": inp.dmarc_result,
                },
            },
            "url": {
                "score": round(url_raw, 1),
                "weight": WEIGHTS["url"],
                "contribution": round(url_raw * WEIGHTS["url"] / 100.0, 2),
            },
            "attachment": {
                "score": round(attach_raw, 1),
                "weight": WEIGHTS["attachment"],
                "contribution": round(attach_raw * WEIGHTS["attachment"] / 100.0, 2),
            },
            "ml": {
                "score": round(ml_raw, 1),
                "weight": WEIGHTS["ml"],
                "contribution": round(ml_raw * WEIGHTS["ml"] / 100.0, 2),
                "probability": round(inp.ml_probability, 4),
            },
            "header": {
                "score": round(header_raw, 1),
                "weight": WEIGHTS["header"],
                "contribution": round(header_raw * WEIGHTS["header"] / 100.0, 2),
            },
            "crypto": {
                "score": round(crypto_raw, 1),
                "weight": WEIGHTS["crypto"],
                "contribution": round(crypto_raw * WEIGHTS["crypto"] / 100.0, 2),
                "details": {
                    "signature_claimed": inp.signature_claimed,
                    "signature_valid": inp.signature_valid,
                    "replay_detected": inp.replay_detected,
                },
            },
        },
        "hard_override": override,
        "override_reason": override_reason,
        "verdict": verdict,
        "total_risk_score": total,
    }

    return RiskOutput(
        total=total,
        auth_score=round(auth_raw * WEIGHTS["auth"] / 100.0, 2),
        url_score=round(url_raw * WEIGHTS["url"] / 100.0, 2),
        attachment_score=round(attach_raw * WEIGHTS["attachment"] / 100.0, 2),
        ml_score=round(ml_raw * WEIGHTS["ml"] / 100.0, 2),
        header_score=round(header_raw * WEIGHTS["header"] / 100.0, 2),
        crypto_score=round(crypto_raw * WEIGHTS["crypto"] / 100.0, 2),
        hard_override=override,
        override_reason=override_reason,
        verdict=verdict,
        explanation=explanation,
    )
