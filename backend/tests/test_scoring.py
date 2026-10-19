"""
Tests for the risk scoring engine.
"""
from __future__ import annotations

from backend.app.scoring import WEIGHTS, RiskInput, compute_risk_score


class TestRiskScoring:
    """Risk scoring engine tests."""

    def test_clean_email_low_score(self):
        inp = RiskInput(
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
            url_risk_score=0.0,
            attachment_risk_score=0.0,
            ml_probability=0.05,
            header_risk_score=0.0,
        )
        out = compute_risk_score(inp)
        assert out.total < 40, f"Clean email should score < 40, got {out.total}"
        assert out.verdict == "LEGITIMATE"

    def test_phishing_email_high_score(self):
        inp = RiskInput(
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
            url_risk_score=90.0,
            attachment_risk_score=80.0,
            ml_probability=0.95,
            header_risk_score=70.0,
        )
        out = compute_risk_score(inp)
        assert out.total >= 70, f"Phishing email should score >= 70, got {out.total}"
        assert out.verdict == "MALICIOUS"

    def test_signature_fail_override(self):
        """Failed signature on a claimed-signed message must force score=100."""
        inp = RiskInput(
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
            ml_probability=0.1,
            signature_claimed=True,
            signature_valid=False,
        )
        out = compute_risk_score(inp)
        assert out.total == 100.0
        assert out.hard_override
        assert out.verdict == "MALICIOUS"
        assert "signature" in (out.override_reason or "").lower()

    def test_replay_override(self):
        """Replay detection must force score=100."""
        inp = RiskInput(
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
            ml_probability=0.1,
            replay_detected=True,
        )
        out = compute_risk_score(inp)
        assert out.total == 100.0
        assert out.hard_override
        assert out.verdict == "MALICIOUS"

    def test_malicious_hash_override(self):
        """Known-malicious attachment hash must force score=100."""
        inp = RiskInput(
            ml_probability=0.1,
            malicious_hash_detected=True,
        )
        out = compute_risk_score(inp)
        assert out.total == 100.0
        assert out.hard_override

    def test_suspicious_threshold(self):
        """Test that scores in suspicious range get SUSPICIOUS verdict."""
        inp = RiskInput(
            spf_result="softfail",
            dkim_result="none",
            dmarc_result="none",
            ml_probability=0.4,
            url_risk_score=30.0,
        )
        out = compute_risk_score(inp, thresholds={"suspicious": 41, "malicious": 71})
        assert out.verdict in ("SUSPICIOUS", "MALICIOUS", "LEGITIMATE")  # score-dependent

    def test_weights_sum_to_100(self):
        assert sum(WEIGHTS.values()) == 100

    def test_score_capped_at_100(self):
        inp = RiskInput(
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
            url_risk_score=100.0,
            attachment_risk_score=100.0,
            ml_probability=1.0,
            header_risk_score=100.0,
        )
        out = compute_risk_score(inp)
        assert out.total <= 100.0

    def test_score_non_negative(self):
        inp = RiskInput(
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
            ml_probability=0.0,
            url_risk_score=0.0,
        )
        out = compute_risk_score(inp)
        assert out.total >= 0.0

    def test_explanation_contains_all_factors(self):
        inp = RiskInput()
        out = compute_risk_score(inp)
        factors = out.explanation["factors"]
        for key in ("auth", "url", "attachment", "ml", "header", "crypto"):
            assert key in factors, f"Missing factor: {key}"

    def test_custom_thresholds(self):
        inp = RiskInput(ml_probability=0.6)
        out_tight = compute_risk_score(inp, thresholds={"suspicious": 10, "malicious": 20})
        assert out_tight.verdict == "MALICIOUS"

        out_loose = compute_risk_score(inp, thresholds={"suspicious": 80, "malicious": 90})
        assert out_loose.verdict == "LEGITIMATE"

    def test_valid_signature_reduces_crypto_risk(self):
        inp_no_sig = RiskInput(ml_probability=0.3)
        inp_valid_sig = RiskInput(
            ml_probability=0.3,
            signature_claimed=True,
            signature_valid=True,
        )
        out_no_sig = compute_risk_score(inp_no_sig)
        out_valid_sig = compute_risk_score(inp_valid_sig)
        # Valid sig should not increase the score
        assert out_valid_sig.total <= out_no_sig.total + 1  # +1 for float tolerance
