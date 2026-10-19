"""
Tests for the email analysis pipeline (end-to-end integration tests).
"""
from __future__ import annotations

import base64

# conftest sets up env + DB

SIMPLE_EMAIL = b"""From: sender@example.com
To: recipient@company.com
Subject: Test email
Date: Mon, 14 Oct 2024 12:00:00 +0000
Message-ID: <test123@example.com>

This is a test email body with no malicious content.
"""

PHISHING_EMAIL = b"""From: "PayPal Security" <security@paypa1-secure.tk>
To: victim@company.com
Subject: URGENT: Your account has been compromised
Date: Mon, 14 Oct 2024 12:00:00 +0000
Message-ID: <phish456@paypa1.tk>

Dear Customer,

URGENT: Your PayPal account has been compromised!
Click here immediately to verify: http://paypa1-secure.tk/verify?token=abc123

Your account will be permanently suspended in 24 hours if you do not act NOW!

PayPal Security Team
"""

SIGNED_TAMPERED_EMAIL = b"""From: legit@trusted.com
To: recipient@company.com
Subject: Signed and tampered
Date: Mon, 14 Oct 2024 12:00:00 +0000
Message-ID: <tampered@trusted.com>
X-PhishShield-Signature: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA key_id=99999
X-PhishShield-Nonce: test-nonce-12345
X-PhishShield-Timestamp: 2024-10-14T12:00:00+00:00

This email was tampered - the signature is invalid.
"""


class TestEmailParser:
    """Email parsing unit tests."""

    def test_parse_simple_email(self):
        from backend.analysis.email_parser import parse_email
        parsed = parse_email(SIMPLE_EMAIL)
        assert parsed.sender_address == "sender@example.com"
        assert "recipient@company.com" in parsed.to_addresses
        assert parsed.subject == "Test email"
        assert "test123@example.com" in parsed.message_id
        assert parsed.body_text is not None
        assert "test email body" in parsed.body_text

    def test_parse_computes_hash(self):
        from backend.analysis.email_parser import parse_email
        from backend.crypto.hashing import sha256_hash
        parsed = parse_email(SIMPLE_EMAIL)
        expected_hash = sha256_hash(SIMPLE_EMAIL)
        assert parsed.sha256_hash == expected_hash

    def test_parse_phishing_email(self):
        from backend.analysis.email_parser import parse_email
        parsed = parse_email(PHISHING_EMAIL)
        assert "paypa1-secure.tk" in parsed.sender_address
        assert "compromised" in parsed.subject.lower()


class TestURLAnalysis:
    """URL analysis tests."""

    def test_detects_ip_url(self):
        from backend.analysis.url_analyzer import analyze_urls
        result = analyze_urls("Click here: http://192.168.1.1/login", "")
        ip_urls = [u for u in result.urls_found if u.is_ip_address]
        assert len(ip_urls) >= 1

    def test_detects_url_shortener(self):
        from backend.analysis.url_analyzer import analyze_urls
        result = analyze_urls("Visit http://bit.ly/abc123 for details", "")
        shorteners = [u for u in result.urls_found if u.uses_url_shortener]
        assert len(shorteners) >= 1

    def test_detects_suspicious_tld(self):
        from backend.analysis.url_analyzer import analyze_urls
        result = analyze_urls("Go to http://evil.tk/page", "")
        suspicious = [u for u in result.urls_found if u.suspicious_tld]
        assert len(suspicious) >= 1

    def test_clean_url_low_risk(self):
        from backend.analysis.url_analyzer import analyze_urls
        result = analyze_urls("Visit https://www.google.com for info", "")
        assert result.risk_score < 50

    def test_risk_score_between_0_and_100(self):
        from backend.analysis.url_analyzer import analyze_urls
        result = analyze_urls(
            "http://bit.ly/x http://192.0.0.1/login http://paypa1.tk/verify", ""
        )
        assert 0 <= result.risk_score <= 100


class TestSpoofingDetection:
    """Spoofing detection tests."""

    def test_detects_reply_to_mismatch(self):
        from backend.analysis.email_parser import parse_email
        from backend.analysis.spoofing import detect_spoofing

        email = b"From: legit@company.com\r\nReply-To: attacker@evil.com\r\nSubject: Hi\r\n\r\nBody"
        parsed = parse_email(email)
        result = detect_spoofing(parsed)
        assert result.reply_to_mismatch

    def test_detects_lookalike_domain(self):
        from backend.analysis.spoofing import detect_lookalike_domain
        # paypa1.com is 1 edit away from paypal.com
        result = detect_lookalike_domain("paypa1.com")
        assert result["is_lookalike"]

    def test_legitimate_domain_not_flagged(self):
        from backend.analysis.spoofing import detect_lookalike_domain
        result = detect_lookalike_domain("mycompanyinternaltools.com")
        assert not result["is_lookalike"]


class TestAPIIntegration:
    """Integration tests against the live FastAPI app."""

    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_login_success(self, client):
        resp = client.post("/auth/login", json={
            "email": "admin@example.com",
            "password": "TestPassword123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["role"] == "admin"

    def test_login_wrong_password(self, client):
        resp = client.post("/auth/login", json={
            "email": "admin@example.com",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401

    def test_protected_endpoint_no_token(self, client):
        resp = client.get("/emails/")
        assert resp.status_code == 401

    def test_list_emails_authenticated(self, client, auth_headers):
        resp = client.get("/emails/", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_dashboard_stats(self, client, auth_headers):
        resp = client.get("/dashboard/stats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_emails" in data
        assert "legitimate" in data

    def test_analyze_email(self, client, auth_headers):
        raw_b64 = base64.b64encode(SIMPLE_EMAIL).decode()
        resp = client.post(
            "/emails/analyze",
            json={"raw_email_b64": raw_b64, "source_ip": "127.0.0.1"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "verdict" in data
        assert "risk_score" in data

    def test_keys_endpoint(self, client, auth_headers):
        resp = client.get("/keys/", headers=auth_headers)
        assert resp.status_code == 200

    def test_generate_ed25519_key(self, client, auth_headers):
        resp = client.post(
            "/keys/generate",
            json={"label": "test-key", "domain": "test.com", "key_type": "ED25519"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"]["key_type"] == "ED25519"
        assert data["private_key_pem"] is not None
        assert "BEGIN PRIVATE KEY" in data["private_key_pem"]

    def test_logs_endpoint(self, client, auth_headers):
        resp = client.get("/logs/", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_settings_thresholds(self, client, auth_headers):
        resp = client.get("/settings/thresholds", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "threshold_suspicious" in data
        assert "threshold_malicious" in data
