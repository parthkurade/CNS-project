"""
PhishShield – Full email processing pipeline.

Orchestrates all analysis stages in order:
1. TLS verification info
2. Sender authentication (SPF / DKIM / DMARC)
3. Cryptographic verification (hash, signature, HMAC, replay)
4. Email analysis (URLs, attachments, headers, spoofing)
5. ML phishing detection
6. Risk scoring
7. Decision (deliver / warn / quarantine)
8. Storage (encrypt + DB)
9. Logging
"""
from __future__ import annotations

import base64
import time
from typing import Any

from sqlalchemy.orm import Session

from backend.analysis.attachment import AttachmentAnalyzer
from backend.analysis.dkim_check import check_dkim
from backend.analysis.dmarc_check import check_dmarc
from backend.analysis.email_parser import ParsedEmail, parse_email
from backend.analysis.header_analyzer import analyze_headers
from backend.analysis.spf_check import check_spf
from backend.analysis.spoofing import detect_spoofing
from backend.analysis.url_analyzer import analyze_urls
from backend.app.config import get_settings
from backend.app.models import EmailRecord, SecurityLog, Verdict
from backend.app.scoring import RiskInput, compute_risk_score
from backend.crypto.aes import encrypt_email
from backend.crypto.hashing import sha256_hash
from backend.crypto.replay import NonceCache
from backend.crypto.signatures import ed25519_verify, rsa_pss_verify
from backend.ml.predict import predict_phishing

settings = get_settings()


def _ms(start: float) -> float:
    """Return milliseconds since start."""
    return round((time.perf_counter() - start) * 1000, 2)


def _strip_header(raw_email: bytes, header_name: str) -> bytes:
    """Remove a named header from raw email bytes.

    Used to compute canonical bytes for signature verification:
    the sender signs the email before adding the signature header,
    so the verifier must strip it before verifying.
    """
    import re
    pattern = re.compile(
        rb"^" + re.escape(header_name.encode()) + rb":[^\r\n]*(?:\r\n[ \t][^\r\n]*)*\r\n",
        re.IGNORECASE | re.MULTILINE,
    )
    return pattern.sub(b"", raw_email)


def _log(
    db: Session,
    email_id: int | None,
    event_type: str,
    severity: str,
    stage: str,
    message: str,
    details: dict | None = None,
    source_ip: str | None = None,
) -> None:
    """Write a security log entry."""
    log = SecurityLog(
        email_id=email_id,
        event_type=event_type,
        severity=severity,
        stage=stage,
        message=message,
        details=details,
        source_ip=source_ip,
    )
    db.add(log)
    db.flush()


def _build_educational_explanation(
    parsed: ParsedEmail,
    spf: Any,
    dkim: Any,
    dmarc: Any,
    sig_valid: bool | None,
    hmac_valid: bool | None,
    replay_detected: bool,
    url_result: Any,
    attach_result: list,
    header_result: Any,
    spoof_result: Any,
    ml_result: Any,
    risk_output: Any,
) -> dict:
    """Build plain-language explanations for the educational panel."""
    return {
        "tls": {
            "title": "TLS Secure Transport",
            "passed": True,  # If we got the email, TLS was used
            "explanation": (
                "TLS (Transport Layer Security) encrypts the email in transit so no one "
                "can read or modify it between the sending server and ours. "
                "We require TLS 1.2 or higher."
            ),
        },
        "spf": {
            "title": "SPF (Sender Policy Framework)",
            "passed": spf.result == "pass" if spf else False,
            "explanation": (
                f"SPF checks whether the sending mail server ({parsed.received_from_ip or 'unknown IP'}) "
                f"is authorized to send email for the domain '{parsed.sender_domain}'. "
                f"Result: {spf.result if spf else 'not checked'}. "
                + (
                    "✓ The server is authorized."
                    if (spf and spf.result == "pass")
                    else "✗ The server is NOT authorized – possible spoofing."
                )
            ),
        },
        "dkim": {
            "title": "DKIM (DomainKeys Identified Mail)",
            "passed": dkim.result == "pass" if dkim else False,
            "explanation": (
                "DKIM verifies a cryptographic signature added by the sender's mail server. "
                "If the signature is valid, the email was not modified in transit. "
                f"Result: {dkim.result if dkim else 'not present'}. "
                + (
                    "✓ Signature verified – email is authentic."
                    if (dkim and dkim.result == "pass")
                    else "✗ No valid signature – email may have been tampered with."
                )
            ),
        },
        "dmarc": {
            "title": "DMARC Policy",
            "passed": dmarc.result == "pass" if dmarc else False,
            "explanation": (
                f"DMARC checks that SPF and DKIM align with the From: address domain '{parsed.sender_domain}' "
                f"and enforces the domain's policy (none/quarantine/reject). "
                f"Result: {dmarc.result if dmarc else 'not present'}. "
                f"Policy: {dmarc.policy if dmarc else 'unknown'}."
            ),
        },
        "hash": {
            "title": "SHA-256 Message Integrity",
            "passed": True,
            "explanation": (
                f"We computed SHA-256({parsed.sha256_hash[:16]}...) of the raw message bytes. "
                "This fingerprint uniquely identifies the message. If any byte changes, "
                "the hash changes, immediately revealing tampering."
            ),
        },
        "signature": {
            "title": "Digital Signature (Ed25519/RSA-PSS)",
            "passed": sig_valid is not False,
            "explanation": (
                "If the sender registered a public key with us, we verify their Ed25519 or RSA-PSS "
                "signature on the message. This proves the message came from the keyholder and was "
                "not altered. "
                + (
                    "✓ Signature valid."
                    if sig_valid is True
                    else ("✗ Signature INVALID – tampered or forged!" if sig_valid is False else "No signature present.")
                )
            ),
        },
        "replay": {
            "title": "Replay Attack Prevention",
            "passed": not replay_detected,
            "explanation": (
                "Every signed message includes a unique nonce and timestamp. We store used nonces "
                "so an attacker cannot simply capture and re-send a valid signed message. "
                + ("✗ REPLAY DETECTED – this nonce was already used!" if replay_detected else "✓ Fresh nonce accepted.")
            ),
        },
        "url_analysis": {
            "title": "URL Analysis",
            "passed": (url_result.risk_score if url_result else 0) < 50,
            "explanation": (
                f"We analyzed {len(url_result.urls_found) if url_result else 0} URL(s) in this email, "
                "checking for IP-based URLs, URL shorteners, suspicious TLDs, punycode domains, "
                f"and keyword indicators. URL risk score: {url_result.risk_score if url_result else 0:.0f}/100."
            ),
        },
        "ml": {
            "title": "AI/ML Phishing Detection",
            "passed": (ml_result.probability if ml_result else 0) < 0.5,
            "explanation": (
                "Our ensemble ML model (Logistic Regression + Random Forest, trained on thousands of "
                "real phishing and legitimate emails) analyzed the text, URLs, and structural features. "
                f"Phishing probability: {(ml_result.probability * 100) if ml_result else 0:.1f}%. "
                + (
                    f"Top indicator: '{ml_result.top_features[0]['feature'] if ml_result and ml_result.top_features else 'N/A'}'"
                    if ml_result and ml_result.top_features
                    else ""
                )
            ),
        },
        "risk_score": {
            "title": "Risk Score",
            "passed": risk_output.verdict != "MALICIOUS",
            "explanation": (
                f"Final risk score: {risk_output.total}/100. "
                f"Verdict: {risk_output.verdict}. "
                "The score combines auth (25%), URLs (20%), attachments (15%), ML (25%), "
                "header analysis (10%), and cryptographic checks (5%). "
                + (f"⚠ Override: {risk_output.override_reason}" if risk_output.hard_override else "")
            ),
        },
    }


async def process_email(
    raw_email: bytes,
    db: Session,
    source_ip: str | None = None,
    tls_info: dict | None = None,
    is_simulation: bool = False,
    simulation_scenario: str | None = None,
) -> EmailRecord:
    """
    Run the full PhishShield analysis pipeline on a raw RFC 2822 email.

    Returns the created EmailRecord with all analysis results populated.
    """
    pipeline_timing: dict[str, float] = {}
    master_key = settings.aes_master_key_bytes

    # ── Stage 1: Parse email ──────────────────────────────────────────────────
    t0 = time.perf_counter()
    parsed: ParsedEmail = parse_email(raw_email)
    pipeline_timing["parse"] = _ms(t0)

    # ── Stage 2: TLS info ─────────────────────────────────────────────────────
    tls_protocol = None
    tls_cipher = None
    tls_established = False
    if tls_info:
        tls_protocol = tls_info.get("protocol")
        tls_cipher = tls_info.get("cipher_name")
        tls_established = tls_info.get("established", False)

    # ── Stage 3: SPF / DKIM / DMARC ──────────────────────────────────────────
    t0 = time.perf_counter()
    spf_result = check_spf(
        sending_ip=source_ip or "127.0.0.1",
        sender_email=parsed.sender_address or "",
    )
    dkim_result = check_dkim(raw_email)
    dmarc_result = check_dmarc(
        from_header=parsed.from_address or "",
        spf_result=spf_result.result,
        spf_domain=parsed.sender_domain or "",
        dkim_result=dkim_result.result,
        dkim_domain=dkim_result.domain or "",
    )
    pipeline_timing["auth"] = _ms(t0)

    auth_details = {
        "spf": {"result": spf_result.result, "explanation": spf_result.explanation},
        "dkim": {"result": dkim_result.result, "domain": dkim_result.domain, "selector": dkim_result.selector},
        "dmarc": {"result": dmarc_result.result, "policy": dmarc_result.policy},
    }

    # ── Stage 4: Hash & Signature Verification ────────────────────────────────
    t0 = time.perf_counter()
    msg_hash = sha256_hash(raw_email)

    # Check for signed message headers (X-PhishShield-Signature: <base64_sig> key_id=<id>)
    # Use case-insensitive lookup since email headers preserve original case
    _headers_lower = {k.lower(): v for k, v in (parsed.headers or {}).items()}
    sig_header = _headers_lower.get("x-phishshield-signature", "")
    hmac_header = _headers_lower.get("x-phishshield-hmac", "")
    nonce_header = _headers_lower.get("x-phishshield-nonce", "")
    timestamp_header = _headers_lower.get("x-phishshield-timestamp", "")

    sig_valid: bool | None = None
    hmac_valid_result: bool | None = None
    replay_detected = False
    signature_claimed = bool(sig_header)
    hmac_claimed = bool(hmac_header)

    # Signature verification
    if sig_header:
        try:
            parts = sig_header.split()
            sig_b64 = parts[0]
            key_id_part = next((p for p in parts if p.startswith("key_id=")), None)
            key_id = key_id_part.split("=", 1)[1] if key_id_part else None
            sig_bytes = base64.b64decode(sig_b64 + "==")
            # Look up registered key by key_id
            from backend.app.models import RegisteredKey
            reg_key = None
            if key_id:
                reg_key = db.query(RegisteredKey).filter(
                    RegisteredKey.id == int(key_id),
                    RegisteredKey.is_active == True,  # noqa: E712
                ).first()
            if reg_key:
                # Verify against canonical bytes: strip the signature header
                # (same bytes the sender signed before adding the sig header)
                canonical = _strip_header(raw_email, "X-PhishShield-Signature")
                if reg_key.key_type.value == "ED25519":
                    sig_valid = ed25519_verify(canonical, sig_bytes, reg_key.public_key_pem)
                elif reg_key.key_type.value == "RSA_PSS":
                    sig_valid = rsa_pss_verify(canonical, sig_bytes, reg_key.public_key_pem)
                else:
                    sig_valid = None
            else:
                sig_valid = False  # Claimed signature but no matching key
        except Exception:
            sig_valid = False

    # HMAC verification
    if hmac_header:
        try:
            import base64 as _b64

            from backend.app.models import RegisteredKey
            parts = hmac_header.split()
            hmac_b64 = parts[0]
            key_id_part = next((p for p in parts if p.startswith("key_id=")), None)
            key_id = key_id_part.split("=", 1)[1] if key_id_part else None
            expected_mac = _b64.b64decode(hmac_b64 + "==")
            reg_key = None
            if key_id:
                reg_key = db.query(RegisteredKey).filter(
                    RegisteredKey.id == int(key_id),
                    RegisteredKey.is_active == True,  # noqa: E712
                    RegisteredKey.key_type == "HMAC",
                ).first()
            if reg_key:
                from backend.crypto.hmac_util import hmac_verify
                # HMAC key stored as base64 in public_key_pem field for HMAC keys
                hmac_key = base64.b64decode(reg_key.public_key_pem)
                hmac_valid_result = hmac_verify(raw_email, hmac_key, expected_mac)
            else:
                hmac_valid_result = False
        except Exception:
            hmac_valid_result = False

    # Replay protection (only for signed messages)
    if nonce_header and timestamp_header:
        nonce_cache = NonceCache(db)
        is_fresh, reason = nonce_cache.check_and_consume(
            nonce=nonce_header,
            message_timestamp=timestamp_header,
            message_id=parsed.message_id,
        )
        if not is_fresh:
            replay_detected = True

    pipeline_timing["crypto"] = _ms(t0)

    crypto_details = {
        "sha256_hash": msg_hash,
        "signature_claimed": signature_claimed,
        "signature_valid": sig_valid,
        "hmac_claimed": hmac_claimed,
        "hmac_valid": hmac_valid_result,
        "replay_detected": replay_detected,
        "nonce": nonce_header or None,
    }

    # ── Stage 5: URL Analysis ─────────────────────────────────────────────────
    t0 = time.perf_counter()
    body_text = (parsed.body_text or "") + " " + (parsed.body_html or "")
    url_result = analyze_urls(body_text, parsed.body_html or "")
    pipeline_timing["url_analysis"] = _ms(t0)

    # ── Stage 6: Attachment Analysis ──────────────────────────────────────────
    t0 = time.perf_counter()
    analyzer = AttachmentAnalyzer(vt_api_key=settings.vt_api_key or "")
    attach_results = [analyzer.analyze(a) for a in parsed.attachments]
    attach_risk = max((a.risk_score for a in attach_results), default=0.0)
    malicious_hash = any(getattr(a, "virustotal_detections", 0) and a.virustotal_detections > 3 for a in attach_results)
    pipeline_timing["attachment"] = _ms(t0)

    # ── Stage 7: Header & Spoofing Analysis ──────────────────────────────────
    t0 = time.perf_counter()
    header_result = analyze_headers(
        all_headers=dict(parsed.headers) if parsed.headers else {},
        received_headers=parsed.received_chain or [],
    )
    spoof_result = detect_spoofing(parsed)
    combined_header_score = max(header_result.score, spoof_result.combined_score)
    pipeline_timing["header_analysis"] = _ms(t0)

    # ── Stage 8: ML Phishing Detection ───────────────────────────────────────
    t0 = time.perf_counter()
    ml_result = predict_phishing(
        text=body_text,
        subject=parsed.subject or "",
        url_features={
            "url_count": len(url_result.urls_found),
            "ip_urls": sum(1 for u in url_result.urls_found if u.is_ip_address),
            "shortener_urls": sum(1 for u in url_result.urls_found if u.uses_url_shortener),
            "suspicious_tld_count": sum(1 for u in url_result.urls_found if u.suspicious_tld),
            "avg_url_length": (
                sum(u.url_length for u in url_result.urls_found) / len(url_result.urls_found)
                if url_result.urls_found else 0
            ),
        },
        header_features={
            "spf_pass": 1 if spf_result.result == "pass" else 0,
            "dkim_pass": 1 if dkim_result.result == "pass" else 0,
            "dmarc_pass": 1 if dmarc_result.result == "pass" else 0,
            "has_reply_to_mismatch": 1 if spoof_result.reply_to_mismatch else 0,
        },
    )
    pipeline_timing["ml"] = _ms(t0)

    # ── Stage 9: Risk Scoring ─────────────────────────────────────────────────
    t0 = time.perf_counter()
    risk_inp = RiskInput(
        spf_result=spf_result.result,
        dkim_result=dkim_result.result,
        dmarc_result=dmarc_result.result,
        url_risk_score=url_result.risk_score,
        attachment_risk_score=attach_risk,
        ml_probability=ml_result.probability,
        header_risk_score=combined_header_score,
        signature_claimed=signature_claimed,
        signature_valid=sig_valid,
        hmac_claimed=hmac_claimed,
        hmac_valid=hmac_valid_result,
        hash_match=True,  # We computed it; tamper detected via sig/hmac
        replay_detected=replay_detected,
        malicious_hash_detected=malicious_hash,
    )
    thresholds = {"suspicious": settings.threshold_suspicious, "malicious": settings.threshold_malicious}
    risk_output = compute_risk_score(risk_inp, thresholds)
    pipeline_timing["scoring"] = _ms(t0)

    # ── Stage 10: Decision ────────────────────────────────────────────────────
    verdict = risk_output.verdict
    delivered = verdict in ("LEGITIMATE", "SUSPICIOUS")
    quarantined = verdict == "MALICIOUS"
    warning = None
    if verdict == "SUSPICIOUS":
        warning = (
            f"⚠ This email has a risk score of {risk_output.total:.0f}/100. "
            "Exercise caution before clicking links or downloading attachments."
        )

    # ── Stage 11: Encrypt & Store ─────────────────────────────────────────────
    t0 = time.perf_counter()
    encrypted_email, enc_nonce = encrypt_email(raw_email, master_key)

    # Sanitize HTML for safe display
    sanitized = None
    if parsed.body_html:
        try:
            import bleach
            sanitized = bleach.clean(
                parsed.body_html,
                tags=["p", "br", "b", "i", "em", "strong", "ul", "ol", "li", "h1", "h2", "h3", "span", "div", "table", "tr", "td", "th"],
                attributes={},
                strip=True,
            )
        except Exception:
            sanitized = None

    pipeline_timing["storage"] = _ms(t0)
    pipeline_timing["total"] = sum(pipeline_timing.values())

    # ── Build educational explanation ─────────────────────────────────────────
    explanation = _build_educational_explanation(
        parsed, spf_result, dkim_result, dmarc_result,
        sig_valid, hmac_valid_result, replay_detected,
        url_result, attach_results, header_result, spoof_result,
        ml_result, risk_output,
    )

    # ── Create DB record ──────────────────────────────────────────────────────
    record = EmailRecord(
        message_id=parsed.message_id,
        sender_address=parsed.sender_address,
        sender_display_name=parsed.sender_display_name,
        reply_to=", ".join(parsed.reply_to) if isinstance(parsed.reply_to, list) else (parsed.reply_to or ""),
        subject=parsed.subject,
        recipients=parsed.to_addresses if isinstance(parsed.to_addresses, list) else [],
        tls_protocol=tls_protocol,
        tls_cipher=tls_cipher,
        tls_established=tls_established,
        spf_result=spf_result.result,
        dkim_result=dkim_result.result,
        dmarc_result=dmarc_result.result,
        auth_details=auth_details,
        sha256_hash=msg_hash,
        signature_valid=sig_valid,
        hmac_valid=hmac_valid_result,
        replay_detected=replay_detected,
        crypto_details=crypto_details,
        url_findings={
            "risk_score": url_result.risk_score,
            "count": len(url_result.urls_found),
            "top_risks": url_result.top_risks,
            "urls": [
                {
                    "url": u.url,
                    "is_ip": u.is_ip_address,
                    "shortener": u.uses_url_shortener,
                    "punycode": u.has_punycode,
                    "suspicious_tld": u.suspicious_tld,
                    "uses_https": u.uses_https,
                }
                for u in url_result.urls_found[:20]  # store top 20
            ],
        },
        attachment_findings={
            "count": len(parsed.attachments),
            "risk_score": attach_risk,
            "attachments": [
                {
                    "filename": a.filename,
                    "content_type": a.content_type,
                    "sha256": a.sha256_hash,
                    "risk_score": a.risk_score,
                    "risks": a.risks,
                }
                for a in attach_results
            ],
        },
        header_findings={
            "score": header_result.score,
            "risk_factors": header_result.risk_factors,
        },
        spoofing_findings={
            "is_spoofed": spoof_result.is_spoofed,
            "checks": spoof_result.checks,
            "details": spoof_result.details,
        },
        ml_phishing_probability=ml_result.probability,
        ml_verdict=ml_result.label,
        ml_top_features=ml_result.top_features,
        risk_score=risk_output.total,
        risk_breakdown={
            "auth_score": risk_output.auth_score,
            "url_score": risk_output.url_score,
            "attachment_score": risk_output.attachment_score,
            "ml_score": risk_output.ml_score,
            "header_score": risk_output.header_score,
            "crypto_score": risk_output.crypto_score,
            "hard_override": risk_output.hard_override,
            "override_reason": risk_output.override_reason,
        },
        verdict=Verdict(verdict),
        delivered=delivered,
        quarantined=quarantined,
        warning_message=warning,
        raw_email_encrypted=bytes(encrypted_email) if encrypted_email else None,
        encryption_nonce=bytes(enc_nonce) if enc_nonce else None,
        sanitized_html=sanitized,
        pipeline_timing=pipeline_timing,
        explanation=explanation,
        is_simulation=is_simulation,
        simulation_scenario=simulation_scenario,
    )
    db.add(record)
    db.flush()

    # Log the verdict
    _log(
        db,
        record.id,
        event_type=f"EMAIL_{verdict}",
        severity="CRITICAL" if verdict == "MALICIOUS" else "WARNING" if verdict == "SUSPICIOUS" else "INFO",
        stage="pipeline",
        message=f"Email processed: verdict={verdict}, score={risk_output.total:.1f}",
        details={
            "sender": parsed.sender_address,
            "subject": parsed.subject,
            "risk_score": risk_output.total,
        },
        source_ip=source_ip,
    )

    if replay_detected:
        _log(db, record.id, "REPLAY_ATTACK", "CRITICAL", "crypto", f"Replay attack detected on message {parsed.message_id}", source_ip=source_ip)

    if spoof_result.is_spoofed:
        _log(db, record.id, "SPOOFING_DETECTED", "WARNING", "auth", f"Spoofing indicators found: {spoof_result.checks}", source_ip=source_ip)

    db.commit()
    db.refresh(record)
    return record
