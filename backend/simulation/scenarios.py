"""
PhishShield – Attack Simulation Module.

Generates real crafted email messages and sends them through the actual pipeline.
Each scenario produces genuinely crafted payloads — no mock/placeholder results.

Scenarios:
  1. phishing     – Credential harvesting with malicious URLs
  2. spoofing     – Forged From domain (SPF/DKIM fail)
  3. tampering    – Valid signed message modified in transit
  4. replay       – Previously used nonce resent
  5. mitm         – Unsigned/invalid-cert payload
  6. batch        – N variations of each + benign emails
"""
from __future__ import annotations

import base64
import random
import string
import time
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from sqlalchemy.orm import Session

from backend.app.pipeline import process_email
from backend.crypto.hashing import sha256_hash
from backend.crypto.replay import current_timestamp, generate_nonce
from backend.crypto.signatures import ed25519_sign, generate_ed25519_keypair

# ─── Phishing email templates ─────────────────────────────────────────────────

PHISHING_SUBJECTS = [
    "URGENT: Your account has been compromised",
    "Action Required: Verify your payment information",
    "Your account will be suspended in 24 hours",
    "Important: Confirm your identity now",
    "Security Alert: Unusual sign-in detected",
    "Your password expires today - click to update",
]

PHISHING_URLS = [
    "http://paypa1-secure.tk/verify?token=abc123",
    "http://192.168.1.100/login",
    "http://bit.ly/2xK9mP",
    "http://secure-micros0ft.ml/reset",
    "http://аррlе.com/id/verify",  # Cyrillic homoglyphs
    "http://g00gle-security.top/update",
]

PHISHING_BODIES = [
    """Dear Customer,

We have detected unusual activity on your account. Your account has been temporarily
limited. To restore full access, please verify your identity immediately:

CLICK HERE TO VERIFY: {url}

This is urgent. Failure to verify within 24 hours will result in permanent account suspension.

Security Team""",
    """Hello,

Your password will expire in 24 hours. Please click the link below to update your password:

{url}

If you do not update your password, you will lose access to your account.

IT Department""",
]

LEGITIMATE_SUBJECTS = [
    "Meeting notes from today's standup",
    "Q3 project update",
    "Invitation: Team lunch on Friday",
    "FYI: Office closed next Monday",
    "Re: Your support ticket #45678",
]

LEGITIMATE_BODIES = [
    """Hi team,

Please find attached the notes from today's standup meeting.

Key points:
- Sprint review is on Thursday at 2pm
- Please submit your status updates by EOD
- New team member starts Monday

Thanks,
John""",
    """Hi,

Just a reminder that the office will be closed next Monday for the public holiday.
Please plan your work accordingly.

Best regards,
HR Team""",
]


# ─── Email builders ────────────────────────────────────────────────────────────

def _build_mime(
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    from_name: str = "",
    reply_to: str = "",
    extra_headers: dict | None = None,
) -> bytes:
    """Build a raw RFC 2822 email as bytes."""
    msg = MIMEMultipart("alternative")
    msg["From"] = f'"{from_name}" <{from_addr}>' if from_name else from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["Message-ID"] = f"<{''.join(random.choices(string.ascii_lowercase, k=16))}@phishshield.test>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if extra_headers:
        for k, v in extra_headers.items():
            msg[k] = v
    msg.attach(MIMEText(body, "plain"))
    return msg.as_bytes()


def _inject_header(raw_email: bytes, header_name: str, header_value: str) -> bytes:
    """Prepend a header to an existing raw email bytes.

    This preserves all existing bytes unchanged and adds the header at the top.
    Used to add X-PhishShield-Signature after signing the base email bytes
    so that the verifier can strip it back to get identical canonical bytes.
    """
    header_line = f"{header_name}: {header_value}\r\n".encode()
    return header_line + raw_email


# ─── Scenario implementations ─────────────────────────────────────────────────

async def scenario_phishing(db: Session, iteration: int = 0) -> dict:
    """
    Phishing scenario: credential-harvesting email with malicious URL.
    Real pipeline detects it via ML, URL analysis, and (optionally) SPF/DKIM failure.
    """
    url = PHISHING_URLS[iteration % len(PHISHING_URLS)]
    subject = PHISHING_SUBJECTS[iteration % len(PHISHING_SUBJECTS)]
    body = PHISHING_BODIES[iteration % len(PHISHING_BODIES)].format(url=url)

    phishing_senders = [
        ("PayPal Security <security@paypal.com>", "security@paypa1.com"),
        ("Google Accounts <accounts@google.com>", "alerts@g00gle.com"),
        ("Apple Security <id@apple.com>", "support@app1e.com"),
        ("Microsoft 365 <admin@microsoft.com>", "security@micros0ft.com"),
        ("Amazon Security <alerts@amazon.com>", "service@amaz0n.com"),
        ("Bank of America <online@bankofamerica.com>", "verify@bank0famerica.com"),
    ]
    from_name, from_addr = phishing_senders[iteration % len(phishing_senders)]

    raw = _build_mime(
        from_addr=from_addr,
        to_addr="victim@company.com",
        subject=subject,
        body=body,
        from_name=from_name,
    )

    t0 = time.perf_counter()
    record = await process_email(
        raw_email=raw,
        db=db,
        source_ip="198.51.100.1",
        tls_info={"protocol": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384", "established": True},
        is_simulation=True,
        simulation_scenario="phishing",
    )
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "scenario": "phishing",
        "iteration": iteration,
        "email_id": record.id,
        "verdict": record.verdict.value if record.verdict else None,
        "risk_score": record.risk_score,
        "detected": record.verdict.value in ("SUSPICIOUS", "MALICIOUS") if record.verdict else False,
        "catching_layers": _identify_catching_layers(record),
        "latency_ms": latency_ms,
        "url_used": url,
    }


async def scenario_spoofing(db: Session, iteration: int = 0) -> dict:
    """
    Spoofing scenario: email claims to be from a legit domain
    but SPF check fails (sending IP not authorized).
    Also tests display-name spoofing detection.
    """
    legitimate_domains = ["paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com"]
    target_domain = legitimate_domains[iteration % len(legitimate_domains)]

    raw = _build_mime(
        from_addr=f"security@{target_domain}",
        to_addr="victim@company.com",
        subject=f"Important security update from {target_domain}",
        body=f"Please verify your {target_domain} account at: http://phishing-site.tk/verify",
        from_name=f"{target_domain.split('.')[0].capitalize()} Security",
        reply_to="attacker@evil-domain.tk",
    )

    t0 = time.perf_counter()
    record = await process_email(
        raw_email=raw,
        db=db,
        source_ip="198.51.100.99",  # Unauthorized IP for these domains
        tls_info={"protocol": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384", "established": True},
        is_simulation=True,
        simulation_scenario="spoofing",
    )
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "scenario": "spoofing",
        "iteration": iteration,
        "email_id": record.id,
        "verdict": record.verdict.value if record.verdict else None,
        "risk_score": record.risk_score,
        "detected": record.verdict.value in ("SUSPICIOUS", "MALICIOUS") if record.verdict else False,
        "catching_layers": _identify_catching_layers(record),
        "latency_ms": latency_ms,
        "spoofed_domain": target_domain,
        "spf_result": record.spf_result,
        "dkim_result": record.dkim_result,
        "spoofing_findings": record.spoofing_findings,
    }


async def scenario_tampering(db: Session, iteration: int = 0) -> dict:
    """
    Message tampering scenario:
    1. Generate an Ed25519 keypair and register it.
    2. Build a legitimate email and sign it.
    3. Modify the email body AFTER signing (simulating MitM tampering).
    4. Send the tampered+signed email through the pipeline.
    5. Pipeline should detect the signature failure.
    """
    # Generate a fresh keypair for this simulation
    private_pem, public_pem = generate_ed25519_keypair()

    # Register the public key
    from backend.app.models import RegisteredKey
    reg_key = RegisteredKey(
        label=f"sim-tampering-{iteration}",
        domain="legit-sender.com",
        key_type="ED25519",
        public_key_pem=public_pem,
        is_active=True,
    )
    db.add(reg_key)
    db.flush()
    key_id = reg_key.id

    # Build the original legitimate email
    original_body = f"Hello,\n\nThis is a legitimate message from our server.\n\nRegards,\nLegitSender (iteration {iteration})"
    nonce = generate_nonce()
    timestamp = current_timestamp()

    # Build original email (without signature header) — this is what gets signed
    original_raw = _build_mime(
        from_addr="legit@legit-sender.com",
        to_addr="recipient@company.com",
        subject="Legitimate business communication",
        body=original_body,
        extra_headers={
            "X-PhishShield-Nonce": nonce,
            "X-PhishShield-Timestamp": timestamp,
        },
    )

    # Sign the canonical original email bytes
    signature = ed25519_sign(original_raw, private_pem)
    sig_b64 = base64.b64encode(signature).decode()
    sig_header_value = f"{sig_b64} key_id={key_id}"

    # Now TAMPER with the email body: different content that the signature doesn't cover
    tampered_body = original_body.replace(
        "legitimate message", "TAMPERED malicious message http://evil.tk/steal"
    )
    tampered_base = _build_mime(
        from_addr="legit@legit-sender.com",
        to_addr="recipient@company.com",
        subject="Legitimate business communication",
        body=tampered_body,  # ← tampered body
        extra_headers={
            "X-PhishShield-Nonce": nonce,
            "X-PhishShield-Timestamp": timestamp,
        },
    )
    # Inject the ORIGINAL signature header — sig was computed over original_raw
    # Pipeline will strip this header → get tampered_base ≠ original_raw → sig FAILS
    tampered_raw = _inject_header(tampered_base, "X-PhishShield-Signature", sig_header_value)

    t0 = time.perf_counter()
    record = await process_email(
        raw_email=tampered_raw,
        db=db,
        source_ip="198.51.100.5",
        tls_info={"protocol": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384", "established": True},
        is_simulation=True,
        simulation_scenario="tampering",
    )
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    db.commit()

    return {
        "scenario": "tampering",
        "iteration": iteration,
        "email_id": record.id,
        "verdict": record.verdict.value if record.verdict else None,
        "risk_score": record.risk_score,
        "detected": record.signature_valid is False,
        "catching_layers": _identify_catching_layers(record),
        "latency_ms": latency_ms,
        "signature_valid": record.signature_valid,
        "original_hash": sha256_hash(original_raw),
        "tampered_hash": sha256_hash(tampered_raw),
        "hashes_differ": sha256_hash(original_raw) != sha256_hash(tampered_raw),
    }


async def scenario_replay(db: Session, iteration: int = 0) -> dict:
    """
    Replay attack scenario:
    1. Generate a valid signed email with a nonce.
    2. Send it through the pipeline (should pass).
    3. Send the EXACT SAME email again (replay).
    4. Pipeline should detect and reject the replay.
    """
    private_pem, public_pem = generate_ed25519_keypair()

    from backend.app.models import RegisteredKey
    reg_key = RegisteredKey(
        label=f"sim-replay-{iteration}",
        domain="trusted-sender.com",
        key_type="ED25519",
        public_key_pem=public_pem,
        is_active=True,
    )
    db.add(reg_key)
    db.flush()
    key_id = reg_key.id

    nonce = generate_nonce()
    timestamp = current_timestamp()

    # Build canonical email (without signature header) — this is what gets signed
    original_raw = _build_mime(
        from_addr="sender@trusted-sender.com",
        to_addr="recipient@company.com",
        subject="Valid signed message",
        body=f"This is a fresh message. Iteration {iteration}.",
        extra_headers={
            "X-PhishShield-Nonce": nonce,
            "X-PhishShield-Timestamp": timestamp,
        },
    )

    # Sign the canonical bytes (without sig header)
    signature = ed25519_sign(original_raw, private_pem)
    sig_b64 = base64.b64encode(signature).decode()
    sig_header_value = f"{sig_b64} key_id={key_id}"

    # Build signed_raw by injecting the signature header into the original
    # Pipeline strips X-PhishShield-Signature → gets original_raw → sig PASSES
    signed_raw = _inject_header(original_raw, "X-PhishShield-Signature", sig_header_value)

    # First delivery: should succeed (fresh nonce)
    t0 = time.perf_counter()
    record1 = await process_email(
        raw_email=signed_raw, db=db,
        source_ip="198.51.100.10",
        tls_info={"established": True, "protocol": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384"},
        is_simulation=True, simulation_scenario="replay",
    )

    # Second delivery: REPLAY — exact same signed_raw with same nonce → detected
    t0 = time.perf_counter()
    record2 = await process_email(
        raw_email=signed_raw, db=db,
        source_ip="198.51.100.10",
        tls_info={"established": True, "protocol": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384"},
        is_simulation=True, simulation_scenario="replay",
    )
    latency_replay = round((time.perf_counter() - t0) * 1000, 2)
    db.commit()

    return {
        "scenario": "replay",
        "iteration": iteration,
        "email_id": record2.id,
        "verdict": record2.verdict.value if record2.verdict else None,
        "risk_score": record2.risk_score,
        "first_delivery": {
            "email_id": record1.id,
            "verdict": record1.verdict.value if record1.verdict else None,
            "replay_detected": record1.replay_detected,
        },
        "replay_delivery": {
            "email_id": record2.id,
            "verdict": record2.verdict.value if record2.verdict else None,
            "replay_detected": record2.replay_detected,
        },
        "detected": record2.replay_detected,
        "catching_layers": ["replay_protection"],
        "latency_ms": latency_replay,
        "nonce": nonce,
    }


async def scenario_mitm(db: Session, iteration: int = 0) -> dict:
    """
    MitM scenario: simulates an attacker intercepting and modifying a message
    without having the private key. The signature fails because the key was never
    registered, and the hash shows the message was altered.
    """
    # Attacker tries to forge a signed header with a random invalid signature
    fake_sig_b64 = base64.b64encode(b"\x00" * 64).decode()
    fake_key_id = 99999  # Non-existent key ID

    base_raw = _build_mime(
        from_addr="ceo@company.com",
        to_addr="finance@company.com",
        subject="URGENT: Wire transfer required immediately",
        body="Please transfer $50,000 to account 12345 immediately. This is confidential.",
        from_name="CEO John Smith",
        extra_headers={
            "X-PhishShield-Nonce": generate_nonce(),
            "X-PhishShield-Timestamp": current_timestamp(),
        },
    )
    # Inject a forged (invalid) signature — key_id doesn't exist → sig_valid=False
    raw = _inject_header(base_raw, "X-PhishShield-Signature", f"{fake_sig_b64} key_id={fake_key_id}")

    t0 = time.perf_counter()
    record = await process_email(
        raw_email=raw,
        db=db,
        source_ip="203.0.113.50",
        tls_info={"established": False, "protocol": None, "cipher_name": None},  # No TLS!
        is_simulation=True,
        simulation_scenario="mitm",
    )
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "scenario": "mitm",
        "iteration": iteration,
        "email_id": record.id,
        "verdict": record.verdict.value if record.verdict else None,
        "risk_score": record.risk_score,
        "detected": record.verdict.value in ("SUSPICIOUS", "MALICIOUS") if record.verdict else False,
        "catching_layers": _identify_catching_layers(record),
        "latency_ms": latency_ms,
        "tls_established": record.tls_established,
        "signature_valid": record.signature_valid,
        "replay_detected": record.replay_detected,
    }


async def scenario_benign(db: Session, iteration: int = 0) -> dict:
    """Generate a legitimate email to test for false positives."""
    subject = LEGITIMATE_SUBJECTS[iteration % len(LEGITIMATE_SUBJECTS)]
    body = LEGITIMATE_BODIES[iteration % len(LEGITIMATE_BODIES)]

    raw = _build_mime(
        from_addr="colleague@company.com",
        to_addr="you@company.com",
        subject=subject,
        body=body,
        from_name="John Smith",
    )

    t0 = time.perf_counter()
    record = await process_email(
        raw_email=raw,
        db=db,
        source_ip="203.0.113.1",
        tls_info={"established": True, "protocol": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384"},
        is_simulation=True,
        simulation_scenario="benign",
    )
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "scenario": "benign",
        "iteration": iteration,
        "email_id": record.id,
        "verdict": record.verdict.value if record.verdict else None,
        "risk_score": record.risk_score,
        "false_positive": record.verdict.value != "LEGITIMATE" if record.verdict else True,
        "latency_ms": latency_ms,
    }


def _identify_catching_layers(record: Any) -> list[str]:
    """Identify which pipeline layers flagged this email."""
    layers = []
    if record.spf_result and record.spf_result != "pass":
        layers.append(f"spf:{record.spf_result}")
    if record.dkim_result and record.dkim_result != "pass":
        layers.append(f"dkim:{record.dkim_result}")
    if record.dmarc_result and record.dmarc_result != "pass":
        layers.append(f"dmarc:{record.dmarc_result}")
    if record.signature_valid is False:
        layers.append("signature:invalid")
    if record.replay_detected:
        layers.append("replay:detected")
    findings = record.url_findings or {}
    if findings.get("risk_score", 0) > 50:
        layers.append(f"url:risk={findings.get('risk_score', 0):.0f}")
    findings = record.spoofing_findings or {}
    if findings.get("is_spoofed"):
        layers.append("spoofing:detected")
    if record.ml_phishing_probability and record.ml_phishing_probability > 0.5:
        layers.append(f"ml:prob={record.ml_phishing_probability:.2f}")
    if not layers:
        layers.append("none (clean email)")
    return layers


# ─── Batch runner ─────────────────────────────────────────────────────────────

SCENARIO_MAP = {
    "phishing": scenario_phishing,
    "spoofing": scenario_spoofing,
    "tampering": scenario_tampering,
    "replay": scenario_replay,
    "mitm": scenario_mitm,
}


async def run_scenario(scenario: str, db: Session, iterations: int = 1, include_benign: bool = True) -> dict:
    """Run a named scenario N times and return aggregated results."""
    if scenario == "batch":
        return await run_batch(db, iterations, include_benign)

    fn = SCENARIO_MAP.get(scenario)
    if not fn:
        raise ValueError(f"Unknown scenario: {scenario!r}")

    results = []
    for i in range(iterations):
        result = await fn(db, iteration=i)
        results.append(result)

    detected = sum(1 for r in results if r.get("detected", False))
    latencies = [r.get("latency_ms", 0) for r in results]

    # Benign emails for false positive rate
    fp_rate = None
    if include_benign and iterations > 1:
        benign_results = [await scenario_benign(db, i) for i in range(iterations)]
        false_positives = sum(1 for r in benign_results if r.get("false_positive", False))
        fp_rate = round(false_positives / iterations * 100, 1)

    return {
        "scenario": scenario,
        "iterations": iterations,
        "results": results,
        "detection_rate": round(detected / iterations * 100, 1) if iterations > 0 else 0,
        "false_positive_rate": fp_rate,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "summary": {
            "detected": detected,
            "missed": iterations - detected,
            "total": iterations,
        },
    }


async def run_batch(db: Session, iterations: int = 5, include_benign: bool = True) -> dict:
    """Run all 5 attack scenarios in batch mode."""
    all_results = {}
    for name, fn in SCENARIO_MAP.items():
        scenario_results = []
        for i in range(iterations):
            r = await fn(db, iteration=i)
            scenario_results.append(r)
        detected = sum(1 for r in scenario_results if r.get("detected", False))
        latencies = [r.get("latency_ms", 0) for r in scenario_results]
        all_results[name] = {
            "results": scenario_results,
            "detection_rate": round(detected / iterations * 100, 1),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        }

    # Benign for false positive rate
    fp_rate = None
    if include_benign:
        benign_results = [await scenario_benign(db, i) for i in range(iterations)]
        false_positives = sum(1 for r in benign_results if r.get("false_positive", False))
        fp_rate = round(false_positives / iterations * 100, 1)

    return {
        "scenario": "batch",
        "iterations": iterations,
        "results": all_results,
        "detection_rate": round(
            sum(v["detection_rate"] for v in all_results.values()) / len(all_results), 1
        ),
        "false_positive_rate": fp_rate,
        "avg_latency_ms": round(
            sum(v["avg_latency_ms"] for v in all_results.values()) / len(all_results), 2
        ),
        "summary": {s: {"detection_rate": v["detection_rate"]} for s, v in all_results.items()},
    }
