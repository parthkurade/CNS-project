"""
PhishShield – ORM Models.
All tables are defined here so that init_db() can create them.
"""
from __future__ import annotations

import enum

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from backend.app.database import Base

# ─── Enums ───────────────────────────────────────────────────────────────────


class Verdict(str, enum.Enum):
    LEGITIMATE = "LEGITIMATE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class KeyType(str, enum.Enum):
    ED25519 = "ED25519"
    RSA_PSS = "RSA_PSS"
    HMAC = "HMAC"


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"


# ─── User ─────────────────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.ANALYST, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    last_login = Column(DateTime, nullable=True)


# ─── Registered Public Key ────────────────────────────────────────────────────


class RegisteredKey(Base):
    __tablename__ = "registered_keys"

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(255), nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    key_type = Column(Enum(KeyType), nullable=False)
    public_key_pem = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    revoked_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)


# ─── Nonce Cache (Replay Protection) ─────────────────────────────────────────


class UsedNonce(Base):
    __tablename__ = "used_nonces"

    id = Column(Integer, primary_key=True, index=True)
    nonce = Column(String(128), unique=True, index=True, nullable=False)
    message_id = Column(String(255), nullable=True)
    used_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)


# ─── Analyzed Email ───────────────────────────────────────────────────────────


class EmailRecord(Base):
    __tablename__ = "email_records"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String(255), index=True, nullable=True)
    received_at = Column(DateTime, server_default=func.now())

    # Sender info
    sender_address = Column(String(255), index=True, nullable=True)
    sender_display_name = Column(String(255), nullable=True)
    reply_to = Column(String(255), nullable=True)
    subject = Column(String(1000), nullable=True)
    recipients = Column(JSON, nullable=True)  # list[str]

    # TLS info
    tls_protocol = Column(String(32), nullable=True)
    tls_cipher = Column(String(128), nullable=True)
    tls_established = Column(Boolean, default=False)

    # Authentication results
    spf_result = Column(String(32), nullable=True)
    dkim_result = Column(String(32), nullable=True)
    dmarc_result = Column(String(32), nullable=True)
    auth_details = Column(JSON, nullable=True)

    # Cryptographic verification
    sha256_hash = Column(String(64), nullable=True)
    signature_valid = Column(Boolean, nullable=True)
    hmac_valid = Column(Boolean, nullable=True)
    replay_detected = Column(Boolean, default=False)
    crypto_details = Column(JSON, nullable=True)

    # Analysis results
    url_findings = Column(JSON, nullable=True)
    attachment_findings = Column(JSON, nullable=True)
    header_findings = Column(JSON, nullable=True)
    spoofing_findings = Column(JSON, nullable=True)

    # ML results
    ml_phishing_probability = Column(Float, nullable=True)
    ml_verdict = Column(String(32), nullable=True)
    ml_top_features = Column(JSON, nullable=True)

    # Risk scoring
    risk_score = Column(Float, nullable=True)
    risk_breakdown = Column(JSON, nullable=True)

    # Decision
    verdict = Column(Enum(Verdict), nullable=True)
    delivered = Column(Boolean, default=False)
    quarantined = Column(Boolean, default=False)
    warning_message = Column(Text, nullable=True)

    # Storage
    raw_email_encrypted = Column(LargeBinary, nullable=True)  # AES-256-GCM encrypted
    encryption_nonce = Column(LargeBinary, nullable=True)
    sanitized_html = Column(Text, nullable=True)

    # Pipeline timing (ms per stage)
    pipeline_timing = Column(JSON, nullable=True)

    # Educational explanation
    explanation = Column(JSON, nullable=True)

    # Attack simulation flag
    is_simulation = Column(Boolean, default=False)
    simulation_scenario = Column(String(64), nullable=True)

    logs = relationship("SecurityLog", back_populates="email")


# ─── Security Log ─────────────────────────────────────────────────────────────


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"), nullable=True)
    timestamp = Column(DateTime, server_default=func.now())
    event_type = Column(String(64), nullable=False)  # e.g. "PHISHING_DETECTED", "REPLAY_ATTACK"
    severity = Column(String(16), nullable=False)  # "INFO", "WARNING", "CRITICAL"
    stage = Column(String(64), nullable=True)  # pipeline stage name
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    source_ip = Column(String(64), nullable=True)

    email = relationship("EmailRecord", back_populates="logs")


# ─── Settings ─────────────────────────────────────────────────────────────────


class AppSettings(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(128), unique=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
