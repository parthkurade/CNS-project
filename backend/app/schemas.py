"""
PhishShield – Pydantic schemas for request/response validation.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field

# ─── Auth ────────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Email Analysis ───────────────────────────────────────────────────────────


class EmailAnalysisRequest(BaseModel):
    """Raw RFC 2822 email bytes (base64-encoded) for analysis."""
    raw_email_b64: str
    source_ip: str | None = None
    tls_info: dict[str, Any] | None = None


class URLAnalysisRequest(BaseModel):
    url: str = Field(max_length=2048)


class RiskBreakdown(BaseModel):
    auth_score: float
    url_score: float
    attachment_score: float
    ml_score: float
    header_score: float
    crypto_score: float
    total: float
    hard_override: bool = False
    override_reason: str | None = None


class EmailSummary(BaseModel):
    id: int
    message_id: str | None
    received_at: datetime
    sender_address: str | None
    subject: str | None
    verdict: str | None
    risk_score: float | None
    tls_established: bool
    is_simulation: bool

    model_config = {"from_attributes": True}


class EmailDetail(BaseModel):
    id: int
    message_id: str | None
    received_at: datetime
    sender_address: str | None
    sender_display_name: str | None
    reply_to: str | None
    subject: str | None
    recipients: list[str] | None
    tls_protocol: str | None
    tls_cipher: str | None
    tls_established: bool
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str | None
    auth_details: dict | None
    sha256_hash: str | None
    signature_valid: bool | None
    hmac_valid: bool | None
    replay_detected: bool
    crypto_details: dict | None
    url_findings: dict | None
    attachment_findings: dict | None
    header_findings: dict | None
    spoofing_findings: dict | None
    ml_phishing_probability: float | None
    ml_verdict: str | None
    ml_top_features: list | None
    risk_score: float | None
    risk_breakdown: dict | None
    verdict: str | None
    delivered: bool
    quarantined: bool
    warning_message: str | None
    sanitized_html: str | None
    pipeline_timing: dict | None
    explanation: dict | None
    is_simulation: bool
    simulation_scenario: str | None

    model_config = {"from_attributes": True}


# ─── Keys ────────────────────────────────────────────────────────────────────


class KeyCreateRequest(BaseModel):
    label: str = Field(max_length=255)
    domain: str = Field(max_length=255)
    key_type: str = Field(pattern="^(ED25519|RSA_PSS|HMAC)$")


class KeyOut(BaseModel):
    id: int
    label: str
    domain: str
    key_type: str
    public_key_pem: str
    is_active: bool
    created_at: datetime
    revoked_at: datetime | None

    model_config = {"from_attributes": True}


class KeyGenerateResponse(BaseModel):
    """Returned once on key creation – private key shown only this once."""
    key: KeyOut
    private_key_pem: str | None = None  # None for HMAC keys
    hmac_secret_b64: str | None = None  # for HMAC keys


# ─── Dashboard ───────────────────────────────────────────────────────────────


class DashboardStats(BaseModel):
    total_emails: int
    legitimate: int
    suspicious: int
    malicious: int
    simulations: int
    avg_risk_score: float
    detections_today: int
    top_attack_types: list[dict]
    layer_catch_rates: dict[str, float]
    recent_verdicts: list[dict]


# ─── Simulation ──────────────────────────────────────────────────────────────


class SimulationRequest(BaseModel):
    scenario: str | None = Field(default=None, pattern="^(phishing|spoofing|tampering|replay|mitm|batch)$")
    iterations: int = Field(default=1, ge=1, le=50)
    include_benign: bool = True


class SimulationResult(BaseModel):
    scenario: str
    iterations: int
    results: Any
    detection_rate: float
    false_positive_rate: float | None = None
    avg_latency_ms: float
    summary: dict



# ─── Log ─────────────────────────────────────────────────────────────────────


class LogEntry(BaseModel):
    id: int
    email_id: int | None
    timestamp: datetime
    event_type: str
    severity: str
    stage: str | None
    message: str
    details: dict | None
    source_ip: str | None

    model_config = {"from_attributes": True}


# ─── Settings ────────────────────────────────────────────────────────────────


class ThresholdUpdate(BaseModel):
    threshold_suspicious: int = Field(ge=1, le=99)
    threshold_malicious: int = Field(ge=2, le=100)


# ─── ML Model ────────────────────────────────────────────────────────────────


class ModelMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: list[list[int]]
    training_samples: int = 2441
    test_samples: int = 611
    top_features: list[dict] = Field(default_factory=list)
    trained_at: str | None = None
    dataset_source: str = "SpamAssassin Public Corpus"
