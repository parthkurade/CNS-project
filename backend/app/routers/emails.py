"""
PhishShield – Emails Router.
Search, preview, release, export, and delete processed emails.
"""
from __future__ import annotations

import base64
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user, require_admin
from backend.app.models import EmailRecord, User
from backend.app.pipeline import process_email
from backend.app.schemas import EmailAnalysisRequest

router = APIRouter(prefix="/emails", tags=["emails"])


@router.post("/analyze")
async def analyze_email(
    body: EmailAnalysisRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Analyze a raw RFC 2822 email payload and run it through PhishShield."""
    try:
        raw_bytes = base64.b64decode(body.raw_email_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {exc}")

    record = await process_email(
        raw_email=raw_bytes,
        db=db,
        source_ip=body.source_ip,
        tls_info=body.tls_info,
    )
    return _serialize_email_detail(record)



def _serialize_email_summary(r: EmailRecord) -> dict:
    return {
        "id": r.id,
        "message_id": r.message_id,
        "sender": r.sender_address or "",
        "sender_address": r.sender_address or "",
        "subject": r.subject or "(No Subject)",
        "received_at": r.received_at.isoformat() if r.received_at else None,
        "verdict": r.verdict.value if r.verdict else "LEGITIMATE",
        "risk_score": r.risk_score or 0.0,
        "tls_valid": bool(r.tls_established),
        "tls_established": bool(r.tls_established),
        "quarantined": bool(r.quarantined),
        "delivered": bool(r.delivered),
        "warned": bool(r.warning_message is not None and len(r.warning_message) > 0),
        "is_simulation": bool(r.is_simulation),
    }


def _serialize_email_detail(r: EmailRecord) -> dict:
    d = _serialize_email_summary(r)
    d.update({
        "sender_display_name": r.sender_display_name,
        "reply_to": r.reply_to,
        "recipients": r.recipients or [],
        "tls_protocol": r.tls_protocol,
        "tls_cipher": r.tls_cipher,
        "spf_result": r.spf_result,
        "dkim_result": r.dkim_result,
        "dmarc_result": r.dmarc_result,
        "auth_details": r.auth_details or {},
        "sha256_hash": r.sha256_hash,
        "signature_valid": r.signature_valid,
        "hmac_valid": r.hmac_valid,
        "replay_detected": bool(r.replay_detected),
        "crypto_details": r.crypto_details or {},
        "url_findings": r.url_findings or {},
        "attachment_findings": r.attachment_findings or {},
        "header_findings": r.header_findings or {},
        "spoofing_findings": r.spoofing_findings or {},
        "ml_phishing_probability": r.ml_phishing_probability,
        "ml_verdict": r.ml_verdict,
        "ml_top_features": r.ml_top_features or [],
        "risk_breakdown": r.risk_breakdown or {},
        "warning_message": r.warning_message,
        "sanitized_html": r.sanitized_html or "<p>(No HTML content)</p>",
        "pipeline_timing": r.pipeline_timing or {},
        "explanation": r.explanation or {},
        "simulation_scenario": r.simulation_scenario,
    })
    return d


@router.get("/")
async def list_emails(
    search: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    quarantine: bool | None = Query(default=None),
    is_simulation: bool | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List emails with filtering and pagination."""
    query = db.query(EmailRecord)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (EmailRecord.subject.ilike(search_term))
            | (EmailRecord.sender_address.ilike(search_term))
            | (EmailRecord.sender_display_name.ilike(search_term))
        )

    if verdict:
        query = query.filter(EmailRecord.verdict == verdict.upper())

    if quarantine is not None:
        query = query.filter(EmailRecord.quarantined == quarantine)

    if is_simulation is not None:
        query = query.filter(EmailRecord.is_simulation == is_simulation)

    records = query.order_by(EmailRecord.received_at.desc()).offset(skip).limit(limit).all()
    return [_serialize_email_summary(r) for r in records]


@router.get("/export/csv")
async def export_csv(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export all email records as CSV."""
    records = db.query(EmailRecord).order_by(EmailRecord.received_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID",
        "Received At",
        "Sender",
        "Subject",
        "Verdict",
        "Risk Score",
        "SPF",
        "DKIM",
        "DMARC",
        "Quarantined",
        "Is Simulation",
    ])

    for r in records:
        writer.writerow([
            r.id,
            r.received_at.isoformat() if r.received_at else "",
            r.sender_address or "",
            r.subject or "",
            r.verdict.value if r.verdict else "",
            r.risk_score or 0.0,
            r.spf_result or "",
            r.dkim_result or "",
            r.dmarc_result or "",
            r.quarantined,
            r.is_simulation,
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="phishshield_emails.csv"'},
    )


@router.get("/{email_id}")
async def get_email(
    email_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Retrieve full analysis details for an email."""
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email record not found")
    return _serialize_email_detail(record)


@router.post("/{email_id}/release")
async def release_email(
    email_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Release an email from quarantine and mark it delivered."""
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email record not found")
    record.quarantined = False
    record.delivered = True
    db.commit()
    return {"status": "released", "email_id": email_id}


@router.delete("/{email_id}")
async def delete_email(
    email_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Permanently delete an email record."""
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email record not found")
    db.delete(record)
    db.commit()
    return {"status": "deleted", "email_id": email_id}
