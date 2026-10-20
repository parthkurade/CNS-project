"""
PhishShield – Emails router.
Handles inbox, quarantine, and email detail views.
"""
from __future__ import annotations

import base64
import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from backend.app.config import get_settings
from backend.app.database import get_db
from backend.app.deps import get_current_user, require_admin
from backend.app.models import EmailRecord, User, Verdict
from backend.app.pipeline import process_email
from backend.app.schemas import EmailAnalysisRequest, EmailDetail, EmailSummary
from backend.crypto.aes import decrypt_email

settings = get_settings()
router = APIRouter(prefix="/emails", tags=["emails"])


@router.get("/", response_model=list[EmailSummary])
async def list_emails(
    verdict: str | None = Query(None),
    search: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    quarantine: bool | None = Query(None),
    is_simulation: bool | None = Query(None),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List emails with filtering and pagination."""
    q = db.query(EmailRecord)
    if verdict:
        q = q.filter(EmailRecord.verdict == verdict.upper())
    if quarantine is not None:
        q = q.filter(EmailRecord.quarantined == quarantine)
    if is_simulation is not None:
        q = q.filter(EmailRecord.is_simulation == is_simulation)
    if search:
        q = q.filter(
            or_(
                EmailRecord.sender_address.ilike(f"%{search}%"),
                EmailRecord.subject.ilike(f"%{search}%"),
                EmailRecord.message_id.ilike(f"%{search}%"),
            )
        )
    q = q.order_by(desc(EmailRecord.received_at))
    return q.offset(skip).limit(limit).all()


@router.get("/{email_id}", response_model=EmailDetail)
async def get_email(
    email_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Get detailed analysis of a specific email."""
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    return record


@router.get("/{email_id}/raw")
async def get_raw_email(
    email_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin-only: decrypt and return the raw email bytes."""
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    if not record.raw_email_encrypted or not record.encryption_nonce:
        raise HTTPException(status_code=404, detail="Raw email not available")
    try:
        raw = decrypt_email(
            record.raw_email_encrypted,
            record.encryption_nonce,
            settings.aes_master_key_bytes,
        )
        return Response(content=raw, media_type="message/rfc822")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {exc}") from exc


@router.post("/{email_id}/release")
async def release_quarantined(
    email_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin: release a quarantined email to the inbox."""
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    record.quarantined = False
    record.delivered = True
    record.verdict = Verdict.SUSPICIOUS
    record.warning_message = "⚠ This email was manually released from quarantine by an administrator."
    db.commit()
    return {"status": "released", "email_id": email_id}


@router.delete("/{email_id}")
async def delete_email(
    email_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin: permanently delete an email record."""
    record = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")
    db.delete(record)
    db.commit()
    return {"status": "deleted", "email_id": email_id}


@router.post("/analyze")
async def analyze_email(
    body: EmailAnalysisRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Submit a raw email (base64-encoded) for analysis through the full pipeline."""
    try:
        raw_email = base64.b64decode(body.raw_email_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid base64: {exc}") from exc

    record = await process_email(
        raw_email=raw_email,
        db=db,
        source_ip=body.source_ip,
        tls_info=body.tls_info,
    )
    return {"email_id": record.id, "verdict": record.verdict.value, "risk_score": record.risk_score}


@router.get("/export/csv")
async def export_csv(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export all email records as CSV."""
    records = db.query(EmailRecord).order_by(desc(EmailRecord.received_at)).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "received_at", "sender", "subject", "verdict", "risk_score",
        "spf", "dkim", "dmarc", "replay", "is_simulation",
    ])
    for r in records:
        writer.writerow([
            r.id, r.received_at, r.sender_address, r.subject,
            r.verdict.value if r.verdict else "",
            r.risk_score, r.spf_result, r.dkim_result, r.dmarc_result,
            r.replay_detected, r.is_simulation,
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishshield_emails.csv"},
    )


@router.get("/export/json")
async def export_json(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export all email records as JSON."""
    records = db.query(EmailRecord).order_by(desc(EmailRecord.received_at)).all()
    data = [
        {
            "id": r.id,
            "received_at": r.received_at.isoformat() if r.received_at else None,
            "sender": r.sender_address,
            "subject": r.subject,
            "verdict": r.verdict.value if r.verdict else None,
            "risk_score": r.risk_score,
            "spf": r.spf_result,
            "dkim": r.dkim_result,
            "dmarc": r.dmarc_result,
            "replay": r.replay_detected,
            "is_simulation": r.is_simulation,
        }
        for r in records
    ]
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=phishshield_emails.json"},
    )
