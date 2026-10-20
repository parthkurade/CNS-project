"""
PhishShield – Logs router.
Searchable, filterable security event log with CSV/JSON export.
"""
from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user
from backend.app.models import SecurityLog, User
from backend.app.schemas import LogEntry

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/", response_model=list[LogEntry])
async def list_logs(
    severity: str | None = Query(None),
    event_type: str | None = Query(None),
    stage: str | None = Query(None),
    search: str | None = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return security log entries with filtering."""
    q = db.query(SecurityLog)
    if severity:
        q = q.filter(SecurityLog.severity == severity.upper())
    if event_type:
        q = q.filter(SecurityLog.event_type.ilike(f"%{event_type}%"))
    if stage:
        q = q.filter(SecurityLog.stage == stage)
    if search:
        q = q.filter(
            or_(
                SecurityLog.message.ilike(f"%{search}%"),
                SecurityLog.event_type.ilike(f"%{search}%"),
            )
        )
    return q.order_by(desc(SecurityLog.timestamp)).offset(skip).limit(limit).all()


@router.get("/export/csv")
async def export_logs_csv(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export all log entries as CSV."""
    logs = db.query(SecurityLog).order_by(desc(SecurityLog.timestamp)).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp", "event_type", "severity", "stage", "message", "source_ip", "email_id"])
    for log in logs:
        writer.writerow([
            log.id, log.timestamp, log.event_type, log.severity,
            log.stage, log.message, log.source_ip, log.email_id,
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishshield_logs.csv"},
    )


@router.get("/export/json")
async def export_logs_json(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export all log entries as JSON."""
    logs = db.query(SecurityLog).order_by(desc(SecurityLog.timestamp)).all()
    data = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "event_type": log.event_type,
            "severity": log.severity,
            "stage": log.stage,
            "message": log.message,
            "source_ip": log.source_ip,
            "email_id": log.email_id,
            "details": log.details,
        }
        for log in logs
    ]
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=phishshield_logs.json"},
    )
