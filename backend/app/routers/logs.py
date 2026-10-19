"""
PhishShield – Security Logs Router.
Query, filter, inspect, and export system security logs.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user
from backend.app.models import SecurityLog, User
from backend.app.schemas import LogEntry

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/", response_model=list[LogEntry])
async def list_logs(
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    stage: str | None = Query(default=None),
    search: str | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Retrieve security logs with filtering and pagination."""
    query = db.query(SecurityLog)

    if severity:
        query = query.filter(SecurityLog.severity == severity.upper())

    if event_type:
        query = query.filter(SecurityLog.event_type == event_type)

    if stage:
        query = query.filter(SecurityLog.stage == stage)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (SecurityLog.message.ilike(search_term))
            | (SecurityLog.event_type.ilike(search_term))
            | (SecurityLog.source_ip.ilike(search_term))
        )

    return query.order_by(SecurityLog.timestamp.desc()).offset(skip).limit(limit).all()


@router.get("/export/json")
async def export_json(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export all security logs as JSON."""
    records = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).all()
    logs_data = [
        {
            "id": r.id,
            "email_id": r.email_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "event_type": r.event_type,
            "severity": r.severity,
            "stage": r.stage,
            "message": r.message,
            "details": r.details,
            "source_ip": r.source_ip,
        }
        for r in records
    ]
    return Response(
        content=json.dumps(logs_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="phishshield_logs.json"'},
    )
