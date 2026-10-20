"""
PhishShield – Settings router.
Manage configurable thresholds and application settings.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user, require_admin
from backend.app.models import AppSettings, User
from backend.app.schemas import ThresholdUpdate

router = APIRouter(prefix="/settings", tags=["settings"])


def _get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(AppSettings).filter(AppSettings.key == key).first()
    return row.value if row else default


def _set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(AppSettings).filter(AppSettings.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSettings(key=key, value=value))
    db.commit()


@router.get("/thresholds")
async def get_thresholds(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return current risk score thresholds."""
    from backend.app.config import get_settings
    settings = get_settings()
    return {
        "threshold_suspicious": int(_get_setting(db, "threshold_suspicious", str(settings.threshold_suspicious))),
        "threshold_malicious": int(_get_setting(db, "threshold_malicious", str(settings.threshold_malicious))),
    }


@router.put("/thresholds")
async def update_thresholds(
    body: ThresholdUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update risk score thresholds (admin only)."""
    if body.threshold_suspicious >= body.threshold_malicious:
        raise HTTPException(
            status_code=400,
            detail="threshold_suspicious must be less than threshold_malicious",
        )
    _set_setting(db, "threshold_suspicious", str(body.threshold_suspicious))
    _set_setting(db, "threshold_malicious", str(body.threshold_malicious))
    return {"status": "updated", **body.model_dump()}
