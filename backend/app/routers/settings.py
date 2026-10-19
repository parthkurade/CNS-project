"""
PhishShield – Settings Router.
Manages risk thresholds and system settings.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user, require_admin
from backend.app.models import AppSettings, User
from backend.app.schemas import ThresholdUpdate

router = APIRouter(prefix="/settings", tags=["settings"])

DEFAULT_SUSPICIOUS = 41
DEFAULT_MALICIOUS = 71


def _get_setting_int(db: Session, key: str, default: int) -> int:
    rec = db.query(AppSettings).filter(AppSettings.key == key).first()
    if rec and rec.value:
        try:
            return int(rec.value)
        except ValueError:
            pass
    return default


def _set_setting(db: Session, key: str, value: str) -> None:
    rec = db.query(AppSettings).filter(AppSettings.key == key).first()
    if rec:
        rec.value = value
    else:
        rec = AppSettings(key=key, value=value)
        db.add(rec)
    db.commit()


@router.get("/thresholds")
async def get_thresholds(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Get current suspicious and malicious risk score thresholds."""
    suspicious = _get_setting_int(db, "threshold_suspicious", DEFAULT_SUSPICIOUS)
    malicious = _get_setting_int(db, "threshold_malicious", DEFAULT_MALICIOUS)
    return {
        "threshold_suspicious": suspicious,
        "threshold_malicious": malicious,
        "suspicious": suspicious,
        "malicious": malicious,
    }


@router.put("/thresholds")
async def update_thresholds(
    body: ThresholdUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update risk score thresholds (admin only)."""
    _set_setting(db, "threshold_suspicious", str(body.threshold_suspicious))
    _set_setting(db, "threshold_malicious", str(body.threshold_malicious))
    return {
        "threshold_suspicious": body.threshold_suspicious,
        "threshold_malicious": body.threshold_malicious,
        "suspicious": body.threshold_suspicious,
        "malicious": body.threshold_malicious,
    }
