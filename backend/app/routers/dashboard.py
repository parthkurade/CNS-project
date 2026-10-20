"""
PhishShield – Dashboard router.
Returns aggregated statistics for the dashboard UI.
"""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user
from backend.app.models import EmailRecord, User, Verdict
from backend.app.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_stats(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return aggregated dashboard statistics."""
    total = db.query(func.count(EmailRecord.id)).scalar() or 0
    legit = db.query(func.count(EmailRecord.id)).filter(EmailRecord.verdict == Verdict.LEGITIMATE).scalar() or 0
    susp = db.query(func.count(EmailRecord.id)).filter(EmailRecord.verdict == Verdict.SUSPICIOUS).scalar() or 0
    mal = db.query(func.count(EmailRecord.id)).filter(EmailRecord.verdict == Verdict.MALICIOUS).scalar() or 0
    sims = db.query(func.count(EmailRecord.id)).filter(EmailRecord.is_simulation == True).scalar() or 0  # noqa: E712

    avg_score = db.query(func.avg(EmailRecord.risk_score)).scalar() or 0.0

    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    detections_today = (
        db.query(func.count(EmailRecord.id))
        .filter(
            EmailRecord.verdict == Verdict.MALICIOUS,
            EmailRecord.received_at >= today_start,
        )
        .scalar()
        or 0
    )

    # Top attack types from simulation scenarios
    sim_records = (
        db.query(EmailRecord.simulation_scenario)
        .filter(EmailRecord.is_simulation == True)  # noqa: E712
        .all()
    )
    scenario_counts = Counter(r[0] for r in sim_records if r[0])
    top_attack_types = [
        {"scenario": k, "count": v}
        for k, v in scenario_counts.most_common(5)
    ]

    # Per-layer catch rates (what % of malicious emails were caught by each layer)
    mal_records = (
        db.query(EmailRecord)
        .filter(EmailRecord.verdict == Verdict.MALICIOUS)
        .all()
    )
    layer_counts = {
        "spf_fail": 0,
        "dkim_fail": 0,
        "dmarc_fail": 0,
        "replay": 0,
        "signature_fail": 0,
        "ml_detected": 0,
        "url_risk": 0,
        "attachment_risk": 0,
    }
    n_mal = len(mal_records)
    for r in mal_records:
        if r.spf_result and r.spf_result != "pass":
            layer_counts["spf_fail"] += 1
        if r.dkim_result and r.dkim_result != "pass":
            layer_counts["dkim_fail"] += 1
        if r.dmarc_result and r.dmarc_result != "pass":
            layer_counts["dmarc_fail"] += 1
        if r.replay_detected:
            layer_counts["replay"] += 1
        if r.signature_valid is False:
            layer_counts["signature_fail"] += 1
        if r.ml_phishing_probability and r.ml_phishing_probability > 0.5:
            layer_counts["ml_detected"] += 1
        findings = r.url_findings or {}
        if findings.get("risk_score", 0) > 50:
            layer_counts["url_risk"] += 1
        findings = r.attachment_findings or {}
        if findings.get("risk_score", 0) > 50:
            layer_counts["attachment_risk"] += 1

    layer_catch_rates = {
        k: round((v / n_mal * 100), 1) if n_mal > 0 else 0.0
        for k, v in layer_counts.items()
    }

    # Recent verdicts (last 20)
    recent = (
        db.query(EmailRecord)
        .order_by(EmailRecord.received_at.desc())
        .limit(20)
        .all()
    )
    recent_verdicts = [
        {
            "id": r.id,
            "sender": r.sender_address,
            "subject": r.subject,
            "verdict": r.verdict.value if r.verdict else None,
            "risk_score": r.risk_score,
            "received_at": r.received_at.isoformat() if r.received_at else None,
        }
        for r in recent
    ]

    return DashboardStats(
        total_emails=total,
        legitimate=legit,
        suspicious=susp,
        malicious=mal,
        simulations=sims,
        avg_risk_score=round(float(avg_score), 2),
        detections_today=detections_today,
        top_attack_types=top_attack_types,
        layer_catch_rates=layer_catch_rates,
        recent_verdicts=recent_verdicts,
    )


@router.get("/timeline")
async def get_timeline(
    days: int = 7,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return verdict counts per day for the last N days."""
    since = datetime.now(UTC) - timedelta(days=days)
    records = (
        db.query(EmailRecord)
        .filter(EmailRecord.received_at >= since)
        .all()
    )
    # Group by date
    by_date: dict[str, dict] = {}
    for r in records:
        date_str = r.received_at.strftime("%Y-%m-%d") if r.received_at else "unknown"
        if date_str not in by_date:
            by_date[date_str] = {"date": date_str, "legitimate": 0, "suspicious": 0, "malicious": 0}
        v = r.verdict.value.lower() if r.verdict else "unknown"
        if v in by_date[date_str]:
            by_date[date_str][v] += 1
    return sorted(by_date.values(), key=lambda x: x["date"])


@router.get("/risk-histogram")
async def risk_histogram(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return risk score distribution in buckets of 10."""
    records = db.query(EmailRecord.risk_score).filter(EmailRecord.risk_score.isnot(None)).all()
    buckets = [0] * 10
    for (score,) in records:
        idx = min(int(score // 10), 9)
        buckets[idx] += 1
    return [
        {"range": f"{i*10}-{i*10+9}", "count": buckets[i]}
        for i in range(10)
    ]
