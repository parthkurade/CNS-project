"""
PhishShield – Simulation router.
POST /simulate/{scenario} – run an attack simulation against the real pipeline.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user
from backend.app.models import User
from backend.app.schemas import SimulationRequest, SimulationResult
from backend.simulation.scenarios import run_scenario

router = APIRouter(prefix="/simulate", tags=["simulation"])


@router.post("/{scenario}", response_model=SimulationResult)
async def run_simulation(
    scenario: str,
    body: SimulationRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    Run one of the 5 attack simulation scenarios through the real pipeline.

    Scenarios:
    - phishing   : Credential-harvesting phishing email
    - spoofing   : Forged sender domain (SPF/DKIM fail)
    - tampering  : Valid signed email modified in transit
    - replay     : Resend a previously-used signed nonce
    - mitm       : Forged/unsigned payload (TLS + sig checks catch it)
    - batch      : All scenarios × N iterations
    """
    valid_scenarios = {"phishing", "spoofing", "tampering", "replay", "mitm", "batch"}
    if scenario not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario. Choose from: {', '.join(sorted(valid_scenarios))}",
        )

    if not body.scenario:
        body.scenario = scenario

    try:
        result = await run_scenario(
            scenario=scenario,
            db=db,
            iterations=body.iterations,
            include_benign=body.include_benign,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {exc}") from exc

    return SimulationResult(**result)
