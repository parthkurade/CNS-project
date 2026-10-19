"""
PhishShield – Keys router.
Manage Ed25519 / RSA-PSS / HMAC keys for partner gateways and signing.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import get_current_user, require_admin
from backend.app.models import RegisteredKey, User
from backend.app.schemas import KeyCreateRequest, KeyGenerateResponse, KeyOut
from backend.crypto.hmac_util import generate_hmac_key
from backend.crypto.signatures import (
    generate_ed25519_keypair,
    generate_rsa_pss_keypair,
)

router = APIRouter(prefix="/keys", tags=["keys"])


@router.get("/", response_model=list[KeyOut])
async def list_keys(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all registered public keys."""
    return db.query(RegisteredKey).order_by(RegisteredKey.created_at.desc()).all()


@router.post("/generate", response_model=KeyGenerateResponse)
async def generate_key(
    body: KeyCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    Generate a new keypair and register the public key.
    The private key (for Ed25519/RSA-PSS) is returned ONCE and never stored.
    For HMAC keys, the shared secret is returned ONCE.
    """
    private_pem: str | None = None
    public_pem: str
    hmac_secret_b64: str | None = None

    if body.key_type == "ED25519":
        private_pem, public_pem = generate_ed25519_keypair()
    elif body.key_type == "RSA_PSS":
        private_pem, public_pem = generate_rsa_pss_keypair(key_size=2048)
    elif body.key_type == "HMAC":
        raw_key = generate_hmac_key(32)
        hmac_secret_b64 = base64.urlsafe_b64encode(raw_key).decode()
        # For HMAC, store the key in public_key_pem field (it's a shared secret)
        public_pem = hmac_secret_b64
    else:
        raise HTTPException(status_code=400, detail="Unknown key type")

    record = RegisteredKey(
        label=body.label,
        domain=body.domain,
        key_type=body.key_type,
        public_key_pem=public_pem,
        is_active=True,
        created_by=admin.id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return KeyGenerateResponse(
        key=record,
        private_key_pem=private_pem,
        hmac_secret_b64=hmac_secret_b64,
    )


@router.post("/{key_id}/revoke")
async def revoke_key(
    key_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Revoke a registered key (marks it inactive)."""
    key = db.query(RegisteredKey).filter(RegisteredKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key.is_active = False
    key.revoked_at = datetime.now(UTC)
    db.commit()
    return {"status": "revoked", "key_id": key_id}


@router.delete("/{key_id}")
async def delete_key(
    key_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Permanently delete a registered key."""
    key = db.query(RegisteredKey).filter(RegisteredKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    db.delete(key)
    db.commit()
    return {"status": "deleted", "key_id": key_id}
