"""
PhishShield – Auth router.
POST /auth/login  – returns JWT access token
GET  /auth/me     – returns current user info
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.deps import create_access_token, get_current_user, verify_password
from backend.app.models import User
from backend.app.schemas import LoginRequest, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate with email and password.
    Returns a JWT bearer token.
    Rate limiting is applied at the middleware level.
    """
    user = db.query(User).filter(
        User.email == body.email,
        User.is_active == True,  # noqa: E712
    ).first()

    # Constant-time comparison: always call verify_password even if user not found
    # to prevent timing attacks
    dummy_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4L5b4q7L.u"
    password_hash = user.hashed_password if user else dummy_hash
    valid = verify_password(body.password, password_hash)

    if not user or not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Update last login
    user.last_login = datetime.now(UTC)
    db.commit()

    token = create_access_token({"sub": user.email, "role": user.role.value})
    return TokenResponse(access_token=token, role=user.role.value)


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return current_user
