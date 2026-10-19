"""
PhishShield – FastAPI Application Entry Point.

Serves the API over HTTPS (TLS 1.2+).
Initialises DB, seeds admin user, wires all routers.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.app.config import get_settings
from backend.app.database import SessionLocal, init_db
from backend.app.deps import hash_password
from backend.app.models import User, UserRole
from backend.app.routers import auth, dashboard, emails, keys, logs, model, simulation
from backend.app.routers import settings as settings_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

app_settings = get_settings()

# ─── Rate limiter ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{app_settings.rate_limit_per_minute}/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup + shutdown."""
    # ── Startup ───────────────────────────────────────────────────────────────
    logger.info("PhishShield starting up...")
    init_db()
    _seed_admin()

    # Start SMTP server in background (set DISABLE_SMTP=1 to skip, e.g. in tests)
    smtp_task = None
    if not os.environ.get("DISABLE_SMTP"):
        try:
            from backend.smtp.ingest import run_smtp_server
            smtp_task = asyncio.create_task(run_smtp_server())
            logger.info("SMTP ingest started on port %d", app_settings.smtp_port)
        except Exception as exc:
            logger.warning("SMTP server could not start: %s", exc)

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    if smtp_task:
        smtp_task.cancel()
        try:
            await smtp_task
        except asyncio.CancelledError:
            pass
    logger.info("PhishShield shutdown complete")


def _seed_admin() -> None:
    """Create the default admin user if they don't exist."""
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == app_settings.admin_email).first()
        if not existing:
            admin = User(
                email=app_settings.admin_email,
                hashed_password=hash_password(app_settings.admin_password),
                role=UserRole.ADMIN,
                is_active=True,
                created_at=datetime.now(UTC),
            )
            db.add(admin)
            db.commit()
            logger.info("Seeded admin user: %s", app_settings.admin_email)
        else:
            if app_settings.admin_password:
                existing.hashed_password = hash_password(app_settings.admin_password)
                existing.is_active = True
                db.commit()
            logger.info("Admin user updated/verified: %s", app_settings.admin_email)
    finally:
        db.close()


# ─── App factory ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishShield API",
    description="Secure Email Gateway — Team ZeroTrace, SPIT Mumbai",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Rate limiting ──────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://localhost:5173",
        "http://127.0.0.1:5173",
        "https://127.0.0.1:5173",
        "http://localhost:3000",
        "https://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Security headers middleware ────────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' http://localhost:8443 http://127.0.0.1:8443 https://localhost:8443"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(emails.router)
app.include_router(dashboard.router)
app.include_router(keys.router)
app.include_router(logs.router)
app.include_router(model.router)
app.include_router(settings_router.router)
app.include_router(simulation.router)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "PhishShield", "version": "1.0.0"}


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import ssl as ssl_module

    ssl_kwargs: dict = {}
    if os.path.exists(app_settings.tls_cert_file) and os.path.exists(app_settings.tls_key_file):
        ssl_kwargs = {
            "ssl_certfile": app_settings.tls_cert_file,
            "ssl_keyfile": app_settings.tls_key_file,
            "ssl_version": ssl_module.PROTOCOL_TLS_SERVER,
        }
        logger.info("TLS enabled: %s", app_settings.tls_cert_file)
    else:
        logger.warning(
            "TLS certs not found — running in HTTP mode. "
            "Run scripts/gen_certs.ps1 to generate certificates."
        )

    uvicorn.run(
        "backend.app.main:app",
        host=app_settings.api_host,
        port=app_settings.api_port,
        reload=True,
        **ssl_kwargs,
    )
