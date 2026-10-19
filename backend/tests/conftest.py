"""
PhishShield – pytest configuration and shared fixtures.
"""
from __future__ import annotations

import base64
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Use test env vars before importing settings
os.environ.setdefault("AES_MASTER_KEY", base64.urlsafe_b64encode(b"x" * 32).decode())
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-for-testing-only")
os.environ.setdefault("ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("ADMIN_PASSWORD", "TestPassword123!")
os.environ.setdefault("AUTH_DNS_MODE", "test")  # Use fake DNS in all tests
os.environ.setdefault("DISABLE_SMTP", "1")       # Skip SMTP server in tests

from datetime import UTC

from backend.app.database import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_phishshield.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create test tables once per session and seed admin."""
    from datetime import datetime

    from sqlalchemy.exc import IntegrityError

    from backend.app import models  # noqa: F401
    from backend.app.deps import hash_password
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        # Check if admin already exists (e.g. leftover from a previous run)
        existing = session.query(models.User).filter(
            models.User.email == "admin@example.com"
        ).first()
        if not existing:
            admin = models.User(
                email="admin@example.com",
                hashed_password=hash_password("TestPassword123!"),
                role=models.UserRole.ADMIN,
                is_active=True,
                created_at=datetime.now(UTC),
            )
            session.add(admin)
            session.commit()
    except IntegrityError:
        session.rollback()
    finally:
        session.close()
    yield
    Base.metadata.drop_all(bind=test_engine)
    try:
        if os.path.exists("test_phishshield.db"):
            os.remove("test_phishshield.db")
    except OSError:
        pass  # Windows may lock the file; it will be overwritten on next run



@pytest.fixture
def db():
    """Yield a fresh DB session for each test."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client():
    """FastAPI test client."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def auth_headers(client):
    """Return JWT auth headers for the admin user."""
    resp = client.post("/auth/login", json={
        "email": "admin@example.com",
        "password": "TestPassword123!",
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def master_key() -> bytes:
    return base64.urlsafe_b64decode(os.environ["AES_MASTER_KEY"] + "==")
