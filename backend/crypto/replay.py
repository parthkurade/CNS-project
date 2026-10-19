"""
PhishShield – Replay Attack Protection.

Every signed message must carry:
  - A unique nonce  (UUID4 or random hex)
  - A timestamp     (ISO-8601 UTC)

The NonceCache checks both:
  1. Timestamp is within ±REPLAY_TIMESTAMP_WINDOW_SECONDS of now.
  2. Nonce has not been seen before (stored in DB with TTL).

This prevents an attacker from capturing and replaying valid signed messages.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from backend.app.config import get_settings
from backend.app.models import UsedNonce

settings = get_settings()


# ─── Nonce generation ─────────────────────────────────────────────────────────


def generate_nonce() -> str:
    """Generate a cryptographically random nonce (UUID4)."""
    return str(uuid.uuid4())


def current_timestamp() -> str:
    """Return the current UTC time as ISO-8601 string."""
    return datetime.now(UTC).isoformat()


# ─── Nonce Cache (database-backed, persistent across restarts) ────────────────


class NonceCache:
    """
    Database-backed nonce cache for replay protection.

    Uses the UsedNonce table to persist nonces; expired entries can be
    pruned periodically.  This approach survives service restarts, unlike
    an in-memory cache.
    """

    def __init__(self, db: Session, window_seconds: int | None = None):
        self.db = db
        self.window = window_seconds or settings.replay_timestamp_window_seconds

    def check_and_consume(
        self,
        nonce: str,
        message_timestamp: str,
        message_id: str | None = None,
    ) -> tuple[bool, str]:
        """
        Validate a nonce+timestamp pair and mark it consumed.

        Args:
            nonce:             Unique nonce from the message.
            message_timestamp: ISO-8601 UTC timestamp from the message.
            message_id:        Optional message identifier for logging.

        Returns:
            Tuple of (is_valid: bool, reason: str).
            is_valid=True means the message is fresh and the nonce is new.
        """
        # ── 1. Validate timestamp ─────────────────────────────────────────────
        try:
            msg_time = datetime.fromisoformat(message_timestamp.replace("Z", "+00:00"))
            if msg_time.tzinfo is None:
                msg_time = msg_time.replace(tzinfo=UTC)
        except ValueError:
            return False, f"Invalid timestamp format: {message_timestamp!r}"

        now = datetime.now(UTC)
        delta = abs((now - msg_time).total_seconds())
        if delta > self.window:
            return False, (
                f"Timestamp too old or too far in future: "
                f"delta={delta:.1f}s, window={self.window}s"
            )

        # ── 2. Check for replay (nonce already used) ──────────────────────────
        existing = self.db.query(UsedNonce).filter(UsedNonce.nonce == nonce).first()
        if existing:
            return False, f"Replay detected: nonce '{nonce}' was already used at {existing.used_at}"

        # ── 3. Record nonce as used ────────────────────────────────────────────
        expires = now + timedelta(seconds=self.window * 2)  # keep for 2× window
        record = UsedNonce(nonce=nonce, message_id=message_id, expires_at=expires)
        self.db.add(record)
        self.db.commit()

        return True, "OK"

    def purge_expired(self) -> int:
        """Remove expired nonce entries.  Call periodically to keep the table small."""
        now = datetime.now(UTC)
        deleted = self.db.query(UsedNonce).filter(UsedNonce.expires_at < now).delete()
        self.db.commit()
        return deleted
