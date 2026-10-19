"""
Tests for the replay attack protection (nonce cache).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.crypto.replay import NonceCache, current_timestamp, generate_nonce


class TestNonceCache:
    """Database-backed nonce cache tests."""

    def test_fresh_nonce_accepted(self, db):
        cache = NonceCache(db, window_seconds=300)
        nonce = generate_nonce()
        timestamp = current_timestamp()
        valid, reason = cache.check_and_consume(nonce, timestamp)
        assert valid, f"Should accept fresh nonce: {reason}"

    def test_replay_rejected(self, db):
        cache = NonceCache(db, window_seconds=300)
        nonce = generate_nonce()
        timestamp = current_timestamp()
        # First use: OK
        valid1, _ = cache.check_and_consume(nonce, timestamp)
        assert valid1
        # Second use: REPLAY
        valid2, reason = cache.check_and_consume(nonce, timestamp)
        assert not valid2
        assert "already used" in reason.lower() or "replay" in reason.lower()

    def test_stale_timestamp_rejected(self, db):
        cache = NonceCache(db, window_seconds=60)
        nonce = generate_nonce()
        # Timestamp 10 minutes old (outside 60-second window)
        old_ts = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
        valid, reason = cache.check_and_consume(nonce, old_ts)
        assert not valid
        assert "timestamp" in reason.lower() or "old" in reason.lower()

    def test_future_timestamp_rejected(self, db):
        cache = NonceCache(db, window_seconds=60)
        nonce = generate_nonce()
        future_ts = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
        valid, reason = cache.check_and_consume(nonce, future_ts)
        assert not valid

    def test_different_nonces_both_accepted(self, db):
        cache = NonceCache(db, window_seconds=300)
        ts = current_timestamp()
        n1 = generate_nonce()
        n2 = generate_nonce()
        assert n1 != n2
        v1, _ = cache.check_and_consume(n1, ts)
        v2, _ = cache.check_and_consume(n2, ts)
        assert v1
        assert v2

    def test_invalid_timestamp_format_rejected(self, db):
        cache = NonceCache(db, window_seconds=300)
        nonce = generate_nonce()
        valid, reason = cache.check_and_consume(nonce, "not-a-timestamp")
        assert not valid
        assert "format" in reason.lower() or "invalid" in reason.lower()

    def test_generate_nonce_is_unique(self):
        nonces = {generate_nonce() for _ in range(1000)}
        assert len(nonces) == 1000

    def test_purge_expired(self, db):
        cache = NonceCache(db, window_seconds=300)
        # Add a nonce with a current timestamp (will be kept)
        nonce = generate_nonce()
        cache.check_and_consume(nonce, current_timestamp())
        # Manually expire it by manipulating the DB
        from datetime import datetime, timedelta

        from backend.app.models import UsedNonce
        record = db.query(UsedNonce).filter(UsedNonce.nonce == nonce).first()
        if record:
            record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()
        deleted = cache.purge_expired()
        assert deleted >= 1
