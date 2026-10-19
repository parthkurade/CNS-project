"""
PhishShield – SHA-256 Hashing Utilities.
Provides deterministic message hashing and constant-time integrity verification.
"""
from __future__ import annotations

import hashlib
import hmac


def _to_bytes(data: bytes | str) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def sha256_hash(data: bytes | str) -> str:
    """Return lowercase hex SHA-256 digest of data (64 hex characters)."""
    return hashlib.sha256(_to_bytes(data)).hexdigest()


def sha256_hash_bytes(data: bytes | str) -> bytes:
    """Return raw 32-byte SHA-256 digest of data."""
    return hashlib.sha256(_to_bytes(data)).digest()


def verify_hash(data: bytes | str, expected_hex: str) -> bool:
    """Constant-time comparison of computed SHA-256 hash against expected hex string."""
    computed = sha256_hash(data)
    return hmac.compare_digest(computed.lower(), expected_hex.lower().strip())
