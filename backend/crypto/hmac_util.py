"""
PhishShield – HMAC-SHA256 utilities.

Provides constant-time MAC comparison using hmac.compare_digest.
Also provides password/key derivation helpers (PBKDF2-HMAC-SHA256).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os


def hmac_sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Compute HMAC-SHA256 of a message.

    Args:
        message:    Bytes to authenticate.
        secret_key: Shared secret key (any length; longer is better).

    Returns:
        32-byte HMAC-SHA256 digest.
    """
    return hmac.new(secret_key, message, hashlib.sha256).digest()


def hmac_verify(message: bytes, secret_key: bytes, expected_mac: bytes) -> bool:
    """
    Verify an HMAC-SHA256 MAC using constant-time comparison.

    This prevents timing attacks – uses hmac.compare_digest() which is
    guaranteed to run in constant time regardless of where the mismatch is.

    Args:
        message:      Original message bytes.
        secret_key:   Shared secret key.
        expected_mac: MAC to compare against.

    Returns:
        True if the MAC is valid, False otherwise.
    """
    computed = hmac_sign(message, secret_key)
    # hmac.compare_digest is constant-time (Python 3.3+)
    return hmac.compare_digest(computed, expected_mac)


def generate_hmac_key(length: int = 32) -> bytes:
    """Generate a cryptographically random HMAC key."""
    return os.urandom(length)


def generate_hmac_key_b64(length: int = 32) -> str:
    """Generate a random HMAC key and return it as URL-safe base64."""
    return base64.urlsafe_b64encode(generate_hmac_key(length)).decode()


# ─── PBKDF2-HMAC-SHA256 key derivation ───────────────────────────────────────

def pbkdf2_derive(
    password: bytes,
    salt: bytes | None = None,
    iterations: int = 600_000,  # NIST 2023 recommendation for SHA-256
    length: int = 32,
) -> tuple[bytes, bytes]:
    """
    Derive a key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password:   Password/passphrase bytes.
        salt:       Random salt (16 bytes recommended).  Generated if None.
        iterations: Iteration count (higher = slower = more secure).
        length:     Output key length in bytes.

    Returns:
        Tuple of (derived_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=length)
    return dk, salt
