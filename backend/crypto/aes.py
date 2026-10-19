"""
PhishShield – AES-256-GCM encryption / decryption.

Uses the `cryptography` library exclusively (no custom primitives).
Each encryption operation uses a fresh random 96-bit nonce.
Key derivation uses HKDF-SHA256 from the master key.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ─── Key derivation ───────────────────────────────────────────────────────────

def derive_key(master_key: bytes, info: bytes, salt: bytes | None = None) -> bytes:
    """
    Derive a 256-bit AES key from the master key using HKDF-SHA256.

    Args:
        master_key: 32-byte master key (from AES_MASTER_KEY env var).
        info:       Context string differentiating derived keys (e.g. b"email-storage").
        salt:       Optional random salt.  If None, HKDF uses a zero-salt.

    Returns:
        32-byte derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_key)


# ─── Encryption / Decryption ──────────────────────────────────────────────────

def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        plaintext:       Data to encrypt.
        key:             32-byte AES-256 key.
        associated_data: Additional authenticated data (AAD) – authenticated but not encrypted.

    Returns:
        Tuple of (ciphertext_with_tag, nonce).
        The 16-byte GCM authentication tag is appended to ciphertext by the library.
    """
    if len(key) != 32:
        raise ValueError("AES key must be exactly 32 bytes for AES-256")
    nonce = os.urandom(12)  # 96-bit nonce per NIST SP 800-38D recommendation
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data or None)
    return ciphertext, nonce


def decrypt(ciphertext: bytes, nonce: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Args:
        ciphertext:      Encrypted data (with appended GCM tag).
        nonce:           96-bit nonce used during encryption.
        key:             32-byte AES-256 key.
        associated_data: Must match what was used during encryption.

    Returns:
        Plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: if authentication fails (tampered data).
    """
    if len(key) != 32:
        raise ValueError("AES key must be exactly 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data or None)


# ─── Convenience wrappers ─────────────────────────────────────────────────────

def encrypt_email(raw_email: bytes, master_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt a raw email for at-rest storage.
    Uses HKDF to derive a storage-specific key from the master key.
    """
    storage_key = derive_key(master_key, b"phishshield-email-storage")
    return encrypt(raw_email, storage_key, associated_data=b"phishshield-email")


def decrypt_email(ciphertext: bytes, nonce: bytes, master_key: bytes) -> bytes:
    """Decrypt a stored email."""
    storage_key = derive_key(master_key, b"phishshield-email-storage")
    return decrypt(ciphertext, nonce, storage_key, associated_data=b"phishshield-email")
