"""
PhishShield – Digital Signature support.

Supports:
  • Ed25519   (preferred – fast, small keys, strong security)
  • RSA-PSS   (2048-bit minimum, SHA-256 hash, MGF1-SHA256 mask)

All using the `cryptography` library exclusively.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

# ─── Ed25519 ──────────────────────────────────────────────────────────────────


def generate_ed25519_keypair() -> tuple[str, str]:
    """
    Generate an Ed25519 keypair.

    Returns:
        Tuple of (private_key_pem, public_key_pem) as strings.
    """
    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def ed25519_sign(message: bytes, private_key_pem: str) -> bytes:
    """
    Sign a message with Ed25519.

    Args:
        message:         Bytes to sign.
        private_key_pem: PEM-encoded Ed25519 private key.

    Returns:
        64-byte signature.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    return private_key.sign(message)


def ed25519_verify(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    """
    Verify an Ed25519 signature.

    Returns:
        True if valid, False if invalid (does not raise).
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, Exception):
        return False


# ─── RSA-PSS ──────────────────────────────────────────────────────────────────


def generate_rsa_pss_keypair(key_size: int = 2048) -> tuple[str, str]:
    """
    Generate an RSA keypair suitable for PSS signing.

    Args:
        key_size: Key size in bits (minimum 2048).

    Returns:
        Tuple of (private_key_pem, public_key_pem).
    """
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits")
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def rsa_pss_sign(message: bytes, private_key_pem: str) -> bytes:
    """
    Sign a message with RSA-PSS (SHA-256, MGF1-SHA256, max salt length).

    Args:
        message:         Bytes to sign.
        private_key_pem: PEM-encoded RSA private key.

    Returns:
        Raw RSA-PSS signature bytes.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("Expected RSA private key")
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    """
    Verify an RSA-PSS signature.

    Returns:
        True if valid, False if invalid.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(public_key, RSAPublicKey):
            return False
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, Exception):
        return False
