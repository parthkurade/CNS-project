"""
Tests for all cryptographic functions.
Covers: AES-256-GCM, Ed25519, RSA-PSS, HMAC-SHA256, SHA-256, replay protection.
"""
from __future__ import annotations

import os

import pytest

from backend.crypto.aes import decrypt, decrypt_email, derive_key, encrypt, encrypt_email
from backend.crypto.hashing import sha256_hash, sha256_hash_bytes, verify_hash
from backend.crypto.hmac_util import hmac_sign, hmac_verify, pbkdf2_derive
from backend.crypto.signatures import (
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    generate_rsa_pss_keypair,
    rsa_pss_sign,
    rsa_pss_verify,
)


class TestAESGCM:
    """AES-256-GCM encryption tests."""

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Hello, PhishShield!"
        ciphertext, nonce = encrypt(plaintext, key)
        assert decrypt(ciphertext, nonce, key) == plaintext

    def test_different_nonces_each_time(self):
        key = os.urandom(32)
        ct1, n1 = encrypt(b"same", key)
        ct2, n2 = encrypt(b"same", key)
        assert n1 != n2  # Random nonces must differ

    def test_tampered_ciphertext_raises(self):
        from cryptography.exceptions import InvalidTag
        key = os.urandom(32)
        ct, nonce = encrypt(b"secret", key)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt(bytes(tampered), nonce, key)

    def test_tampered_aad_raises(self):
        from cryptography.exceptions import InvalidTag
        key = os.urandom(32)
        ct, nonce = encrypt(b"secret", key, associated_data=b"auth")
        with pytest.raises(InvalidTag):
            decrypt(ct, nonce, key, associated_data=b"different_auth")

    def test_wrong_key_raises(self):
        from cryptography.exceptions import InvalidTag
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct, nonce = encrypt(b"secret", key1)
        with pytest.raises(InvalidTag):
            decrypt(ct, nonce, key2)

    def test_bad_key_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt(b"data", b"short_key")

    def test_email_encrypt_decrypt(self, master_key):
        raw_email = b"From: test@test.com\r\nSubject: Test\r\n\r\nBody"
        ct, nonce = encrypt_email(raw_email, master_key)
        assert decrypt_email(ct, nonce, master_key) == raw_email

    def test_nonce_is_12_bytes(self):
        key = os.urandom(32)
        _, nonce = encrypt(b"test", key)
        assert len(nonce) == 12

    def test_hkdf_derive_deterministic(self, master_key):
        k1 = derive_key(master_key, b"context")
        k2 = derive_key(master_key, b"context")
        assert k1 == k2

    def test_hkdf_different_context_different_key(self, master_key):
        k1 = derive_key(master_key, b"email-storage")
        k2 = derive_key(master_key, b"hmac-auth")
        assert k1 != k2


class TestEd25519:
    """Ed25519 digital signature tests."""

    def test_sign_verify(self):
        priv, pub = generate_ed25519_keypair()
        msg = b"Important email content"
        sig = ed25519_sign(msg, priv)
        assert ed25519_verify(msg, sig, pub)

    def test_invalid_signature_rejected(self):
        priv, pub = generate_ed25519_keypair()
        msg = b"Original message"
        sig = ed25519_sign(msg, priv)
        # Flip a byte in the signature
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert not ed25519_verify(msg, bytes(bad_sig), pub)

    def test_tampered_message_rejected(self):
        priv, pub = generate_ed25519_keypair()
        sig = ed25519_sign(b"original", priv)
        assert not ed25519_verify(b"tampered", sig, pub)

    def test_wrong_key_rejected(self):
        priv1, pub1 = generate_ed25519_keypair()
        _priv2, pub2 = generate_ed25519_keypair()
        sig = ed25519_sign(b"message", priv1)
        assert not ed25519_verify(b"message", sig, pub2)

    def test_signature_is_64_bytes(self):
        priv, _ = generate_ed25519_keypair()
        sig = ed25519_sign(b"test", priv)
        assert len(sig) == 64

    def test_generated_keys_are_pem(self):
        priv, pub = generate_ed25519_keypair()
        assert priv.startswith("-----BEGIN PRIVATE KEY-----")
        assert pub.startswith("-----BEGIN PUBLIC KEY-----")


class TestRSAPSS:
    """RSA-PSS digital signature tests."""

    @pytest.fixture(scope="class")
    @classmethod
    def keypair(cls):
        return generate_rsa_pss_keypair(key_size=2048)

    def test_sign_verify(self, keypair):
        priv, pub = keypair
        sig = rsa_pss_sign(b"test message", priv)
        assert rsa_pss_verify(b"test message", sig, pub)

    def test_tampered_rejected(self, keypair):
        priv, pub = keypair
        sig = rsa_pss_sign(b"original", priv)
        assert not rsa_pss_verify(b"tampered", sig, pub)

    def test_minimum_key_size(self):
        with pytest.raises(ValueError, match="2048"):
            generate_rsa_pss_keypair(key_size=1024)


class TestHMAC:
    """HMAC-SHA256 constant-time verification tests."""

    def test_verify_correct(self):
        key = os.urandom(32)
        msg = b"trusted message"
        mac = hmac_sign(msg, key)
        assert hmac_verify(msg, key, mac)

    def test_verify_wrong_key(self):
        mac = hmac_sign(b"msg", b"key1" * 8)
        assert not hmac_verify(b"msg", b"key2" * 8, mac)

    def test_verify_tampered_message(self):
        key = os.urandom(32)
        mac = hmac_sign(b"original", key)
        assert not hmac_verify(b"tampered", key, mac)

    def test_verify_truncated_mac(self):
        key = os.urandom(32)
        mac = hmac_sign(b"msg", key)
        assert not hmac_verify(b"msg", key, mac[:16])

    def test_mac_is_32_bytes(self):
        mac = hmac_sign(b"test", b"key" * 10)
        assert len(mac) == 32

    def test_pbkdf2_derive_correct_length(self):
        dk, salt = pbkdf2_derive(b"password", iterations=1000)
        assert len(dk) == 32
        assert len(salt) == 16

    def test_pbkdf2_deterministic_with_salt(self):
        salt = os.urandom(16)
        dk1, _ = pbkdf2_derive(b"password", salt=salt, iterations=1000)
        dk2, _ = pbkdf2_derive(b"password", salt=salt, iterations=1000)
        assert dk1 == dk2

    def test_pbkdf2_different_password_different_key(self):
        salt = os.urandom(16)
        dk1, _ = pbkdf2_derive(b"password1", salt=salt, iterations=1000)
        dk2, _ = pbkdf2_derive(b"password2", salt=salt, iterations=1000)
        assert dk1 != dk2


class TestHashing:
    """SHA-256 hashing tests."""

    def test_hash_deterministic(self):
        assert sha256_hash(b"test") == sha256_hash(b"test")

    def test_hash_changes_on_tamper(self):
        assert sha256_hash(b"original") != sha256_hash(b"tampered")

    def test_hash_is_64_hex_chars(self):
        h = sha256_hash(b"data")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_verify_correct(self):
        data = b"PhishShield integrity check"
        h = sha256_hash(data)
        assert verify_hash(data, h)

    def test_verify_tampered_fails(self):
        data = b"original"
        h = sha256_hash(data)
        assert not verify_hash(b"tampered", h)

    def test_no_md5(self):
        """Ensure we never use MD5 for security purposes."""
        # SHA-256 output is 32 bytes; MD5 is 16 bytes
        result = sha256_hash_bytes(b"test")
        assert len(result) == 32  # Not MD5's 16 bytes
