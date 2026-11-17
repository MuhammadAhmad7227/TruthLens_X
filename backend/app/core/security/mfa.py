"""TOTP helpers and authenticated-at-rest secret protection."""

from __future__ import annotations

import hashlib
import os

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\n_NONCE_BYTES = 12\n_MIN_ENCRYPTED_BYTES = _NONCE_BYTES + 16


def _key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_secret(secret: str, key_material: str) -> bytes:
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_key(key_material)).encrypt(nonce, secret.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_secret(blob: bytes, key_material: str) -> str:
    if len(blob) < _MIN_ENCRYPTED_BYTES:
        raise ValueError("invalid encrypted MFA secret")
    plaintext = AESGCM(_key(key_material)).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], None)
    return plaintext.decode("utf-8")


def new_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, *, email: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)
