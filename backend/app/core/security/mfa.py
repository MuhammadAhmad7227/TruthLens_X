"""TOTP helpers and authenticated-at-rest secret protection."""

from __future__ import annotations

import base64
import hashlib
import os

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_secret(secret: str, key_material: str) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key(key_material)).encrypt(nonce, secret.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_secret(blob: bytes, key_material: str) -> str:
    if len(blob) < 13:
        raise ValueError("invalid encrypted MFA secret")
    plaintext = AESGCM(_key(key_material)).decrypt(blob[:12], blob[12:], None)
    return plaintext.decode("utf-8")


def new_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, *, email: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)
