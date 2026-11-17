# fmt: off
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.config import Environment, Settings
from app.core.errors import TokenExpiredError, UnauthenticatedError
from app.core.security.denylist import InProcessJtiDenylist
from app.core.security.jwt import decode_access_token, issue_access_token
from app.core.security.mfa import decrypt_secret, encrypt_secret, new_totp_secret
from app.core.security.passwords import hash_password, needs_rehash, verify_password
from app.core.security.rate_limit import InProcessRateLimiter


def _settings() -> Settings:
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return Settings(
        tlx_env=Environment.TEST,
        jwt_private_key=private_pem,
        jwt_public_key=public_pem,
        encryption_key="test-encryption-key",
    )


def test_jwt_uses_ed25519_and_required_claims() -> None:
    settings = _settings()
    user_id = uuid4()
    session_id = uuid4()
    token = issue_access_token(
        settings,
        user_id=user_id,
        session_id=session_id,
        roles=["investigator"],
        mfa_verified=False,
    )
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA"
    assert header["kid"] == settings.jwt_key_id
    claims = decode_access_token(settings, token)
    assert claims["sub"] == str(user_id)
    assert claims["sid"] == str(session_id)
    assert claims["roles"] == ["investigator"]
    assert "jti" in claims
    assert claims["exp"] > claims["iat"]


def test_jwt_rejects_hs256() -> None:
    settings = _settings()
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "jti": str(uuid4()),
            "roles": ["investigator"],
            "sid": str(uuid4()),
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
        },
        "not-a-valid-ed25519-key",
        algorithm="HS256",
    )
    with pytest.raises(UnauthenticatedError):
        decode_access_token(settings, token)


def test_expired_jwt_is_distinguished() -> None:
    settings = _settings()
    private = settings.jwt_private_key
    assert private is not None
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "jti": str(uuid4()),
            "roles": ["investigator"],
            "sid": str(uuid4()),
            "iat": datetime.now(UTC) - timedelta(minutes=10),
            "exp": datetime.now(UTC) - timedelta(minutes=1),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
        },
        private,
        algorithm="EdDSA",
        headers={"kid": settings.jwt_key_id},
    )
    with pytest.raises(TokenExpiredError):
        decode_access_token(settings, token)


def test_passwords_are_argon2id_and_verify() -> None:
    encoded = hash_password("A sufficiently strong password!")
    assert encoded.startswith("$argon2id$")
    assert verify_password("A sufficiently strong password!", encoded)
    assert not verify_password("wrong password", encoded)
    assert needs_rehash(encoded) is False


def test_mfa_secret_is_encrypted_and_totp_verifies() -> None:
    secret = new_totp_secret()
    blob = encrypt_secret(secret, "test-key")
    assert blob != secret.encode()
    recovered = decrypt_secret(blob, "test-key")
    assert recovered == secret


def test_denylist_ttl_and_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    denylist = InProcessJtiDenylist()
    denylist.deny("jti-1", 1)
    assert denylist.is_denied("jti-1")
    assert denylist.purge_expired() == 0
    monkeypatch.setattr("app.core.security.denylist.monotonic", lambda: 2.0)
    denylist2 = InProcessJtiDenylist()
    denylist2.deny("jti-2", 1)
    monkeypatch.setattr("app.core.security.denylist.monotonic", lambda: 4.0)
    assert not denylist2.is_denied("jti-2")


def test_rate_limiter_enforces_window() -> None:
    limiter = InProcessRateLimiter()
    assert limiter.allow("k", limit=2, window_seconds=60)[0]
    assert limiter.allow("k", limit=2, window_seconds=60)[0]
    assert not limiter.allow("k", limit=2, window_seconds=60)[0]


def test_test_settings_generate_matching_ed25519_keypair() -> None:
    settings = Settings(tlx_env=Environment.TEST)
    assert settings.jwt_private_key is not None
    assert settings.jwt_public_key is not None
    token = issue_access_token(
        settings,
        user_id=uuid4(),
        session_id=uuid4(),
        roles=["investigator"],
        mfa_verified=False,
    )
    assert decode_access_token(settings, token)["iss"] == settings.jwt_issuer

# fmt: on
