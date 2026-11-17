"""Ed25519 JWT access-token handling for M3.

This module deliberately depends only on configuration and third-party crypto/JWT libraries.
Application/session state is checked by the authentication service, not here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt
from jwt import InvalidTokenError

from app.core.config import Settings
from app.core.errors import TokenExpiredError, UnauthenticatedError

ALGORITHM = "EdDSA"
MAX_ACCESS_TOKEN_TTL_SECONDS = 15 * 60


def issue_access_token(
    settings: Settings,
    *,
    user_id: UUID,
    session_id: UUID,
    roles: list[str],
    mfa_verified: bool,
) -> str:
    """Issue the mandatory short-lived EdDSA access token."""
    if settings.access_token_ttl_seconds > MAX_ACCESS_TOKEN_TTL_SECONDS:
        raise ValueError("access token TTL exceeds the mandatory 15-minute maximum")
    if not settings.jwt_private_key:
        raise ValueError("JWT_PRIVATE_KEY is not configured")
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "sub": str(user_id),
        "jti": str(uuid4()),
        "roles": roles,
        "sid": str(session_id),
        "iat": now,
        "exp": now + timedelta(seconds=settings.access_token_ttl_seconds),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "mfa": mfa_verified,
    }
    return jwt.encode(
        claims,
        settings.jwt_private_key,
        algorithm=ALGORITHM,
        headers={"kid": settings.jwt_key_id},
    )


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    """Verify signature, algorithm, issuer, audience and required claims."""
    if not settings.jwt_public_key:
        raise UnauthenticatedError("JWT verification key is not configured")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != ALGORITHM:
            raise UnauthenticatedError("Unsupported JWT signing algorithm")
        if header.get("kid") != settings.jwt_key_id:
            raise UnauthenticatedError("Unknown JWT signing key")
        claims = jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=[ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "jti", "roles", "sid", "iat", "exp", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except InvalidTokenError as exc:
        raise UnauthenticatedError("Invalid access token") from exc

    for name in ("sub", "jti", "sid", "iss", "aud"):
        if not isinstance(claims.get(name), str) or not claims[name]:
            raise UnauthenticatedError("Invalid access token claims")
    if not isinstance(claims.get("roles"), list) or not all(isinstance(x, str) for x in claims["roles"]):
        raise UnauthenticatedError("Invalid access token claims")
    try:
        UUID(claims["sub"])
        UUID(claims["sid"])
        UUID(claims["jti"])
    except ValueError as exc:
        raise UnauthenticatedError("Invalid access token identifiers") from exc
    return claims
