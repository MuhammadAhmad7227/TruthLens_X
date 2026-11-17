"""Authentication, session, lockout and MFA business rules."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import jwt
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import (
    AuthorisationError,
    MFARequiredError,
    RateLimitedError,
    TokenExpiredError,
    UnauthenticatedError,
)
from app.core.security.denylist import InProcessJtiDenylist, JtiDenylist
from app.core.security.jwt import decode_access_token, issue_access_token
from app.core.security.mfa import decrypt_secret, encrypt_secret, new_totp_secret, provisioning_uri, verify_totp
from app.core.security.rate_limit import InProcessRateLimiter
from app.core.security.passwords import hash_password, needs_rehash, verify_password
from app.models.identity import User, UserSession
from app.repositories.audit import append_audit
from app.repositories.identity import (
    create_session,
    get_session_by_refresh_hash,
    get_user,
    get_user_by_email,
    is_locked,
    record_failed_login,
    revoke_all_sessions,
    revoke_family,
    revoke_session,
    touch_successful_login,
    user_roles,
)

DENYLIST: JtiDenylist = InProcessJtiDenylist()


@dataclass(frozen=True)
class Principal:
    user: User
    session: UserSession
    claims: dict[str, object]

LOGIN_LIMITER = InProcessRateLimiter()


def _challenge(settings: Settings, user: User) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(user.id),
            "jti": str(uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "purpose": "mfa",
        },
        settings.jwt_private_key,
        algorithm="EdDSA",
        headers={"kid": settings.jwt_key_id},
    )


def _decode_challenge(settings: Settings, token: str) -> UUID:
    try:
        claims = jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=["EdDSA"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "jti", "iat", "exp", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except jwt.InvalidTokenError as exc:
        raise UnauthenticatedError("Invalid MFA challenge") from exc
    if claims.get("purpose") != "mfa":
        raise UnauthenticatedError("Invalid MFA challenge")
    try:
        return UUID(str(claims["sub"]))
    except ValueError as exc:
        raise UnauthenticatedError("Invalid MFA challenge") from exc


def login(
    session: Session,
    settings: Settings,
    *,
    email: str,
    password: str,
    ip: str | None,
    user_agent: str | None,
    request_id: str | None,
) -> tuple[User, UserSession | None, str | None, str | None]:
    """Authenticate credentials and either issue a session or an MFA challenge."""
    allowed_ip, _ = LOGIN_LIMITER.allow(f"login:ip:{ip or 'unknown'}", limit=10, window_seconds=60)
    allowed_email, _ = LOGIN_LIMITER.allow(f"login:email:{email.strip().lower()}", limit=10, window_seconds=60)
    if not allowed_ip or not allowed_email:
        append_audit(session, action="auth.login.rate_limited", result="denied", reason="RATE_LIMITED", actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise RateLimitedError(retry_after=60)
    user = get_user_by_email(session, email)
    if user is None:
        append_audit(session, action="auth.login.failed", result="denied", reason="INVALID_CREDENTIALS", actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise UnauthenticatedError("Invalid email or password")
    if is_locked(user):
        append_audit(session, action="auth.login.failed", result="denied", actor_id=user.id, actor_role=user.global_role.value, reason="ACCOUNT_LOCKED", actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise AuthorisationError("Account is temporarily locked")
    if user.status.value != "active" or not verify_password(password, user.password_hash):
        record_failed_login(session, user)
        append_audit(session, action="auth.login.failed", result="denied", actor_id=user.id, actor_role=user.global_role.value, reason="INVALID_CREDENTIALS", actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise UnauthenticatedError("Invalid email or password")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        user.password_changed_at = datetime.now(UTC)
    touch_successful_login(session, user, ip)
    if user.mfa_enabled:
        challenge = _challenge(settings, user)
        append_audit(session, action="auth.login.mfa_required", result="allowed", actor_id=user.id, actor_role=user.global_role.value, actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise MFARequiredError("Multi-factor authentication is required", challenge_token=challenge)
    session_row, refresh = create_session(session, user=user, ip=ip, user_agent=user_agent, ttl_seconds=settings.refresh_token_ttl_seconds)
    access = issue_access_token(settings, user_id=user.id, session_id=session_row.id, roles=user_roles(user), mfa_verified=False)
    append_audit(session, action="auth.login.succeeded", result="allowed", actor_id=user.id, actor_role=user.global_role.value, actor_ip=ip, user_agent=user_agent, request_id=request_id, resource_type="user", resource_id=user.id)
    session.commit()
    return user, session_row, access, refresh


def verify_mfa(
    session: Session,
    settings: Settings,
    *,
    challenge_token: str,
    code: str,
    ip: str | None,
    user_agent: str | None,
    request_id: str | None,
) -> tuple[User, UserSession, str, str]:
    user_id = _decode_challenge(settings, challenge_token)
    user = get_user(session, user_id)
    if user is None or not user.mfa_enabled or not user.mfa_secret_encrypted or not settings.encryption_key:
        raise UnauthenticatedError("Invalid MFA challenge")
    secret = decrypt_secret(user.mfa_secret_encrypted, settings.encryption_key)
    if not verify_totp(secret, code):
        append_audit(session, action="auth.mfa.failed", result="denied", actor_id=user.id, actor_role=user.global_role.value, reason="INVALID_TOTP", actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise UnauthenticatedError("Invalid MFA code")
    row, refresh = create_session(session, user=user, ip=ip, user_agent=user_agent, ttl_seconds=settings.refresh_token_ttl_seconds)
    access = issue_access_token(settings, user_id=user.id, session_id=row.id, roles=user_roles(user), mfa_verified=True)
    append_audit(session, action="auth.mfa.verified", result="allowed", actor_id=user.id, actor_role=user.global_role.value, actor_ip=ip, user_agent=user_agent, request_id=request_id)
    session.commit()
    return user, row, access, refresh


def refresh(
    session: Session,
    settings: Settings,
    *,
    raw_refresh_token: str,
    ip: str | None,
    user_agent: str | None,
    request_id: str | None,
) -> tuple[User, UserSession, str, str]:
    digest = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
    row = get_session_by_refresh_hash(session, digest)
    now = datetime.now(UTC)
    if row is None:
        raise UnauthenticatedError("Invalid refresh token")
    user = get_user(session, row.user_id)
    if user is None:
        raise UnauthenticatedError("Invalid refresh token")
    if row.revoked_at is not None:
        revoke_family(session, row.family_id, now)
        append_audit(session, action="auth.refresh.reuse_detected", result="denied", actor_id=user.id, actor_role=user.global_role.value, reason="ROTATED_TOKEN_REUSE", actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise UnauthenticatedError("Refresh token reuse detected; the session family was revoked")
    if row.expires_at <= now:
        append_audit(session, action="auth.refresh.rejected", result="denied", actor_id=user.id, actor_role=user.global_role.value, reason="EXPIRED", actor_ip=ip, user_agent=user_agent, request_id=request_id)
        session.commit()
        raise UnauthenticatedError("Invalid refresh token")
    revoke_session(session, row, now)
    new_row, new_refresh = create_session(session, user=user, ip=ip, user_agent=user_agent, ttl_seconds=settings.refresh_token_ttl_seconds)
    new_row.family_id = row.family_id
    access = issue_access_token(settings, user_id=user.id, session_id=new_row.id, roles=user_roles(user), mfa_verified=user.mfa_enabled)
    append_audit(session, action="auth.refresh.succeeded", result="allowed", actor_id=user.id, actor_role=user.global_role.value, actor_ip=ip, user_agent=user_agent, request_id=request_id, resource_type="user_session", resource_id=new_row.id)
    session.commit()
    return user, new_row, access, new_refresh


def logout(session: Session, *, current_session: UserSession, user: User, jti: str, token_exp: int, request_id: str | None, ip: str | None, user_agent: str | None) -> None:
    now = datetime.now(UTC)
    revoke_family(session, current_session.family_id, now)
    DENYLIST.deny(jti, max(0, token_exp - int(now.timestamp())))
    append_audit(session, action="auth.logout.succeeded", result="allowed", actor_id=user.id, actor_role=user.global_role.value, actor_ip=ip, user_agent=user_agent, request_id=request_id, resource_type="user_session", resource_id=current_session.id)
    session.commit()


def logout_all(session: Session, *, user: User, jti: str, token_exp: int, request_id: str | None, ip: str | None, user_agent: str | None) -> None:
    now = datetime.now(UTC)
    revoke_all_sessions(session, user.id, now)
    DENYLIST.deny(jti, max(0, token_exp - int(now.timestamp())))
    append_audit(session, action="auth.logout_all.succeeded", result="allowed", actor_id=user.id, actor_role=user.global_role.value, actor_ip=ip, user_agent=user_agent, request_id=request_id, resource_type="user", resource_id=user.id)
    session.commit()


def change_password(session: Session, *, user: User, current_password: str, new_password: str, request_id: str | None) -> None:
    if not verify_password(current_password, user.password_hash):
        append_audit(session, action="auth.password.change.failed", result="denied", actor_id=user.id, actor_role=user.global_role.value, reason="INVALID_CURRENT_PASSWORD", request_id=request_id)
        session.commit()
        raise UnauthenticatedError("Current password is incorrect")
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(UTC)
    revoke_all_sessions(session, user.id, datetime.now(UTC))
    append_audit(session, action="auth.password.changed", result="allowed", actor_id=user.id, actor_role=user.global_role.value, request_id=request_id, resource_type="user", resource_id=user.id)
    session.commit()


def begin_mfa_enrolment(session: Session, settings: Settings, *, user: User, request_id: str | None) -> tuple[str, str]:
    if not settings.encryption_key:
        raise UnauthenticatedError("MFA encryption is not configured")
    secret = new_totp_secret()
    user.mfa_secret_encrypted = encrypt_secret(secret, settings.encryption_key)
    user.mfa_enabled = False
    append_audit(session, action="auth.mfa.enrol.started", result="allowed", actor_id=user.id, actor_role=user.global_role.value, request_id=request_id, resource_type="user", resource_id=user.id)
    session.commit()
    return secret, provisioning_uri(secret, email=user.email, issuer=settings.service_name)


def confirm_mfa_enrolment(session: Session, settings: Settings, *, user: User, code: str, request_id: str | None) -> None:
    if not user.mfa_secret_encrypted or not settings.encryption_key:
        raise UnauthenticatedError("MFA enrolment has not been started")
    secret = decrypt_secret(user.mfa_secret_encrypted, settings.encryption_key)
    if not verify_totp(secret, code):
        raise UnauthenticatedError("Invalid MFA code")
    user.mfa_enabled = True
    append_audit(session, action="auth.mfa.enrol.confirmed", result="allowed", actor_id=user.id, actor_role=user.global_role.value, request_id=request_id, resource_type="user", resource_id=user.id)
    session.commit()


def disable_mfa(session: Session, *, user: User, password: str, request_id: str | None) -> None:
    if not verify_password(password, user.password_hash):
        raise UnauthenticatedError("Current password is incorrect")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    revoke_all_sessions(session, user.id, datetime.now(UTC))
    append_audit(session, action="auth.mfa.disabled", result="allowed", actor_id=user.id, actor_role=user.global_role.value, request_id=request_id, resource_type="user", resource_id=user.id)
    session.commit()


def admin_unlock(session: Session, *, actor: User, target: User, request_id: str | None) -> None:
    """Clear login lockout; only the administrator global role may invoke this M3 operation."""
    from app.models.enums import GlobalRole

    if actor.global_role is not GlobalRole.ADMIN:
        raise AuthorisationError("Administrator role required")
    target.failed_login_count = 0
    target.locked_until = None
    append_audit(
        session,
        action="admin.user.unlock",
        result="allowed",
        actor_id=actor.id,
        actor_role=actor.global_role.value,
        resource_type="user",
        resource_id=target.id,
        request_id=request_id,
    )
    session.commit()


def authenticate_access_token(session: Session, settings: Settings, token: str) -> Principal:
    claims = decode_access_token(settings, token)
    jti = str(claims["jti"])
    if DENYLIST.is_denied(jti):
        raise UnauthenticatedError("Access token has been revoked")
    session_id = UUID(str(claims["sid"]))
    row = session.get(UserSession, session_id)
    if row is None or row.revoked_at is not None or row.expires_at <= datetime.now(UTC):
        raise UnauthenticatedError("Session is no longer active")
    user = session.get(User, UUID(str(claims["sub"])))
    if user is None or user.status.value != "active":
        raise UnauthenticatedError()
    if row.user_id != user.id:
        raise AuthorisationError("Session does not belong to the authenticated user")
    return Principal(user=user, session=row, claims=claims)


def admin_unlock_by_id(session: Session, *, actor: User, target_id: UUID, request_id: str | None) -> None:
    target = session.get(User, target_id)
    if target is None:
        from app.core.errors import NotFoundError
        raise NotFoundError()
    admin_unlock(session, actor=actor, target=target, request_id=request_id)


def update_profile(session: Session, *, user: User, full_name: str, request_id: str | None) -> None:
    user.full_name = full_name.strip()
    append_audit(
        session,
        action="auth.profile.updated",
        result="allowed",
        actor_id=user.id,
        actor_role=user.global_role.value,
        request_id=request_id,
        resource_type="user",
        resource_id=user.id,
    )
    session.commit()
