"""Identity persistence operations used by authentication services."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from app.models.identity import User, UserSession


def get_user_by_email(session: Session, email: str) -> User | None:
    return session.scalar(select(User).where(User.email.ilike(email.strip())).limit(1))


def get_user(session: Session, user_id: UUID) -> User | None:
    return session.get(User, user_id)


def create_session(
    session: Session,
    *,
    user: User,
    ip: str | None,
    user_agent: str | None,
    ttl_seconds: int,
) -> tuple[UserSession, str]:
    raw = secrets.token_urlsafe(48)
    now = datetime.now(UTC)
    row = UserSession(
        user_id=user.id,
        refresh_token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        family_id=uuid4(),
        issued_at=now,
        expires_at=now.replace(microsecond=0) + timedelta(seconds=ttl_seconds),
        ip=ip,
        user_agent=user_agent,
    )
    session.add(row)
    return row, raw


def get_session_by_refresh_hash(session: Session, digest: str) -> UserSession | None:
    return session.scalar(
        select(UserSession).where(UserSession.refresh_token_hash == digest).with_for_update()
    )


def revoke_session(session: Session, row: UserSession, when: datetime) -> None:
    row.revoked_at = when


def revoke_family(session: Session, family_id: UUID, when: datetime) -> int:
    result = session.execute(
        update(UserSession)
        .where(UserSession.family_id == family_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=when)
    )
    return int(cast(CursorResult[Any], result).rowcount)


def revoke_all_sessions(session: Session, user_id: UUID, when: datetime) -> int:
    result = session.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=when)
    )
    return int(result.rowcount)


def touch_successful_login(session: Session, user: User, ip: str | None) -> None:
    user.last_login_at = datetime.now(UTC)
    user.last_login_ip = ip
    user.failed_login_count = 0
    user.locked_until = None


def record_failed_login(session: Session, user: User, *, lock_threshold: int = 5) -> None:
    user.failed_login_count += 1
    if user.failed_login_count >= lock_threshold:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=15)


def is_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > datetime.now(UTC)


def user_roles(user: User) -> list[str]:
    roles = {user.global_role.value}
    for assignment in user.role_assignments:
        if assignment.revoked_at is None:
            roles.add(assignment.role.code.value)
    return sorted(roles)
