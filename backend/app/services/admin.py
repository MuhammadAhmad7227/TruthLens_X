"""M19 admin lifecycle operations. No impersonation is exposed."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

SHA256_HEX_LENGTH = 64
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationError
from app.models.enums import UserStatus
from app.models.identity import User, UserSession


def suspend_user(session: Session, user_id: UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise NotFoundError()
    user.status = UserStatus.SUSPENDED
    session.commit()
    return user


def deactivate_user(session: Session, user_id: UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise NotFoundError()
    user.status = UserStatus.DEACTIVATED
    user.deleted_at = datetime.now(UTC)
    session.commit()
    return user


def force_logout(session: Session, user_id: UUID) -> int:
    sessions = list(
        session.scalars(
            select(UserSession).where(
                UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
            )
        ).all()
    )
    now = datetime.now(UTC)
    for item in sessions:
        item.revoked_at = now
    session.commit()
    return len(sessions)


def validate_model_registration(payload: dict[str, Any]) -> dict[str, Any]:
    required = ("name", "version", "weights_sha256", "engine_name")
    if any(not payload.get(k) for k in required):
        raise ValidationError("Model registration is incomplete")
    if len(str(payload["weights_sha256"])) != SHA256_HEX_LENGTH:
        raise ValidationError("weights_sha256 must be SHA-256")
    return payload
