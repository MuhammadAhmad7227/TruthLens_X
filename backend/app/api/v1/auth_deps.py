"""Authentication dependencies for v1 routers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import SessionDep
from app.core.config import Settings, get_settings
from app.core.errors import AuthorisationError, UnauthenticatedError
from app.core.security.jwt import decode_access_token
from app.models.identity import User, UserSession
from app.services.auth import DENYLIST

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    user: User
    session: UserSession
    claims: dict[str, object]


def _get_session(session: Session, session_id: UUID) -> UserSession | None:
    return session.get(UserSession, session_id)


def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: SessionDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise UnauthenticatedError()
    claims = decode_access_token(settings, credentials.credentials)
    jti = str(claims["jti"])
    if DENYLIST.is_denied(jti):
        raise UnauthenticatedError("Access token has been revoked")
    session_id = UUID(str(claims["sid"]))
    row = _get_session(session, session_id)
    if row is None or row.revoked_at is not None or row.expires_at <= datetime.now(UTC):
        raise UnauthenticatedError("Session is no longer active")
    user = session.get(User, UUID(str(claims["sub"])))
    if user is None or user.status.value != "active":
        raise UnauthenticatedError()
    if row.user_id != user.id:
        raise AuthorisationError("Session does not belong to the authenticated user")
    return Principal(user=user, session=row, claims=claims)


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
