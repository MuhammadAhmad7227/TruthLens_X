"""Authentication dependency for v1 routers."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.api.v1.deps import SessionDep
from app.core.config import Settings, get_settings
from app.core.errors import UnauthenticatedError
from app.services.auth import Principal, authenticate_access_token


_bearer = HTTPBearer(auto_error=False)


def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: SessionDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise UnauthenticatedError()
    return authenticate_access_token(session, settings, credentials.credentials)


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
