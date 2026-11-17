"""Authentication dependency for v1 routers."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from app.api.v1.deps import SessionDep
from app.core.config import Settings, get_settings
from app.core.errors import UnauthenticatedError
from app.services.auth import Principal, authenticate_access_token


class _Bearer:
    def __call__(self) -> None:
        return None


def get_current_principal(
    authorization: Annotated[str | None, Depends(_Bearer())],
    session: SessionDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    if authorization is None or not authorization.lower().startswith("bearer "):
        raise UnauthenticatedError()
    return authenticate_access_token(session, settings, authorization[7:].strip())


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
