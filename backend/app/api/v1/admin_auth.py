"""Minimal M3 administrator authentication operations."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.deps import SessionDep
from app.core.errors import ForbiddenRoleError, NotFoundError
from app.core.config import Settings, get_settings
from app.models.enums import GlobalRole
from app.models.identity import User
from app.services import auth as auth_service

router = APIRouter(prefix="/admin/users", tags=["auth"])


@router.post("/{user_id}:unlock", status_code=status.HTTP_204_NO_CONTENT)
def unlock_user(
    user_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> None:
    if principal.user.global_role is not GlobalRole.ADMIN:
        raise ForbiddenRoleError()
    target = session.get(User, user_id)
    if target is None:
        raise NotFoundError()
    auth_service.admin_unlock(session, actor=principal.user, target=target, request_id=None)
