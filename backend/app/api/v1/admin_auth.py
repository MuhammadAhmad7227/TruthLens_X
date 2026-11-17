# fmt: off
"""Minimal M3 administrator authentication operations."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Request, status

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.deps import SessionDep
from app.services import auth as auth_service

router = APIRouter(prefix="/admin/users", tags=["auth"])


@router.post("/{user_id}:unlock", status_code=status.HTTP_204_NO_CONTENT)
def unlock_user(
    user_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> None:
    auth_service.admin_unlock_by_id(session, actor=principal.user, target_id=user_id, request_id=getattr(request.state, "request_id", None))

# fmt: on
