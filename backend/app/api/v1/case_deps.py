"""FastAPI dependencies for the single case authorization choke point."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import Depends

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.deps import SessionDep
from app.services.authorization import CaseAccess, authorize_case_access


def require_case_access(capability: str) -> Callable[..., CaseAccess]:
    def dependency(
        case_id: UUID,
        principal: CurrentPrincipal,
        session: SessionDep,
    ) -> CaseAccess:
        return authorize_case_access(
            session,
            user=principal.user,
            case_id=case_id,
            capability=capability,
        )

    return dependency


CaseViewAccess = Annotated[CaseAccess, Depends(require_case_access("view_case"))]
CaseEditAccess = Annotated[CaseAccess, Depends(require_case_access("edit_case"))]
CaseTransitionAccess = Annotated[CaseAccess, Depends(require_case_access("close_case"))]
CaseMemberManageAccess = Annotated[CaseAccess, Depends(require_case_access("manage_members"))]
