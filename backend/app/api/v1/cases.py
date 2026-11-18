# ruff: isort: skip_file
"""M4 case-management HTTP surface. Routers stay thin: validate, call service, map schema."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Query, status

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.case_deps import (
    CaseEditAccess,
    CaseMemberManageAccess,
    CaseTransitionAccess,
    CaseViewAccess,
)
from app.api.v1.case_schemas import (
    CaseCreateRequest,
    CaseDashboardResponse,
    CaseMemberCreateRequest,
    CaseMemberResponse,
    CaseMemberUpdateRequest,
    CaseResponse,
    CaseTransitionRequest,
    CaseTransitionResponse,
    CaseUpdateRequest,
)
from app.api.v1.deps import SessionDep
from app.services import case_management


router = APIRouter(tags=["cases"])


def _response(case: Any) -> CaseResponse:
    return CaseResponse.model_validate(case, from_attributes=True)


def _member_response(member: Any) -> CaseMemberResponse:
    return CaseMemberResponse.model_validate(member, from_attributes=True)


@router.get("/cases", response_model=list[CaseResponse])
def list_cases_endpoint(
    principal: CurrentPrincipal,
    session: SessionDep,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    lead: UUID | None = None,
    tag: str | None = None,
    q: str | None = None,
    sensitivity: str | None = None,
) -> list[CaseResponse]:
    return [
        _response(c)
        for c in case_management.list_cases(
            session,
            actor=principal.user,
            status=status_filter,
            lead_id=lead,
            sensitivity=sensitivity,
            tag=tag,
            query=q,
        )
    ]


@router.post("/cases", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case_endpoint(
    body: CaseCreateRequest,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> CaseResponse:
    case = case_management.create_case(
        session,
        actor=principal.user,
        title=body.title,
        description=body.description,
        sensitivity=body.sensitivity,
        case_type=body.case_type,
        jurisdiction=body.jurisdiction,
        lead_investigator_id=body.lead_investigator_id,
        statutory_deadline=body.statutory_deadline,
        tags=body.tags,
    )
    return _response(case)


@router.get("/cases:by-number/{case_number}", response_model=CaseResponse)
def get_case_by_number_endpoint(
    case_number: str,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> CaseResponse:
    case = case_management.get_case_by_number_for_user(
        session, actor=principal.user, case_number=case_number
    )
    return _response(case)


@router.get("/cases/{case_id}", response_model=CaseResponse)
def get_case_endpoint(
    access: CaseViewAccess,
) -> CaseResponse:
    return _response(access.case)


@router.patch("/cases/{case_id}", response_model=CaseResponse)
def update_case_endpoint(
    body: CaseUpdateRequest,
    access: CaseEditAccess,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> CaseResponse:
    changes = body.model_dump(exclude_unset=True)
    return _response(
        case_management.update_case(
            session,
            actor=principal.user,
            case_id=access.case.id,
            changes=changes,
        )
    )


@router.post("/cases/{case_id}:transition", response_model=CaseTransitionResponse)
def transition_case_endpoint(
    body: CaseTransitionRequest,
    access: CaseTransitionAccess,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> CaseTransitionResponse:
    return CaseTransitionResponse.model_validate(
        case_management.transition_case(
            session,
            actor=principal.user,
            case_id=access.case.id,
            target=body.to,
            reason=body.reason,
        ),
        from_attributes=True,
    )


@router.get("/cases/{case_id}/dashboard", response_model=CaseDashboardResponse)
def dashboard_endpoint(
    access: CaseViewAccess,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> CaseDashboardResponse:
    return CaseDashboardResponse.model_validate(
        case_management.dashboard(session, actor=principal.user, case_id=access.case.id)
    )


@router.get("/cases/{case_id}/members", response_model=list[CaseMemberResponse])
def list_members_endpoint(
    access: CaseViewAccess,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> list[CaseMemberResponse]:
    return [
        _member_response(m)
        for m in case_management.list_case_members(
            session, actor=principal.user, case_id=access.case.id
        )
    ]


@router.post("/cases/{case_id}/members", response_model=CaseMemberResponse, status_code=201)
def add_member_endpoint(
    body: CaseMemberCreateRequest,
    access: CaseMemberManageAccess,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> CaseMemberResponse:
    member = case_management.add_member(
        session,
        actor=principal.user,
        case_id=access.case.id,
        user_id=body.user_id,
        case_role=body.case_role,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        capability_overrides=body.capability_overrides,
        can_view_original_content=body.can_view_original_content,
        can_verify_findings=body.can_verify_findings,
    )
    return _member_response(member)


@router.patch("/cases/{case_id}/members/{user_id}", response_model=CaseMemberResponse)
def update_member_endpoint(
    body: CaseMemberUpdateRequest,
    access: CaseMemberManageAccess,
    principal: CurrentPrincipal,
    session: SessionDep,
    user_id: UUID,
) -> CaseMemberResponse:
    return _member_response(
        case_management.update_member(
            session,
            actor=principal.user,
            case_id=access.case.id,
            user_id=user_id,
            changes=body.model_dump(exclude_unset=True),
        )
    )


@router.delete("/cases/{case_id}/members/{user_id}", status_code=204)
def revoke_member_endpoint(
    access: CaseMemberManageAccess,
    principal: CurrentPrincipal,
    session: SessionDep,
    user_id: UUID,
) -> None:
    case_management.revoke_member(
        session,
        actor=principal.user,
        case_id=access.case.id,
        user_id=user_id,
    )


__all__ = ["router"]
