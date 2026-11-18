# fmt: off
"""M6 custody ledger and verification endpoints."""
from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.custody_schemas import CustodyEventResponse, CustodyVerificationResponse
from app.api.v1.deps import SessionDep
from app.services import custody as custody_service

router = APIRouter(prefix="/cases/{case_id}/custody", tags=["custody"])


@router.get("", response_model=list[CustodyEventResponse])
def list_case_custody(
    case_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
    evidence_id: Annotated[UUID | None, Query()] = None,
) -> list[CustodyEventResponse]:
    events = custody_service.list_for_case(
        session, actor=principal.user, case_id=case_id, evidence_id=evidence_id
    )
    return [CustodyEventResponse.model_validate(event) for event in events]


@router.post("/verify", response_model=CustodyVerificationResponse)
def verify_case_custody(
    case_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
    evidence_id: Annotated[UUID | None, Query()] = None,
) -> CustodyVerificationResponse:
    valid, broken = custody_service.verify_chain(
        session, actor=principal.user, case_id=case_id, evidence_id=evidence_id
    )
    return CustodyVerificationResponse(valid=valid, broken_at_record_id=broken)

# fmt: on
