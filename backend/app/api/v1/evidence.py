# fmt: off
"""M5 evidence endpoints: ingest, list, metadata and integrity verification."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, File, Form, Query, UploadFile
from fastapi.responses import StreamingResponse

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.deps import SessionDep
from app.api.v1.evidence_schemas import (
    EvidenceIntegrityResponse,
    EvidenceListResponse,
    EvidenceResponse,
)
from app.core.config import get_settings
from app.core.errors import ValidationError
from app.services import evidence as evidence_service

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"])


def _response(item) -> EvidenceResponse:
    return EvidenceResponse.model_validate(evidence_service._item_response(item))


@router.post("", response_model=EvidenceResponse, status_code=201)
def upload_evidence(
    case_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
    file: Annotated[UploadFile, File()],
    item_type: Annotated[str, Form()],
    acquisition_method: Annotated[str | None, Form()] = None,
    acquisition_device: Annotated[str | None, Form()] = None,
    collection_location: Annotated[str | None, Form()] = None,
    notes: Annotated[str | None, Form()] = None,
    tags: Annotated[str | None, Form()] = None,
    acquired_at: Annotated[str | None, Form()] = None,
) -> EvidenceResponse:
    if not file.filename:
        raise ValidationError("A filename is required")
    acquired = None
    if acquired_at:
        try:
            acquired = datetime.fromisoformat(acquired_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("acquired_at must be an ISO-8601 timestamp") from exc
    item = evidence_service.ingest(
        session,
        settings=get_settings(),
        actor=principal.user,
        case_id=case_id,
        source=file.file,
        filename=file.filename,
        declared_mime=file.content_type,
        item_type=item_type,
        acquisition_method=acquisition_method,
        acquisition_device=acquisition_device,
        collection_location=collection_location,
        notes=notes,
        tags=[tag.strip() for tag in (tags or "").split(",") if tag.strip()],
        acquired_at=acquired,
    )
    return _response(item)


@router.get("", response_model=EvidenceListResponse)
def list_case_evidence(
    case_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EvidenceListResponse:
    items, total = evidence_service.list_for_case(
        session, actor=principal.user, case_id=case_id, limit=limit, offset=offset
    )
    return EvidenceListResponse(
        items=[_response(item) for item in items],
        total=total,
    )


@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(
    evidence_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> EvidenceResponse:
    return _response(
        evidence_service.get_one(session, actor=principal.user, evidence_id=evidence_id)
    )


@router.post("/{evidence_id}/verify", response_model=EvidenceIntegrityResponse)
def verify_evidence(
    evidence_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> EvidenceIntegrityResponse:
    check = evidence_service.verify_integrity(
        session, settings=get_settings(), actor=principal.user, evidence_id=evidence_id
    )
    return EvidenceIntegrityResponse(
        evidence_id=evidence_id,
        status=check.result,
        expected_sha256=check.expected_sha256,
        actual_sha256=check.actual_sha256,
        checked_at=check.checked_at,
    )


@router.get("/{evidence_id}/content")
def download_evidence(
    evidence_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
    purpose: Annotated[str, Query(min_length=3, max_length=500)],
) -> StreamingResponse:
    item, content = evidence_service.prepare_download(
        session,
        settings=get_settings(),
        actor=principal.user,
        evidence_id=evidence_id,
        purpose=purpose,
    )
    headers = {
        "Content-Disposition": f'attachment; filename="{item.sanitized_filename.replace(chr(34), "")}"',
        "X-Evidence-SHA256": item.physical_object.sha256,
    }
    return StreamingResponse(
        content,
        media_type=item.physical_object.detected_mime,
        headers=headers,
    )

# fmt: on
