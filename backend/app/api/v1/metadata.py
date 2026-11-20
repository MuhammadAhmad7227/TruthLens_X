"""M8 metadata extraction endpoints."""
from __future__ import annotations

from uuid import UUID, uuid4

from fastapi import APIRouter, Header, status

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.deps import SessionDep
from app.api.v1.metadata_schemas import (
    MetadataDiffResponse,
    MetadataExtractResponse,
    MetadataListResponse,
    MetadataRecordResponse,
)
from app.core.config import get_settings
from app.services import jobs as job_service
from app.services import metadata as metadata_service

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["metadata"])


@router.post(
    "/{evidence_id}/metadata:reextract",
    response_model=MetadataExtractResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_metadata_extraction(
    case_id: UUID,
    evidence_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> MetadataExtractResponse:
    metadata_service.assert_case_access(
        session,
        actor=principal.user,
        case_id=case_id,
        evidence_id=evidence_id,
        capability="analyze_evidence",
    )
    job = job_service.create_job(
        session,
        actor=principal.user,
        case_id=case_id,
        evidence_id=evidence_id,
        pipeline="metadata.extract",
        pipeline_version="1.0",
        params={"schema_version": "1.0"},
        queue="analysis.cpu",
        priority=5,
        idempotency_key=idempotency_key or f"metadata-reextract:{evidence_id}:{uuid4()}",
    )
    return MetadataExtractResponse(
        job_id=job.id,
        status=job.status.value,
        pipeline=job.pipeline,
        pipeline_version=job.pipeline_version,
    )


@router.get(
    "/{evidence_id}/metadata",
    response_model=MetadataListResponse,
)
def list_metadata(
    case_id: UUID,
    evidence_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> MetadataListResponse:
    metadata_service.assert_case_access(
        session, actor=principal.user, case_id=case_id, evidence_id=evidence_id
    )
    records = metadata_service.list_for_evidence(
        session, actor=principal.user, evidence_id=evidence_id
    )
    return MetadataListResponse(
        items=[MetadataRecordResponse.model_validate(record) for record in records],
        total=len(records),
    )


@router.get(
    "/{evidence_id}/metadata/latest",
    response_model=MetadataRecordResponse,
)
def latest_metadata(
    case_id: UUID,
    evidence_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> MetadataRecordResponse:
    metadata_service.assert_case_access(
        session, actor=principal.user, case_id=case_id, evidence_id=evidence_id
    )
    record = metadata_service.get_latest(
        session, actor=principal.user, evidence_id=evidence_id
    )
    return MetadataRecordResponse.model_validate(record)


@router.get(
    "/{evidence_id}/metadata/diff",
    response_model=MetadataDiffResponse,
)
def metadata_diff(
    case_id: UUID,
    evidence_id: UUID,
    other: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> MetadataDiffResponse:
    metadata_service.assert_case_access(
        session, actor=principal.user, case_id=case_id, evidence_id=evidence_id
    )
    metadata_service.assert_case_access(
        session, actor=principal.user, case_id=case_id, evidence_id=other
    )
    base = metadata_service.get_latest(session, actor=principal.user, evidence_id=evidence_id)
    comparison = metadata_service.get_latest(session, actor=principal.user, evidence_id=other)
    keys = set(base.normalised) | set(comparison.normalised)
    changes = {
        key: {"before": base.normalised.get(key), "after": comparison.normalised.get(key)}
        for key in sorted(keys)
        if base.normalised.get(key) != comparison.normalised.get(key)
    }
    return MetadataDiffResponse(
        evidence_id=evidence_id,
        base_id=base.id,
        other_id=comparison.id,
        changes=changes,
    )
