"""M7 asynchronous job endpoints."""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from uuid import UUID

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from app.api.v1.auth_deps import CurrentPrincipal
from app.db.session import get_session_factory
from app.api.v1.deps import SessionDep
from app.api.v1.job_schemas import CreateJobRequest, JobCreateResponse, JobResponse
from app.models.enums import JobStatus
from app.services import jobs as job_service

router = APIRouter(prefix="/cases/{case_id}/jobs", tags=["jobs"])


def _response(job: object) -> JobResponse:
    return JobResponse.model_validate(job)


@router.post("", response_model=JobCreateResponse, status_code=202)
def create(
    case_id: UUID,
    body: CreateJobRequest,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> JobCreateResponse:
    job = job_service.create_job(
        session,
        actor=principal.user,
        case_id=case_id,
        pipeline=body.pipeline,
        pipeline_version=body.pipeline_version,
        params=body.params,
        queue=body.queue,
        priority=body.priority,
        evidence_id=body.evidence_id,
        idempotency_key=body.idempotency_key,
    )
    return JobCreateResponse(
        job_id=job.id,
        status=job.status.value,
        status_url=f"/api/v1/cases/{case_id}/jobs/{job.id}",
        progress_url=f"/api/v1/cases/{case_id}/jobs/{job.id}/events",
    )


@router.get("", response_model=list[JobResponse])
def list_all(
    case_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
    status: JobStatus | None = None,
    pipeline: str | None = Query(default=None, max_length=200),
    evidence_id: UUID | None = None,
    requested_by: UUID | None = None,
) -> list[JobResponse]:
    return [
        _response(job)
        for job in job_service.list_jobs(
            session,
            actor=principal.user,
            case_id=case_id,
            status=status,
            pipeline=pipeline,
            evidence_id=evidence_id,
            requested_by=requested_by,
        )
    ]


@router.get("/{job_id}", response_model=JobResponse)
def get(
    case_id: UUID,
    job_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> JobResponse:
    return _response(
        job_service.get_job(session, actor=principal.user, case_id=case_id, job_id=job_id)
    )


@router.post("/{job_id}:retry", response_model=JobResponse, status_code=202)
def retry(
    case_id: UUID,
    job_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> JobResponse:
    return _response(
        job_service.retry_job(session, actor=principal.user, case_id=case_id, job_id=job_id)
    )


@router.post("/{job_id}:cancel", response_model=JobResponse)
def cancel(
    case_id: UUID,
    job_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> JobResponse:
    return _response(
        job_service.cancel_job(session, actor=principal.user, case_id=case_id, job_id=job_id)
    )


@router.get("/{job_id}/events")
async def events(
    case_id: UUID,
    job_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> StreamingResponse:
    job_service.get_job(session, actor=principal.user, case_id=case_id, job_id=job_id)

    async def stream() -> AsyncIterator[str]:
        factory = get_session_factory()
        while True:
            stream_session = factory()
            try:
                current = job_service.get_job(
                    stream_session, actor=principal.user, case_id=case_id, job_id=job_id
                )
                payload = _response(current).model_dump(mode="json")
                terminal = current.status.value in {
                    "succeeded",
                    "failed",
                    "cancelled",
                    "dead_letter",
                }
            finally:
                stream_session.close()
            yield f"event: job\\ndata: {json.dumps(payload, separators=(',', ':'))}\\n\\n"
            if terminal:
                break
            await asyncio.sleep(1)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
