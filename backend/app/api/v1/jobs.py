"""M7 asynchronous job endpoints."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.deps import SessionDep
from app.api.v1.job_schemas import CreateJobRequest, JobCreateResponse, JobResponse
from app.db.session import get_session_factory
from app.models.enums import JobStatus
from app.services import jobs as job_service

router = APIRouter(prefix="/cases/{case_id}/jobs", tags=["jobs"])


def _response(job: object) -> JobResponse:
    return JobResponse.model_validate(job)


@router.post("", response_model=JobCreateResponse, status_code=202)
def create(
    case_id: UUID,
    body: CreateJobRequest,
    request: Request,
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
        request_id=getattr(request.state, "request_id", None),
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
        job_service.get_job(
            session,
            actor=principal.user,
            case_id=case_id,
            job_id=job_id,
        )
    )


@router.post("/{job_id}:retry", response_model=JobResponse, status_code=202)
def retry(
    case_id: UUID,
    job_id: UUID,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> JobResponse:
    return _response(
        job_service.retry_job(
            session,
            actor=principal.user,
            case_id=case_id,
            job_id=job_id,
            request_id=getattr(request.state, "request_id", None),
        )
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
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> StreamingResponse:
    job_service.get_job(session, actor=principal.user, case_id=case_id, job_id=job_id)
    session.close()
    raw_last_id = request.headers.get("Last-Event-ID")
    try:
        last_event_id = int(raw_last_id) if raw_last_id else 0
    except ValueError:
        last_event_id = 0

    async def stream() -> AsyncIterator[str]:
        factory = get_session_factory()
        sequence = max(last_event_id, 0)
        last_marker: datetime | None = None
        while True:
            stream_session = factory()
            try:
                current = job_service.get_job(
                    stream_session, actor=principal.user, case_id=case_id, job_id=job_id
                )
                payload = _response(current).model_dump(mode="json")
                updated_at = getattr(current, "updated_at", None)
                changed = updated_at != last_marker
                candidate = (
                    int(updated_at.timestamp() * 1_000_000)
                    if updated_at is not None
                    else sequence + 1
                )
                if changed:
                    sequence = max(sequence + 1, candidate)
                    last_marker = updated_at
                terminal = current.status in {
                    JobStatus.SUCCEEDED,
                    JobStatus.FAILED,
                    JobStatus.CANCELLED,
                    JobStatus.DEAD_LETTER,
                }
            finally:
                stream_session.close()

            if changed or terminal:
                yield (
                    f"id: {sequence}\n"
                    f"event: job\n"
                    f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"
                )
            if terminal:
                break
            await asyncio.sleep(1)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
