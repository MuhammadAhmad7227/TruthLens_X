"""Business rules for durable asynchronous jobs."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.models.analysis import AnalysisJob
from app.models.enums import JobStatus
from app.models.identity import User
from app.services.authorization import authorize_case_access
from app.tasks.jobs import execute_job

MAX_PIPELINE_NAME_LENGTH = 200
MAX_JOB_PRIORITY = 9


def _params_hash(params: dict[str, Any]) -> str:
    payload = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(payload).hexdigest()


def get_job(session: Session, *, actor: User, case_id: UUID, job_id: UUID) -> AnalysisJob:
    authorize_case_access(session, user=actor, case_id=case_id, capability="view_case")
    job = session.scalar(
        select(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.case_id == case_id)
    )
    if job is None:
        raise NotFoundError()
    return job


def create_job(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    pipeline: str,
    pipeline_version: str,
    params: dict[str, Any],
    queue: str,
    priority: int = 5,
    evidence_id: UUID | None = None,
    idempotency_key: UUID | None = None,
) -> AnalysisJob:
    authorize_case_access(session, user=actor, case_id=case_id, capability="view_case")
    if not pipeline or len(pipeline) > MAX_PIPELINE_NAME_LENGTH:
        raise ValidationError("pipeline is required and must be at most 200 characters")
    if queue not in {"analysis.cpu", "analysis.gpu", "ingest", "reports", "maintenance"}:
        raise ValidationError("Unsupported queue")
    if not 0 <= priority <= MAX_JOB_PRIORITY:
        raise ValidationError("priority must be between 0 and 9")

    digest = _params_hash(params)
    if idempotency_key is not None:
        existing = session.scalar(
            select(AnalysisJob).where(
                AnalysisJob.case_id == case_id,
                AnalysisJob.idempotency_key == str(idempotency_key),
            )
        )
        if existing is not None:
            if existing.params_hash != digest or existing.pipeline != pipeline:
                raise ConflictError("Idempotency key was already used for a different job")
            return existing

    job = AnalysisJob(
        case_id=case_id,
        evidence_id=evidence_id,
        pipeline=pipeline,
        pipeline_version=pipeline_version,
        params=params,
        params_hash=digest,
        priority=priority,
        queue=queue,
        status=JobStatus.QUEUED,
        requested_by=actor.id,
        idempotency_key=str(idempotency_key) if idempotency_key is not None else None,
        queued_at=datetime.now(UTC),
        progress_pct=0,
        progress_message="Queued",
    )
    session.add(job)
    session.flush()
    try:
        async_result = execute_job.apply_async(args=[str(job.id)], queue=queue)
        job.celery_task_id = async_result.id
        session.commit()
    except Exception as exc:
        session.rollback()
        raise ValidationError("Worker queue is unavailable") from exc
    return job


def cancel_job(session: Session, *, actor: User, case_id: UUID, job_id: UUID) -> AnalysisJob:
    job = get_job(session, actor=actor, case_id=case_id, job_id=job_id)
    if job.status in {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.DEAD_LETTER}:
        raise ConflictError("Completed jobs cannot be cancelled")
    job.status = JobStatus.CANCELLED
    job.finished_at = datetime.now(UTC)
    job.progress_message = "Cancelled by user"
    session.commit()
    return job
