"""Business rules for durable asynchronous jobs."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    NotFoundError,
    ValidationError,
)
from app.models.analysis import AnalysisJob
from app.models.enums import JobStatus
from app.models.identity import User
from app.services.authorization import authorize_case_access
from app.tasks.jobs import execute_job

MAX_PIPELINE_NAME_LENGTH = 200
MAX_JOB_PRIORITY = 9
_ALLOWED_QUEUES = {"analysis.cpu", "analysis.gpu", "ingest", "reports", "maintenance"}


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
    request_id: str | None = None,
) -> AnalysisJob:
    authorize_case_access(session, user=actor, case_id=case_id, capability="view_case")
    if not pipeline or len(pipeline) > MAX_PIPELINE_NAME_LENGTH:
        raise ValidationError("pipeline is required and must be at most 200 characters")
    if queue not in _ALLOWED_QUEUES:
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
        headers = {"request_id": request_id} if request_id else None
        async_result = execute_job.apply_async(
            args=[str(job.id)],
            queue=queue,
            priority=priority,
            headers=headers,
        )
        job.celery_task_id = async_result.id
        session.commit()
    except Exception as exc:
        session.rollback()
        raise DependencyUnavailableError("Worker queue is unavailable") from exc
    return job


def list_jobs(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    status: JobStatus | None = None,
    pipeline: str | None = None,
    evidence_id: UUID | None = None,
    requested_by: UUID | None = None,
) -> list[AnalysisJob]:
    authorize_case_access(session, user=actor, case_id=case_id, capability="view_case")
    stmt = (
        select(AnalysisJob)
        .where(AnalysisJob.case_id == case_id)
        .order_by(AnalysisJob.queued_at.desc())
    )
    if status is not None:
        stmt = stmt.where(AnalysisJob.status == status)
    if pipeline is not None:
        stmt = stmt.where(AnalysisJob.pipeline == pipeline)
    if evidence_id is not None:
        stmt = stmt.where(AnalysisJob.evidence_id == evidence_id)
    if requested_by is not None:
        stmt = stmt.where(AnalysisJob.requested_by == requested_by)
    return list(session.scalars(stmt).all())


def retry_job(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    job_id: UUID,
    request_id: str | None = None,
) -> AnalysisJob:
    job = get_job(session, actor=actor, case_id=case_id, job_id=job_id)
    if job.status not in {JobStatus.FAILED, JobStatus.DEAD_LETTER}:
        raise ConflictError("Only failed or dead-lettered jobs can be retried")
    job.status = JobStatus.QUEUED
    job.finished_at = None
    job.error_class = None
    job.error_detail = None
    job.progress_pct = 0
    job.progress_message = "Retry queued"
    job.queued_at = datetime.now(UTC)
    job.celery_task_id = None
    session.flush()
    try:
        headers = {"request_id": request_id} if request_id else None
        async_result = execute_job.apply_async(
            args=[str(job.id)],
            queue=job.queue or "analysis.cpu",
            priority=job.priority,
            headers=headers,
        )
        job.celery_task_id = async_result.id
        session.commit()
    except Exception as exc:
        session.rollback()
        raise ValidationError("Worker queue is unavailable") from exc
    return job


def cancel_job(session: Session, *, actor: User, case_id: UUID, job_id: UUID) -> AnalysisJob:
    job = get_job(session, actor=actor, case_id=case_id, job_id=job_id)
    if job.status in {
        JobStatus.SUCCEEDED,
        JobStatus.FAILED,
        JobStatus.DEAD_LETTER,
        JobStatus.CANCELLED,
    }:
        raise ConflictError("Completed jobs cannot be cancelled")
    job.status = JobStatus.CANCELLED
    job.finished_at = datetime.now(UTC)
    job.progress_message = "Cancelled by user"
    session.commit()
    return job
