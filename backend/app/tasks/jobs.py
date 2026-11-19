"""Durable Celery job lifecycle."""

from __future__ import annotations

import socket
import time
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import redis
import structlog
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_session_factory
from app.models.analysis import AnalysisJob
from app.models.enums import JobStatus
from app.tasks.celery_app import celery_app


def _now() -> datetime:
    return datetime.now(UTC)


def _error_class(exc: BaseException) -> str:
    if isinstance(exc, SoftTimeLimitExceeded):
        return "TIMEOUT"
    return type(exc).__name__


def _get_job(session: Session, job_id: UUID) -> AnalysisJob:
    job = session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
    if job is None:
        raise LookupError(f"Analysis job {job_id} does not exist")
    return job


def _mark(session: Any, job: AnalysisJob, status: JobStatus, **fields: Any) -> None:
    job.status = status
    for key, value in fields.items():
        setattr(job, key, value)
    session.commit()


def _analysis_lock(job: AnalysisJob) -> tuple[redis.Redis, Any] | None:
    if job.evidence_id is None:
        return None
    settings = get_settings()
    broker_url = settings.celery_broker_url
    if broker_url is None:
        raise RuntimeError("CELERY_BROKER_URL is not configured")
    client = redis.Redis.from_url(broker_url)
    timeout = max(settings.celery_task_time_limit, settings.celery_task_soft_time_limit) + 60
    lock = client.lock(
        f"truthlens:analysis:{job.evidence_id}:{job.pipeline}",
        timeout=timeout,
        blocking_timeout=0,
    )
    return client, lock


class JobTask(Task):
    max_retries = 3
    acks_late = True

    def on_retry(
        self,
        exc: BaseException,
        task_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        einfo: Any,
    ) -> None:
        session = get_session_factory()()
        try:
            job = _get_job(session, UUID(str(args[0])))
            _mark(
                session,
                job,
                JobStatus.RETRYING,
                celery_task_id=task_id,
                error_class=_error_class(exc),
                progress_message=f"Retrying after {_error_class(exc)}",
            )
        finally:
            session.close()

    def on_failure(
        self,
        exc: BaseException,
        task_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        einfo: Any,
    ) -> None:
        session = get_session_factory()()
        try:
            job = _get_job(session, UUID(str(args[0])))
            _mark(
                session,
                job,
                JobStatus.DEAD_LETTER,
                celery_task_id=task_id,
                finished_at=_now(),
                error_class=_error_class(exc),
                error_detail={"message": str(exc)[:1000]},
                progress_pct=100,
                progress_message="Dead-lettered after retry limit",
            )
        finally:
            session.close()


@celery_app.task(bind=True, base=JobTask, name="truthlens.jobs.execute", ignore_result=True)  # type: ignore[untyped-decorator]
def execute_job(self: JobTask, job_id: str) -> None:
    session = get_session_factory()()
    started = time.monotonic()
    job: AnalysisJob | None = None
    lock_resource: tuple[redis.Redis, Any] | None = None
    lock_acquired = False
    request_id = getattr(self.request, "headers", {}).get("request_id")
    if request_id:
        structlog.contextvars.bind_contextvars(request_id=request_id)
    try:
        job = _get_job(session, UUID(job_id))
        if job.status is JobStatus.CANCELLED:
            return
        _mark(
            session,
            job,
            JobStatus.RUNNING,
            celery_task_id=self.request.id,
            worker_id=socket.gethostname(),
            attempt=job.attempt + 1,
            started_at=_now(),
            progress_pct=1,
            progress_message="Worker accepted job",
        )

        lock_resource = _analysis_lock(job)
        if lock_resource is not None:
            _, lock = lock_resource
            lock_acquired = lock.acquire(blocking=False)
            if not lock_acquired:
                raise RuntimeError("DUPLICATE_ANALYSIS_IN_PROGRESS")

        if not job.pipeline.startswith("maintenance."):
            raise RuntimeError(f"Unsupported pipeline in M7: {job.pipeline}")
        _mark(
            session,
            job,
            JobStatus.SUCCEEDED,
            finished_at=_now(),
            progress_pct=100,
            progress_message="Completed",
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception as exc:
        if job is None:
            raise
        job.error_class = _error_class(exc)
        job.error_detail = {"message": str(exc)[:1000]}
        job.progress_message = "Retry scheduled"
        job.status = JobStatus.RETRYING
        session.commit()
        retry_count = int(getattr(self.request, "retries", 0))
        countdown = min(300, 2**retry_count * 10)
        raise self.retry(exc=exc, countdown=countdown, max_retries=3) from exc
    finally:
        if lock_resource is not None:
            client, lock = lock_resource
            if lock_acquired:
                with suppress(redis.exceptions.LockError):
                    lock.release()
            client.close()
        session.close()
        if request_id:
            structlog.contextvars.unbind_contextvars("request_id")
