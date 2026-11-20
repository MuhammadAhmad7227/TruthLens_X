"""Administrative worker and queue monitoring for M7."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import redis
from celery import Celery
from fastapi import APIRouter, HTTPException
from sqlalchemy import func, select

from app.api.v1.auth_deps import CurrentPrincipal
from app.core.config import get_settings
from app.core.errors import ForbiddenRoleError, ValidationError
from app.db.session import get_session_factory
from app.models.analysis import AnalysisJob
from app.models.enums import JobStatus
from app.services import jobs as job_service

router = APIRouter(prefix="/admin", tags=["jobs"])


_ALLOWED_QUEUES = {"ingest", "analysis.cpu", "analysis.gpu", "reports", "maintenance"}


def _require_admin(principal: CurrentPrincipal) -> None:
    if principal.user.global_role.value != "admin":
        raise ForbiddenRoleError("Administrator role required")


def _queue_lengths(broker_url: str) -> dict[str, int]:
    client = redis.Redis.from_url(broker_url, decode_responses=True)
    try:
        return {
            queue: int(client.llen(queue))
            for queue in (
                "ingest",
                "analysis.cpu",
                "analysis.gpu",
                "reports",
                "maintenance",
            )
        }
    finally:
        client.close()


@router.get("/queues")
def monitor(principal: CurrentPrincipal) -> dict[str, Any]:
    _require_admin(principal)
    settings = get_settings()
    broker_url = settings.celery_broker_url
    if broker_url is None:
        raise ValidationError("CELERY_BROKER_URL is not configured")
    celery = Celery("truthlens-monitor", broker=broker_url)
    inspect = celery.control.inspect(timeout=1.0)
    active = inspect.active() or {}
    reserved = inspect.reserved() or {}
    stats = inspect.stats() or {}
    try:
        queues = _queue_lengths(broker_url)
    except Exception:
        queues = {}

    session = get_session_factory()()
    try:
        since = datetime.now(UTC) - timedelta(hours=1)
        metrics: dict[str, dict[str, Any]] = {}
        for queue in _ALLOWED_QUEUES:
            rows = session.execute(
                select(AnalysisJob.status, func.count(AnalysisJob.id))
                .where(AnalysisJob.queue == queue)
                .group_by(AnalysisJob.status)
            ).all()
            counts = {status.value: int(count) for status, count in rows}
            completed_last_hour = session.scalar(
                select(func.count(AnalysisJob.id)).where(
                    AnalysisJob.queue == queue,
                    AnalysisJob.status == JobStatus.SUCCEEDED,
                    AnalysisJob.finished_at >= since,
                )
            )
            metrics[queue] = {
                "depth": queues.get(queue, 0),
                "running": counts.get("running", 0),
                "reserved": sum(len(items) for items in reserved.values()),
                "succeeded": counts.get("succeeded", 0),
                "failed": counts.get("failed", 0),
                "retrying": counts.get("retrying", 0),
                "dead_letter": counts.get("dead_letter", 0),
                "throughput_last_hour": int(completed_last_hour or 0),
            }
    finally:
        session.close()

    return {
        "workers": {
            name: {
                "active": len(active.get(name, [])),
                "reserved": len(reserved.get(name, [])),
                "stats": stats.get(name),
            }
            for name in sorted(set(active) | set(reserved) | set(stats))
        },
        "queues": metrics,
    }


@router.post("/queues/{queue_name}:purge")
def purge_queue_endpoint(queue_name: str, principal: CurrentPrincipal) -> dict[str, object]:
    _require_admin(principal)
    if queue_name not in _ALLOWED_QUEUES:
        raise ValidationError("Unsupported queue")
    settings = get_settings()
    if settings.celery_broker_url is None:
        raise ValidationError("CELERY_BROKER_URL is not configured")
    client = redis.Redis.from_url(settings.celery_broker_url, decode_responses=True)
    try:
        keys = list(client.scan_iter(match=f"{queue_name}*"))
        removed = int(client.delete(*keys)) if keys else 0
    finally:
        client.close()
    return {"queue": queue_name, "removed_keys": removed}


@router.post("/jobs/{job_id}:requeue")
def requeue_job(job_id: str, principal: CurrentPrincipal) -> dict[str, object]:
    _require_admin(principal)
    session = get_session_factory()()
    try:
        job = session.get(AnalysisJob, UUID(job_id))
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        queued = job_service.retry_job(
            session,
            actor=principal.user,
            case_id=job.case_id,
            job_id=job.id,
        )
        return {"job_id": str(queued.id), "status": queued.status.value}
    finally:
        session.close()
