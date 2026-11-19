"""Celery application configuration."""

from __future__ import annotations

from celery import Celery

from app.core.config import get_settings


def build_celery_app() -> Celery:
    settings = get_settings()
    if not settings.celery_broker_url:
        raise RuntimeError("CELERY_BROKER_URL is required to run a worker")
    app = Celery("truthlens")
    app.conf.update(
        broker_url=settings.celery_broker_url,
        result_backend=settings.celery_result_backend,
        task_serializer=settings.celery_task_serializer,
        accept_content=settings.celery_accept_content,
        task_acks_late=settings.celery_task_acks_late,
        worker_prefetch_multiplier=settings.celery_worker_prefetch_multiplier,
        task_soft_time_limit=settings.celery_task_soft_time_limit,
        task_time_limit=settings.celery_task_time_limit,
        task_default_retry_delay=settings.celery_task_default_retry_delay,
        task_default_max_retries=settings.celery_task_max_retries,
        timezone=settings.celery_timezone,
        enable_utc=True,
        task_track_started=True,
        task_send_sent_event=True,
        broker_connection_retry_on_startup=True,
        task_routes={"truthlens.jobs.execute": {"queue": "analysis.cpu"}},
        imports=("app.tasks.jobs",),
    )
    return app


try:
    celery_app = build_celery_app()
except RuntimeError:
    celery_app = Celery("truthlens")
    celery_app.conf.task_always_eager = True
