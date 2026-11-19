"""M7 job API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class CreateJobRequest(BaseModel):
    pipeline: str = Field(min_length=1, max_length=200)
    pipeline_version: str = Field(min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)
    queue: str = "analysis.cpu"
    priority: int = Field(default=5, ge=0, le=9)
    evidence_id: UUID | None = None
    idempotency_key: UUID | None = None


class JobResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    case_id: UUID
    evidence_id: UUID | None
    pipeline: str
    pipeline_version: str
    status: str
    queue: str | None
    celery_task_id: str | None
    attempt: int
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    progress_pct: int | None
    progress_message: str | None
    error_class: str | None
    error_detail: dict[str, Any] | None


class JobCreateResponse(BaseModel):
    job_id: UUID
    status: str
    status_url: str
    progress_url: str
