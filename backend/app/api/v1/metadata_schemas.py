"""Metadata API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class MetadataRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    extractor: str
    extractor_version: str
    invocation_args: dict[str, Any]
    raw_tags: dict[str, Any]
    normalised: dict[str, Any]
    extraction_job_id: UUID | None
    stripping_signals: dict[str, Any]
    source_sha256: str
    extracted_at: datetime


class MetadataListResponse(BaseModel):
    items: list[MetadataRecordResponse]
    total: int


class MetadataExtractResponse(BaseModel):
    job_id: UUID
    status: str
    pipeline: str
    pipeline_version: str


class MetadataDiffResponse(BaseModel):
    evidence_id: UUID
    base_id: UUID
    other_id: UUID
    changes: dict[str, dict[str, Any]]
