# fmt: off
"""M5 evidence API schemas."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EvidenceStatus, EvidenceType, IntegrityStatus, Sensitivity, SourceType


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    physical_object_id: UUID
    evidence_number: str
    original_filename: str
    sanitized_filename: str
    item_type: EvidenceType
    subcategory: str | None
    status: EvidenceStatus
    integrity_status: IntegrityStatus
    source_type: SourceType
    size_bytes: int
    sha256: str
    detected_mime: str
    declared_mime: str | None
    submitted_by: UUID
    acquired_at: datetime | None
    acquisition_method: str | None
    acquisition_device: str | None
    collection_location: str | None
    notes: str | None
    tags: list[str]
    sensitivity_override: Sensitivity | None
    created_at: datetime
    updated_at: datetime


class EvidenceListResponse(BaseModel):
    items: list[EvidenceResponse]
    total: int


class EvidenceUploadMetadata(BaseModel):
    item_type: EvidenceType
    acquisition_method: str | None = Field(default=None, max_length=500)
    acquisition_device: str | None = Field(default=None, max_length=500)
    collection_location: str | None = Field(default=None, max_length=1000)
    notes: str | None = Field(default=None, max_length=5000)
    tags: list[str] = Field(default_factory=list, max_length=50)
    sensitivity_override: Sensitivity | None = None
    acquired_at: datetime | None = None


class EvidenceIntegrityResponse(BaseModel):
    evidence_id: UUID
    status: IntegrityStatus
    expected_sha256: str
    actual_sha256: str | None
    checked_at: datetime

# fmt: on
