"""M4 case-management request and response contracts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20_000)
    sensitivity: str = Field(pattern=r"^(public|internal|confidential|restricted)$")
    case_type: str | None = Field(default=None, max_length=100)
    jurisdiction: str | None = Field(default=None, max_length=200)
    lead_investigator_id: UUID | None = None
    statutory_deadline: datetime | None = None
    tags: list[str] = Field(default_factory=list, max_length=50)


class CaseUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20_000)
    sensitivity: str | None = Field(
        default=None, pattern=r"^(public|internal|confidential|restricted)$"
    )
    case_type: str | None = Field(default=None, max_length=100)
    jurisdiction: str | None = Field(default=None, max_length=200)
    lead_investigator_id: UUID | None = None
    statutory_deadline: datetime | None = None
    tags: list[str] | None = Field(default=None, max_length=50)


class CaseTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: str = Field(pattern=r"^(draft|active|under_review|closed|archived)$")
    reason: str = Field(min_length=1, max_length=2000)


class CaseMemberCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    case_role: str = Field(pattern=r"^(owner|lead|member|contributor|viewer)$")
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    capability_overrides: list[str] = Field(default_factory=list, max_length=50)
    can_view_original_content: bool = True
    can_verify_findings: bool = False


class CaseMemberUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_role: str | None = Field(default=None, pattern=r"^(owner|lead|member|contributor|viewer)$")
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    capability_overrides: list[str] | None = Field(default=None, max_length=50)
    can_view_original_content: bool | None = None
    can_verify_findings: bool | None = None


class CaseResponse(BaseModel):
    id: UUID
    case_number: str
    title: str
    description: str | None
    status: str
    sensitivity: str
    case_type: str | None
    jurisdiction: str | None
    lead_investigator_id: UUID | None
    statutory_deadline: datetime | None
    legal_hold: bool
    storage_quota_bytes: int | None
    storage_used_bytes: int
    tags: list[str]
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class CaseMemberResponse(BaseModel):
    case_id: UUID
    user_id: UUID
    case_role: str
    valid_from: datetime | None
    valid_until: datetime | None
    capability_overrides: list[str]
    can_view_original_content: bool
    can_verify_findings: bool
    revoked_at: datetime | None


class CaseTransitionResponse(CaseResponse):
    pass


class CaseDashboardResponse(BaseModel):
    case_id: UUID
    status: str
    evidence_count: int
    analysis_job_count: int
    finding_count: int
    verification_backlog: int
    integrity_exception_count: int
    storage_used_bytes: int
