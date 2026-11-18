# fmt: off
"""M6 custody API schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CustodyEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    evidence_id: UUID | None
    sequence: int
    event_type: str
    actor_id: UUID | None
    system_actor: str | None
    acted_at: datetime
    sha256_at_event: str
    purpose: str | None
    ip: str | None
    user_agent: str | None
    request_id: str | None
    recipient_id: UUID | None
    detail: dict[str, Any]


class CustodyVerificationResponse(BaseModel):
    valid: bool
    broken_at_record_id: UUID | None

# fmt: on
