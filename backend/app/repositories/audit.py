# fmt: off
# ruff: isort: skip_file
"""Append-only audit-chain writer for M3 authentication events."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.models.audit import AuditLog


_ZERO_HASH = "0" * 64


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def append_audit(
    session: Session,
    *,
    action: str,
    result: str,
    actor_id: UUID | None = None,
    actor_role: str | None = None,
    actor_ip: str | None = None,
    user_agent: str | None = None,
    reason: str | None = None,
    request_id: str | None = None,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one event while serialising writers with a PostgreSQL transaction advisory lock."""
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext('truthlens.audit.chain'))"))
    sequence = int(session.scalar(select(func.coalesce(func.max(AuditLog.sequence), 0))) or 0) + 1
    previous = session.scalar(
        select(AuditLog.record_hash).where(AuditLog.sequence == sequence - 1)
    ) or _ZERO_HASH
    occurred_at = datetime.now(UTC)
    payload = {
        "sequence": sequence,
        "occurred_at": occurred_at.isoformat(),
        "actor_id": actor_id,
        "actor_role": actor_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "result": result,
        "reason": reason,
        "request_id": request_id,
        "metadata": metadata,
        "prev_hash": previous,
    }
    record_hash = hashlib.sha256(_canonical(payload)).hexdigest()
    row = AuditLog(
        sequence=sequence,
        occurred_at=occurred_at,
        actor_id=actor_id,
        actor_role=actor_role,
        actor_ip=actor_ip,
        user_agent=user_agent,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        reason=reason,
        request_id=request_id,
        event_metadata=metadata,
        prev_hash=previous,
        record_hash=record_hash,
    )
    session.add(row)
    return row

# fmt: on
