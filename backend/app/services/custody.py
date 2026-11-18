"""M6 append-only custody ledger and deterministic hash-chain verification."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationError
from app.models.evidence import CustodyEvent, EvidenceItem, GENESIS_PREV_HASH
from app.models.enums import CustodyEventType
from app.models.identity import User
from app.repositories.custody import latest_event, list_events
from app.repositories.evidence import get_evidence
from app.services.authorization import authorize_case_access


def canonical_payload(event: CustodyEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "case_id": event.case_id,
        "evidence_id": event.evidence_id,
        "sequence": event.sequence,
        "event_type": event.event_type,
        "actor_id": event.actor_id,
        "system_actor": event.system_actor,
        "acted_at": event.acted_at,
        "sha256_at_event": event.sha256_at_event,
        "purpose": event.purpose,
        "ip": event.ip,
        "user_agent": event.user_agent,
        "request_id": event.request_id,
        "recipient_id": event.recipient_id,
        "detail": event.detail,
        "prev_hash": event.prev_hash,
    }


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda value: value.value if hasattr(value, "value") else str(value),
    ).encode("utf-8")


def record_digest(event: CustodyEvent) -> str:
    return hashlib.sha256(canonical_json(canonical_payload(event))).hexdigest()


def append_event(
    session: Session,
    *,
    actor: User | None,
    case_id: UUID,
    evidence: EvidenceItem,
    event_type: CustodyEventType,
    purpose: str | None,
    system_actor: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    recipient_id: UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> CustodyEvent:
    if actor is None and not system_actor:
        raise ValidationError("A custody event requires a human or system actor")
    if actor is not None and system_actor is not None:
        raise ValidationError("A custody event cannot name both actor types")
    if event_type in {
        CustodyEventType.ACCESSED,
        CustodyEventType.DOWNLOADED,
        CustodyEventType.EXPORTED,
    } and not purpose:
        raise ValidationError("Content access and export custody events require a purpose")
    if evidence.case_id != case_id:
        raise ValidationError("Evidence does not belong to the supplied case")

    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"truthlens.custody.chain:{case_id}"},
    )
    previous = latest_event(session, case_id=case_id)
    sequence = (previous.sequence + 1) if previous else 1
    prev_hash = previous.record_hash if previous else GENESIS_PREV_HASH
    event = CustodyEvent(
        case_id=case_id,
        evidence_id=evidence.id,
        sequence=sequence,
        event_type=event_type,
        actor_id=actor.id if actor is not None else None,
        system_actor=system_actor,
        acted_at=datetime.now(UTC),
        sha256_at_event=evidence.physical_object.sha256,
        purpose=purpose,
        ip=ip,
        user_agent=user_agent,
        request_id=request_id,
        recipient_id=recipient_id,
        detail=detail or {},
        prev_hash=prev_hash,
        record_hash="0" * 64,
    )
    event.record_hash = record_digest(event)
    session.add(event)
    return event


def verify_chain(
    session: Session, *, actor: User, case_id: UUID, evidence_id: UUID | None = None
) -> tuple[bool, UUID | None]:
    authorize_case_access(
        session, user=actor, case_id=case_id, capability="view_evidence"
    )
    events = list_events(session, case_id=case_id, evidence_id=evidence_id)
    expected_prev = GENESIS_PREV_HASH
    for event in events:
        if event.prev_hash != expected_prev:
            return False, event.id
        if record_digest(event) != event.record_hash:
            return False, event.id
        expected_prev = event.record_hash
    return True, None


def evidence_for_custody(
    session: Session, *, actor: User, evidence_id: UUID
) -> EvidenceItem:
    item = get_evidence(session, evidence_id)
    if item is None:
        raise NotFoundError()
    authorize_case_access(
        session, user=actor, case_id=item.case_id, capability="view_evidence"
    )
    return item
