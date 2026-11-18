"""Persistence helpers for the append-only custody ledger."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence import CustodyEvent


def list_events(
    session: Session, *, case_id: UUID, evidence_id: UUID | None = None
) -> list[CustodyEvent]:
    stmt = select(CustodyEvent).where(CustodyEvent.case_id == case_id)
    if evidence_id is not None:
        stmt = stmt.where(CustodyEvent.evidence_id == evidence_id)
    return list(session.scalars(stmt.order_by(CustodyEvent.sequence.asc())).all())


def latest_event(session: Session, *, case_id: UUID) -> CustodyEvent | None:
    return session.scalar(
        select(CustodyEvent)
        .where(CustodyEvent.case_id == case_id)
        .order_by(CustodyEvent.sequence.desc())
        .limit(1)
    )
