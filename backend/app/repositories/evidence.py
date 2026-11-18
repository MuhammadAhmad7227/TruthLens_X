# fmt: off
"""Persistence helpers for M5 evidence ingest."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.evidence import EvidenceItem, PhysicalObject


def get_evidence(session: Session, evidence_id: UUID) -> EvidenceItem | None:
    return session.scalar(
        select(EvidenceItem).where(EvidenceItem.id == evidence_id, EvidenceItem.deleted_at.is_(None))
    )


def get_physical_object_by_sha256(session: Session, sha256: str) -> PhysicalObject | None:
    return session.scalar(select(PhysicalObject).where(PhysicalObject.sha256 == sha256))


def next_evidence_number(session: Session, case_id: UUID) -> str:
    count = int(
        session.scalar(
            select(func.count()).select_from(EvidenceItem).where(
                EvidenceItem.case_id == case_id
            )
        )
        or 0
    )
    return f"EXH-{count + 1:04d}"


def list_evidence(
    session: Session, *, case_id: UUID, limit: int = 100, offset: int = 0
) -> tuple[list[EvidenceItem], int]:
    base = select(EvidenceItem).where(
        EvidenceItem.case_id == case_id, EvidenceItem.deleted_at.is_(None)
    )
    total = int(session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    items = list(
        session.scalars(
            base.order_by(EvidenceItem.created_at.desc()).limit(limit).offset(offset)
        ).all()
    )
    return items, total

# fmt: on
