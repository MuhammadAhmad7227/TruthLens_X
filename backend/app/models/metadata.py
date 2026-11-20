"""Metadata extraction persistence models (M8).

The metadata table stores the complete extractor output plus a curated, stable normalised view.
Raw evidence bytes are never stored here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Index, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UTCDateTime
from app.models.types import SHA256

__all__ = ["MetadataRecord"]


class MetadataRecord(Base):
    """One reproducible metadata extraction for an evidence item."""

    __tablename__ = "metadata_records"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    evidence_id: Mapped[UUID] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="CASCADE"), nullable=False
    )
    extractor: Mapped[str] = mapped_column(Text, nullable=False)
    extractor_version: Mapped[str] = mapped_column(Text, nullable=False)
    invocation_args: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    raw_tags: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    normalised: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    extraction_job_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True, default=None
    )
    stripping_signals: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    source_sha256: Mapped[str] = mapped_column(SHA256, nullable=False)
    extracted_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, server_default=text("now()")
    )

    evidence: Mapped[Any] = relationship(foreign_keys=[evidence_id])
    job: Mapped[Any] = relationship(foreign_keys=[extraction_job_id])

    __table_args__ = (
        UniqueConstraint(
            "evidence_id",
            "extractor",
            "extractor_version",
            name="uq_metadata_records_evidence_extractor_version",
        ),
        Index("ix_metadata_records_evidence_extracted_at", "evidence_id", "extracted_at"),
    )
