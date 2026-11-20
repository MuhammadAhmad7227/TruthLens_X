"""Normalised geographic metadata extracted from evidence."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Index, Numeric, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UTCDateTime


class Location(Base):
    __tablename__ = "locations"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    evidence_id: Mapped[UUID] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="CASCADE"), nullable=False
    )
    latitude: Mapped[Decimal] = mapped_column(Numeric(9, 6), nullable=False)
    longitude: Mapped[Decimal] = mapped_column(Numeric(9, 6), nullable=False)
    altitude_m: Mapped[Decimal | None] = mapped_column(Numeric(12, 3), nullable=True)
    uncertainty_m: Mapped[Decimal | None] = mapped_column(Numeric(12, 3), nullable=True)
    precision_digits: Mapped[int | None] = mapped_column(nullable=True)
    geohash: Mapped[str | None] = mapped_column(Text, nullable=True)
    gazetteer_match: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )
    source: Mapped[str] = mapped_column(Text, nullable=False, default="exif_gps")
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, server_default=text("now()")
    )

    evidence: Mapped[Any] = relationship()

    __table_args__ = (
        Index("ix_locations_evidence", "evidence_id"),
        Index("ix_locations_geohash", "geohash"),
    )


__all__ = ["Location"]
