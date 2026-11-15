"""Declarative base, naming convention and the timestamp mixins every table shares.

Two decisions here shape the whole schema, and both exist to make migrations reviewable.

**A naming convention is registered on the metadata.** Without one, SQLAlchemy derives
constraint names from an internal counter and a hash of the column expressions, so the same
model change can produce a different constraint name on a different machine. ``DATABASE_DESIGN``
§1 principle DB-7 makes migrations the only schema path and §11 requires them to be
*deterministic*; an unnamed CHECK constraint is not deterministic, and renaming one later means
a migration that drops and recreates a constraint on a table holding evidence.

**Timestamps are ``timestamptz``, never ``timestamp``.** DB-6 requires UTC everywhere with
offsets preserved. A naive ``timestamp`` column silently discards the offset of whatever wrote
it, and for a platform whose job is to testify about *when* something happened, that loss is
the defect. ``DateTime(timezone=True)`` maps to ``timestamptz`` on PostgreSQL, which stores an
instant and renders it in the session zone.

Note that nothing here calls ``MetaData.create_all``. DB-7: Alembic migrations are the only
schema path, so the metadata is a source of truth for *comparison* (``alembic check``) and for
reflection in tests, not a way to build a database.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "NAMING_CONVENTION",
    "Base",
    "SoftDeleteMixin",
    "TimestampMixin",
    "UTCDateTime",
]

#: Deterministic names for every auto-generated constraint and index.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: ``timestamptz`` on PostgreSQL. Aliased so the intent is visible at every use site: a column
#: declared with this type stores an instant, not a wall-clock reading.
UTCDateTime = DateTime(timezone=True)


class Base(DeclarativeBase):
    """Base class for every TruthLens X ORM model.

    ``metadata`` carries the naming convention above, so it must be the metadata Alembic compares
    against and the one tests inspect. Reaching for a second ``DeclarativeBase`` would split the
    schema into two graphs that neither ``alembic check`` nor the architecture tests could see
    whole.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    #: Keeps ``Mapped[dict[str, Any]]`` annotations from needing an explicit type argument at
    #: every JSONB column. Only additive mappings live here; anything with a real PostgreSQL
    #: counterpart (uuid, timestamptz, inet, arrays) is declared explicitly at the column so the
    #: DDL is readable without chasing a lookup table.
    type_annotation_map: ClassVar[dict[Any, Any]] = {}


class TimestampMixin:
    """``created_at`` / ``updated_at``, both ``timestamptz NOT NULL``.

    Defaults are **server-side** (``now()``), not Python-side. A client clock that is wrong —
    and in a single-host deployment the app and the database share one clock, but a worker
    container need not — must not be able to write a timestamp the database would disagree
    with. ``updated_at`` is maintained by ``onupdate`` so the ORM keeps it current; rows written
    outside the ORM (a bulk migration, ``psql`` during an incident) will not advance it, which
    is the honest behaviour: the column then means "last updated through the application".
    """

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class SoftDeleteMixin:
    """``deleted_at`` — the soft-delete marker required by §1.1.

    Nothing in TruthLens X is hard-deleted while a case holds it (§12). Deactivation preserves
    attribution: a forensic platform that can no longer answer "who did this" has lost the
    property it exists to provide. Unique constraints that must ignore soft-deleted rows are
    declared as **partial** indexes (``WHERE deleted_at IS NULL``) at the model, because a plain
    UNIQUE would permanently burn an email address or case number that was deactivated.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime,
        nullable=True,
        default=None,
    )
