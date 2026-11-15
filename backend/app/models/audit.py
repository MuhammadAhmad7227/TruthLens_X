"""``audit_logs`` — the platform-wide, append-only, hash-chained record of who did what (§8.3).

This is not a debug log and it is not the same ledger as ``custody_events``. ``custody_events``
answers "what happened to this item of evidence, in this case"; ``audit_logs`` answers "what did
this actor do on this platform", including the things that were refused. Both are append-only, both
are hash-chained, and §12 says both **outlive the case** — which is why ``case_id`` is
``ON DELETE RESTRICT`` here: destroying a case must not be able to destroy the record of what was
done in it.

Append-only is enforced three ways, because one way is never enough:

1. No ``updated_at``, no ``deleted_at``, no ``ON UPDATE`` behaviour — nothing in the mapping
   suggests a row can change.
2. Migration ``0001`` revokes ``UPDATE`` and ``DELETE`` on this table from the application role, so
   the guarantee holds for every client that connects as ``tlx_app``, including one written next
   year by someone who has never read this file.
3. ``prev_hash`` / ``record_hash`` make a row that *was* altered detectable, which is the property
   that survives even a superuser with a psql prompt.

The hash-chain **algorithm** — canonical JSON serialisation, golden vectors, the verification walk
— is M6. What is here is the shape the chain needs and constraints on its parts, because adding
chain columns to a populated audit table means rewriting history, and a rewritten history is
worthless as evidence.

Partitioning is deliberately **not** applied yet. §8.3 specifies monthly ``RANGE`` partitioning on
``occurred_at``, and it is the right destination for a table that grows without limit. Doing it now
would be worse than not doing it: a partitioned table with no partition for the current month
rejects every insert ("no partition of relation found for row"), so audit writes would fail closed
until the partition-maintenance job that creates next month's partition exists. Partitioning without
that job trades a slow table for a missing audit record, and a missing audit record is the failure
this table exists to prevent. It arrives with the administration milestone that ships the
maintenance job (§14 records the deferral). The primary key is therefore ``id`` alone; a partitioned
form must include the partition key, which is a second reason to make the change once, deliberately,
rather than twice.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UTCDateTime
from app.db.uuid7 import uuid7
from app.models.enums import AuditResult, native_enum
from app.models.types import HEX_SHA256_PATTERN, SHA256

if TYPE_CHECKING:
    from app.models.cases import Case
    from app.models.identity import User

__all__ = ["AuditLog"]

#: §8.3's namespaced action vocabulary: lowercase, dot-separated, at least two segments
#: (``auth.login.failed``, ``evidence.original.accessed``, ``admin.user.role.changed``). Enforced
#: because the audit log is queried by action prefix — ``WHERE action LIKE 'evidence.%'`` — and a
#: single row spelled ``EvidenceCreated`` silently drops out of that query forever.
ACTION_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"


class AuditLog(Base):
    """One audited action. Written once, never updated, never deleted (§8.3, principle DB-3)."""

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("uuid_generate_v7()")
    )
    #: Platform-wide monotonic sequence — the ledger's order, allocated under an advisory lock by
    #: the audit writer. ``id`` is UUIDv7 and therefore only approximately ordered (see
    #: :mod:`app.models.types`); a verifier walking the chain needs an exact one.
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    #: When the action happened, not when the row was written. There is no ``created_at``: two
    #: timestamps on an audit row is an invitation for code to use the wrong one, and the insertion
    #: time is recoverable from the UUIDv7 identifier if an incident ever needs it.
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    #: NULL when the actor is unknown or is not a person — a failed login for a username that does
    #: not exist has no ``actor_id``, and inventing one would put a fabricated user in the record.
    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, default=None
    )
    #: Snapshot of the actor's global role **at the time**. Not a foreign key and not an enum: a
    #: role can be renamed or revoked, and the audit row must keep saying what the actor was
    #: permitted to be when the action happened.
    actor_role: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    actor_ip: Mapped[str | None] = mapped_column(INET, nullable=True, default=None)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    action: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: ``uuid`` rather than ``text`` on purpose: the things this platform audits are its own
    #: entities, and a typed id cannot be misspelled into an audit record that points nowhere.
    resource_id: Mapped[UUID | None] = mapped_column(nullable=True, default=None)
    case_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="RESTRICT"), nullable=True, default=None
    )

    result: Mapped[AuditResult] = mapped_column(native_enum(AuditResult), nullable=False)
    #: Why. Mandatory for a denial: §4.1 requires a denial to name the layer that refused it
    #: (``FORBIDDEN_ROLE``, ``FORBIDDEN_CASE_ACCESS``, ``FORBIDDEN_CAPABILITY``, ``CASE_CLOSED``,
    #: ``LEGAL_HOLD``), and a denial without a reason cannot be triaged or appealed.
    reason: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: Correlates the audit row to the application log for the same request.
    request_id: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    #: Redacted before/after snapshots. §8.3 is explicit that these are never secrets, never full
    #: evidence content, and PII-minimised; the redaction allowlist is code-reviewed and
    #: unit-tested in the milestone that writes them. The columns are here because an audit row
    #: that cannot show what changed cannot answer the only question anybody asks of it.
    before: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    #: Column is named ``metadata`` in §8.3. The Python attribute cannot be: ``metadata`` is
    #: reserved on a declarative class (it is the ``MetaData`` registry itself), so SQLAlchemy
    #: refuses the attribute name outright. The column keeps the documented name.
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", JSONB, nullable=True, default=None
    )

    prev_hash: Mapped[str] = mapped_column(SHA256, nullable=False)
    record_hash: Mapped[str] = mapped_column(SHA256, nullable=False)

    actor: Mapped[User | None] = relationship(foreign_keys=[actor_id])
    case: Mapped[Case | None] = relationship(back_populates="audit_entries")

    __table_args__ = (
        CheckConstraint(f"action ~ '{ACTION_PATTERN}'", name="action_is_namespaced"),
        CheckConstraint(
            f"record_hash ~ '{HEX_SHA256_PATTERN}'", name="record_hash_is_lowercase_hex"
        ),
        CheckConstraint(f"prev_hash ~ '{HEX_SHA256_PATTERN}'", name="prev_hash_is_lowercase_hex"),
        CheckConstraint("sequence > 0", name="sequence_is_positive"),
        CheckConstraint("result <> 'denied' OR reason IS NOT NULL", name="denial_states_why"),
        # A change audit row without either snapshot records that something happened and nothing
        # about what, which is the row an investigator cannot use.
        CheckConstraint(
            "before IS NOT NULL OR after IS NOT NULL OR action NOT LIKE '%.changed'",
            name="change_action_carries_a_snapshot",
        ),
        Index("ix_audit_logs_occurred_at", "occurred_at"),
        Index("ix_audit_logs_actor_occurred", "actor_id", "occurred_at"),
        Index("ix_audit_logs_case_occurred", "case_id", "occurred_at"),
        Index("ix_audit_logs_action_occurred", "action", "occurred_at"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_request", "request_id"),
        # The security-review query: everything that was refused, newest first.
        Index(
            "ix_audit_logs_denied",
            "occurred_at",
            postgresql_where=text("result = 'denied'"),
        ),
    )
