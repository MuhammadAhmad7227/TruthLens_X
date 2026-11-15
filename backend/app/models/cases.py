"""Cases, case membership (the case-level ACL), case notes and notifications.

``cases`` is the root of every case-scoped table, and §10 explains why that matters for the schema
rather than only for the API: ``case_id`` leads the composite index on every case-scoped table
because the authorization choke point always applies it, so a query that forgets it is slow *and*
wrong.

Two structural decisions in this module are worth stating before the columns.

**Composite foreign keys keep a case's children inside the case.** ``evidence_items`` carries
``UNIQUE (case_id, id)``, and every table that references both a case and one of its items declares
its foreign key against that *pair* — ``ForeignKeyConstraint(["case_id", "evidence_id"],
["evidence_items.case_id", "evidence_items.id"])``. The database then makes it impossible for a
note, custody event, derivative or analysis result to point at evidence belonging to a different
case. ADR-0004 puts case scoping at the centre of the authorization model and requires a forbidden
case to look identical to a nonexistent one (404); a constraint that makes cross-case references
unrepresentable means one class of leakage cannot be introduced by a future bug in query code.
With ``MATCH SIMPLE`` (PostgreSQL's default) a NULL ``evidence_id`` skips the check, which is
exactly the intended behaviour for case-level rows.

**``cases.sensitivity`` has no server default.** A classification that arrives by default was never
chosen by anybody. ``status`` defaults to ``draft`` because that is a workflow position, not a
handling caveat; sensitivity is a handling caveat, and §3.3 says it drives download and masking
policy. Making the caller state it is the fail-closed reading.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UTCDateTime
from app.models.enums import CaseRole, CaseStatus, Sensitivity, native_enum
from app.models.types import text_array

if TYPE_CHECKING:
    from app.models.analysis import AnalysisJob, AnalysisResult
    from app.models.assistant import AIConversation
    from app.models.audit import AuditLog
    from app.models.evidence import CustodyEvent, Derivative, EvidenceItem
    from app.models.identity import Organisation, User
    from app.models.reporting import Report

__all__ = ["Case", "CaseMember", "CaseNote", "Notification"]

#: The seeded ``org_default`` organisation (§3.2b). A fixed literal rather than a generated id:
#: ``cases.organisation_id`` is NOT NULL with a server default that must name an existing row, and
#: at the moment migration ``0001`` emits that DEFAULT the row does not exist yet. Migration
#: ``0002`` inserts exactly this organisation, so the default resolves. The value is version-4
#: shaped and obviously synthetic — it is a placeholder row, not an entity anybody created.
DEFAULT_ORGANISATION_ID = "00000000-0000-4000-8000-000000000001"

#: §3.3: ``TLX-<YYYY>-<6 digits>``. Enforced in the database so no code path can mint a case number
#: that a report header, an export filename and a court reference will render differently.
CASE_NUMBER_PATTERN = r"^TLX-[0-9]{4}-[0-9]{6}$"


class Case(Base, TimestampMixin, SoftDeleteMixin):
    """An investigation. Everything evidential is scoped to one.

    ``legal_hold`` defaults to **true**: a case is protected from hard deletion until somebody
    deliberately releases it (§12, ADR-0020). Defaulting to false would mean an oversight permits
    destruction; defaulting to true means an oversight blocks it, and blocking is recoverable.
    """

    __tablename__ = "cases"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    #: Immutable after creation (§3.3). Immutability is enforced by the service layer and by the
    #: audit trail, not by a trigger — see ``physical_objects`` for the one place this schema does
    #: use a database-level write-once rule, and why the two differ.
    case_number: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    organisation_id: Mapped[UUID] = mapped_column(
        ForeignKey("organisations.id", ondelete="RESTRICT"),
        nullable=False,
        server_default=text(f"'{DEFAULT_ORGANISATION_ID}'::uuid"),
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    status: Mapped[CaseStatus] = mapped_column(
        native_enum(CaseStatus), nullable=False, server_default=text("'draft'")
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(native_enum(Sensitivity), nullable=False)
    #: Free-form taxonomy (``fraud``, ``media_authenticity``, ``incident``). ``text`` because the
    #: vocabulary is operational and grows without a design decision (§9's asymmetry rule).
    case_type: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    jurisdiction: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    lead_investigator_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    opened_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    #: Statutory deadline. NULL means "none recorded", which §12 and ADR-0020 treat as *retain
    #: forever*: a retention job that read NULL as "delete now" would be the most destructive bug
    #: available in this schema.
    statutory_deadline: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True, default=None
    )
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: ``bigint``, never float (§1.1). NULL quota means the global default applies.
    storage_quota_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
    storage_used_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default=text("0")
    )
    tags: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, server_default=text("'{}'")
    )
    #: Generated, not maintained by application code: a stored ``tsvector`` that could drift from
    #: the columns it summarises would return search results that do not match the case, which is
    #: worse than no full-text search.
    #:
    #: Two details are load-bearing and easy to "simplify" into a broken migration:
    #:
    #: * ``'english'::regconfig`` — without the cast PostgreSQL resolves the literal through the
    #:   single-argument ``to_tsvector(text)``, which is ``STABLE`` (it reads
    #:   ``default_text_search_config``) and therefore rejected in a generated column.
    #: * ``tlx_array_to_text(tags)`` rather than ``array_to_string(tags, ' ')`` — the built-in is
    #:   marked ``STABLE``, so it cannot appear in a generation expression at all. Migration
    #:   ``0001`` installs an ``IMMUTABLE`` equivalent for ``text[]``, which is safe because
    #:   concatenating text with a fixed delimiter depends on nothing but its input.
    search_vector: Mapped[str | None] = mapped_column(
        TSVECTOR,
        Computed(
            "to_tsvector('english'::regconfig, coalesce(title, '') || ' ' "
            "|| coalesce(description, '') || ' ' || coalesce(tlx_array_to_text(tags), ''))",
            persisted=True,
        ),
        nullable=True,
    )
    created_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    organisation: Mapped[Organisation] = relationship(back_populates="cases")
    lead_investigator: Mapped[User | None] = relationship(foreign_keys=[lead_investigator_id])
    created_by_user: Mapped[User] = relationship(foreign_keys=[created_by])
    members: Mapped[list[CaseMember]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    evidence_items: Mapped[list[EvidenceItem]] = relationship(back_populates="case")
    custody_events: Mapped[list[CustodyEvent]] = relationship(back_populates="case")
    derivatives: Mapped[list[Derivative]] = relationship(back_populates="case")
    analysis_jobs: Mapped[list[AnalysisJob]] = relationship(back_populates="case")
    analysis_results: Mapped[list[AnalysisResult]] = relationship(back_populates="case")
    notes: Mapped[list[CaseNote]] = relationship(back_populates="case")
    reports: Mapped[list[Report]] = relationship(back_populates="case")
    audit_entries: Mapped[list[AuditLog]] = relationship(back_populates="case")
    notifications: Mapped[list[Notification]] = relationship(back_populates="case")
    #: The assistant's threads on this case (§8.2). Retrieval is hard-scoped to a case, so every
    #: conversation belongs to one and this list is the whole of what the assistant can reach.
    conversations: Mapped[list[AIConversation]] = relationship(back_populates="case")

    __table_args__ = (
        CheckConstraint(
            f"case_number ~ '{CASE_NUMBER_PATTERN}'", name="case_number_has_required_format"
        ),
        CheckConstraint(
            "closed_at IS NULL OR opened_at IS NULL OR closed_at >= opened_at",
            name="closed_after_opened",
        ),
        CheckConstraint("storage_used_bytes >= 0", name="storage_used_not_negative"),
        CheckConstraint(
            "storage_quota_bytes IS NULL OR storage_quota_bytes > 0",
            name="storage_quota_positive",
        ),
        Index("ix_cases_status", "status"),
        Index("ix_cases_lead_investigator", "lead_investigator_id"),
        Index("ix_cases_created_at", "created_at"),
        Index("ix_cases_tags_gin", "tags", postgresql_using="gin"),
        Index("ix_cases_search_vector_gin", "search_vector", postgresql_using="gin"),
    )


class CaseMember(Base, TimestampMixin):
    """Layer 2 of authorization: one user's standing in one case (§3.4).

    The composite primary key ``(case_id, user_id)`` *is* the uniqueness constraint §3.4 asks for —
    a second row for the same pair would be two contradictory answers to "what may this user do
    here". No ``deleted_at``: access is ended by setting ``revoked_at``, which keeps the grant,
    its validity window and its revocation as one auditable row instead of a deletion nobody can
    explain later.

    ``capability_overrides`` is a ``text[]`` of capability codes (optionally ``!``-prefixed to
    revoke) applied **after** the ``case_role`` defaults. It is an array of codes rather than a
    join table because the set is small, is read as a whole on every authorization decision, and
    §4.2 defines per-membership overrides as adjustments to a role rather than as independent
    grants. The codes are not foreign keys: an override may name a capability that has since been
    removed, and a dangling override must fail closed (it grants nothing) rather than cascade away
    silently.
    """

    __tablename__ = "case_members"

    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    case_role: Mapped[CaseRole] = mapped_column(
        native_enum(CaseRole), nullable=False, server_default=text("'viewer'")
    )
    granted_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    valid_from: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    capability_overrides: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, server_default=text("'{}'")
    )
    #: Metadata-only membership (``reviewer``, ``auditor``) is expressed by setting this false:
    #: the member may see that evidence exists and what it is, never its contents. Maps to the
    #: ``view_evidence_content`` capability (§3.4).
    can_view_original_content: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    #: Separation of duties: the ability to set a verification verdict is granted explicitly, and
    #: §4.2 note ⁽³⁾ denies it to ``admin`` so that administrative power cannot manufacture an
    #: epistemic conclusion.
    can_verify_findings: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    revoked_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )

    case: Mapped[Case] = relationship(back_populates="members")
    user: Mapped[User] = relationship(
        back_populates="case_memberships", foreign_keys="[CaseMember.user_id]"
    )
    granted_by_user: Mapped[User] = relationship(foreign_keys=[granted_by])
    revoked_by_user: Mapped[User | None] = relationship(foreign_keys=[revoked_by])

    __table_args__ = (
        Index(
            "ix_case_members_user_active", "user_id", postgresql_where=text("revoked_at IS NULL")
        ),
        # The membership query is "who is on this case right now", ordered by when they joined.
        Index("ix_case_members_case_role", "case_id", "case_role"),
        CheckConstraint(
            "valid_from IS NULL OR valid_until IS NULL OR valid_until > valid_from",
            name="validity_window_is_ordered",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_by IS NOT NULL", name="revocation_names_an_actor"
        ),
    )


class CaseNote(Base, TimestampMixin, SoftDeleteMixin):
    """An analyst's note on a case or on one item of evidence.

    ``DATABASE_DESIGN.md`` §8.4 lists this concept as ``annotations`` (regions and notes attached
    to a derivative). Both are needed and they are not the same thing: an annotation carries
    geometry and points at a rendered image, a case note is free text in the case record. This is
    the case note; §8.4's ``annotations`` arrives with the imaging milestone that can produce the
    derivative it points at (recorded in §14).

    Soft delete only. A deleted investigative note is itself a fact about the investigation, so the
    row survives with ``deleted_at`` and ``deleted_by`` set rather than disappearing.
    """

    __tablename__ = "case_notes"

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    #: NULL for a case-level note. The composite foreign key below is what makes "a note in case A
    #: about evidence in case B" unrepresentable.
    evidence_id: Mapped[UUID | None] = mapped_column(nullable=True, default=None)
    author_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    parent_note_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("case_notes.id", ondelete="CASCADE"), nullable=True, default=None
    )
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    deleted_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    deletion_justification: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    case: Mapped[Case] = relationship(back_populates="notes")
    #: Pinned to `evidence_id`; see `AnalysisJob.evidence` for why.
    evidence: Mapped[EvidenceItem | None] = relationship(
        back_populates="case_notes", foreign_keys=[evidence_id]
    )
    author: Mapped[User] = relationship(foreign_keys=[author_id])
    parent: Mapped[CaseNote | None] = relationship(
        remote_side="CaseNote.id", back_populates="replies"
    )
    replies: Mapped[list[CaseNote]] = relationship(back_populates="parent")
    deleted_by_user: Mapped[User | None] = relationship(foreign_keys=[deleted_by])

    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "evidence_id"],
            ["evidence_items.case_id", "evidence_items.id"],
            name="fk_case_notes_case_evidence_evidence_items",
            ondelete="CASCADE",
        ),
        Index("ix_case_notes_case_created", "case_id", "created_at"),
        Index("ix_case_notes_evidence", "evidence_id"),
        Index("ix_case_notes_author", "author_id"),
        CheckConstraint(
            "deleted_at IS NULL OR deleted_by IS NOT NULL", name="deletion_names_an_actor"
        ),
    )


class Notification(Base, TimestampMixin):
    """A per-user alert: verification backlog, integrity failures, membership changes (§8.4).

    ``kind`` is ``text``, not an enum — notification kinds are added by features, and §9 is explicit
    that a growing vocabulary must not be a native enum. ``payload`` is JSONB because the shape is
    per-kind and nothing queries inside it except through ``kind`` first (§1 principle DB-5: JSONB
    for open shape, columns for queried shape).
    """

    __tablename__ = "notifications"

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, default=None
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    #: Notifications age out of the UI without being deleted, so an integrity alert that was never
    #: read is still discoverable in the row.
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)

    user: Mapped[User] = relationship(
        back_populates="notifications", foreign_keys="[Notification.user_id]"
    )
    case: Mapped[Case | None] = relationship(back_populates="notifications")

    __table_args__ = (
        # The unread inbox, which is the only query the UI makes on every poll.
        Index(
            "ix_notifications_user_unread",
            "user_id",
            "created_at",
            postgresql_where=text("read_at IS NULL"),
        ),
        Index("ix_notifications_case", "case_id", "created_at"),
        Index("ix_notifications_kind", "kind"),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at", name="expiry_after_creation"
        ),
    )
