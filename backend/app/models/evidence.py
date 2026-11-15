"""Evidence and integrity: ``physical_objects``, ``evidence_items``, ``custody_events``,
``derivatives``.

The split between the first two tables is the most important idea in this schema (§4.2). A
**physical object** is a content-addressed blob: its ``sha256`` is unique, so two people uploading
the same file store it once. An **evidence item** is that blob *as it appears in one case*: its own
evidence number, its own acquisition story, its own custody chain, its own sensitivity. The same
bytes submitted to two cases by two people with two different accounts of how they got them produce
one physical object and two evidence items. Collapsing the two would either duplicate storage or —
worse — merge two contradictory provenance records into one, which is the exact failure a defence
expert would cross-examine.

Immutability is enforced in the database, not only in code
----------------------------------------------------------
``physical_objects`` carries a ``BEFORE UPDATE OR DELETE`` trigger (created by migration ``0001``)
that raises unless the session has explicitly set ``app.maintenance = 'on'``. Code-level immutability
is a promise the next refactor can break; a trigger is a property of the database. Two limits on it
are deliberate and matter:

* It protects the **content-addressed identity** columns (``sha256``, ``sha1``, ``md5``,
  ``size_bytes``, ``storage_path``, ``storage_backend``, ``detected_mime``, ``merkle_root``,
  ``block_size``, ``encryption``, ``wrapped_dek``, ``written_at``). It does *not* freeze the whole
  row: §4.1 has the application maintaining ``reference_count`` and recording antivirus results, and
  a trigger that blocked those would push that bookkeeping into a second table where nobody would
  think to look for it.
* §4.1 describes the escape hatch as "the ``tlx_migrator`` role with an explicit maintenance flag".
  The trigger implements the flag (``app.maintenance``) and leaves the role check to the grants in
  ``infra/postgres/initdb``: a trigger that also inspected ``current_user`` would stop working under
  any connection-pooling or role-assumption change, and would fail in a way that looks like data
  corruption rather than a permissions problem.

The custody hash chain is **not** implemented here. ``custody_events`` carries the fields the chain
needs — ``sequence``, ``prev_hash``, ``record_hash`` — and constrains their shape, because a ledger
that has to be rewritten to gain those columns is a ledger that has already lost its history. The
canonical-JSON serialisation, the golden vectors and the verification walk are M6, as the milestone
plan requires.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import LargeBinary

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UTCDateTime
from app.db.uuid7 import uuid7
from app.models.enums import (
    ArtifactStatus,
    CustodyEventType,
    DerivativeKind,
    EncState,
    EvidenceStatus,
    EvidenceType,
    IntegrityStatus,
    Sensitivity,
    SourceType,
    native_enum,
)
from app.models.types import HEX_SHA256_PATTERN, MD5, SHA1, SHA256, text_array

if TYPE_CHECKING:
    from app.models.analysis import AnalysisJob, AnalysisResult
    from app.models.cases import Case, CaseNote
    from app.models.identity import User
    from app.models.reporting import ReportVersion

__all__ = ["CustodyEvent", "Derivative", "EvidenceItem", "IntegrityCheck", "PhysicalObject"]

#: §4.3: the genesis link of a custody chain is 64 zero characters, not NULL. A NULL ``prev_hash``
#: would make "this is the first event" indistinguishable from "the chain was never computed", and
#: those two states have opposite meanings for a verifier.
GENESIS_PREV_HASH = "0" * 64


class PhysicalObject(Base, TimestampMixin):
    """One immutable, content-addressed blob in the write-once store (§4.1).

    No ``deleted_at``: a physical object is either present or gone, and "gone" is a physical event
    with an audit record, not a flag. §12 permits destruction only when ``reference_count`` is 0,
    with an administrator, a justification and a second approver — so the row leaves the table by a
    deliberate act, in maintenance mode, leaving its audit trail behind.
    """

    __tablename__ = "physical_objects"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    #: The dedup key and the integrity anchor. UNIQUE: two rows claiming the same content hash would
    #: make "which bytes does this evidence item point at" ambiguous.
    sha256: Mapped[str] = mapped_column(SHA256, nullable=False, unique=True)
    #: Interop only. Never an integrity decision — §4.1 keeps them because external tooling still
    #: emits them, and a platform that cannot answer "does this match the hash in your letter" is
    #: harder to work with than one that can.
    sha1: Mapped[str | None] = mapped_column(SHA1, nullable=True, default=None)
    md5: Mapped[str | None] = mapped_column(MD5, nullable=True, default=None)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: ``filesystem`` in v1 (ADR-0011 — no object storage). ``text`` rather than an enum: §4.1
    #: lists two backends and the choice is a deployment decision, so an enum would need a
    #: PostgreSQL type rebuild to add a third (§9's asymmetry rule).
    storage_backend: Mapped[str] = mapped_column(Text, nullable=False)
    #: Relative to the configured root, and never built from a user-supplied filename. A path that
    #: contained the original name would put ``../../`` from an upload straight into the store
    #: layout (EVID-04).
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    #: From magic bytes, not from the client (EVID-03). ``declared_mime`` is kept beside it because
    #: the *disagreement* between the two is itself evidence about the file's history.
    detected_mime: Mapped[str] = mapped_column(Text, nullable=False)
    declared_mime: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: Optional per-block Merkle tree (EVID-11): proves which *part* of a large file changed
    #: without re-reading the whole of it.
    merkle_root: Mapped[str | None] = mapped_column(SHA256, nullable=True, default=None)
    block_size: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    #: No server default. Whether evidence is encrypted at rest is a property the ingest path must
    #: state for every object; a default would let a configuration mistake produce silently
    #: unencrypted evidence, and ``config.py`` already refuses to start with encryption disabled.
    encryption: Mapped[EncState] = mapped_column(native_enum(EncState), nullable=False)
    #: The data encryption key, wrapped by the application KEK (D-006). Never the key itself.
    wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True, default=None)
    av_scan_status: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    av_scan_detail: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )
    #: Set once, at write time, and protected by the write-once trigger. This is the timestamp the
    #: platform can defend: when the bytes arrived here, not when somebody says they were created.
    written_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    first_ingested_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    #: How many evidence items point at these bytes. Zero is the precondition for physical deletion
    #: (§12) — the guard that stops one case's cleanup destroying another case's original.
    reference_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    evidence_items: Mapped[list[EvidenceItem]] = relationship(back_populates="physical_object")
    first_ingested_by_user: Mapped[User | None] = relationship()
    #: Every sweep that has ever re-hashed these bytes, oldest first by ``checked_at``.
    integrity_checks: Mapped[list[IntegrityCheck]] = relationship(back_populates="physical_object")

    __table_args__ = (
        CheckConstraint(f"sha256 ~ '{HEX_SHA256_PATTERN}'", name="sha256_is_lowercase_hex"),
        CheckConstraint("size_bytes >= 0", name="size_not_negative"),
        CheckConstraint("reference_count >= 0", name="reference_count_not_negative"),
        # An encrypted object with no wrapped key is unrecoverable data. Refusing the row at insert
        # time is the difference between "we cannot read this evidence" discovered now and
        # discovered in court.
        CheckConstraint(
            "encryption = 'none' OR wrapped_dek IS NOT NULL",
            name="encrypted_requires_wrapped_key",
        ),
        # A Merkle root without a block size cannot be recomputed or verified by anyone else.
        CheckConstraint(
            "merkle_root IS NULL OR block_size IS NOT NULL", name="merkle_root_has_block_size"
        ),
        Index("ix_physical_objects_written_at", "written_at"),
        Index(
            "ix_physical_objects_unreferenced",
            "sha256",
            postgresql_where=text("reference_count = 0"),
        ),
    )


class EvidenceItem(Base, TimestampMixin, SoftDeleteMixin):
    """One item of evidence **as it exists in one case** (§4.2).

    Soft delete only (EVID-08). ``deleted_at``, ``deleted_by`` and ``deletion_justification`` travel
    together: a removal from an evidential record with no stated reason and no named actor is
    indistinguishable from tampering, so the schema requires both.

    ``acquired_at`` is the *claimed* real-world acquisition time and is kept strictly apart from
    ``created_at``, which is when the platform received the item. Conflating them is how a platform
    ends up testifying to a time nobody observed.
    """

    __tablename__ = "evidence_items"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    physical_object_id: Mapped[UUID] = mapped_column(
        ForeignKey("physical_objects.id", ondelete="RESTRICT"), nullable=False
    )
    #: The court-facing identifier, unique **within the case** — two cases may each have an
    #: ``EXH-0001`` and neither is wrong.
    evidence_number: Mapped[str] = mapped_column(Text, nullable=False)
    #: Preserved verbatim as *data*. Never used to build a path, never rendered without escaping:
    #: filenames are attacker-controlled input in an evidential system.
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_filename: Mapped[str] = mapped_column(Text, nullable=False)
    item_type: Mapped[EvidenceType] = mapped_column(native_enum(EvidenceType), nullable=False)
    #: ``jpeg``, ``mp4``, ``pdf``… Free text because the set is whatever the world's file formats
    #: are this year, and ``detected_mime`` on the physical object is the authoritative value.
    subcategory: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    status: Mapped[EvidenceStatus] = mapped_column(
        native_enum(EvidenceStatus), nullable=False, server_default=text("'ingesting'")
    )
    integrity_status: Mapped[IntegrityStatus] = mapped_column(
        native_enum(IntegrityStatus), nullable=False, server_default=text("'unverified'")
    )
    integrity_last_checked_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True, default=None
    )
    source_type: Mapped[SourceType] = mapped_column(native_enum(SourceType), nullable=False)
    #: Self-reference for children extracted from a container or a document (DOC-04). Each child is
    #: a full evidence item with its own custody chain, which is what makes "this file came out of
    #: that archive" provable rather than asserted.
    parent_evidence_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="RESTRICT"), nullable=True, default=None
    )
    submitted_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    acquired_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    acquisition_method: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    acquisition_device: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    collection_location: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    custody_holder_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    tags: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, server_default=text("'{}'")
    )
    #: May **raise** the handling caveat above the case's, never lower it (§4.2). The direction of
    #: that rule is enforced by the service layer, which is the only place that knows both values;
    #: the column exists so an item can be more protected than its case without re-classifying the
    #: whole investigation.
    sensitivity_override: Mapped[Sensitivity | None] = mapped_column(
        native_enum(Sensitivity), nullable=True, default=None
    )
    deleted_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    deletion_justification: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    case: Mapped[Case] = relationship(back_populates="evidence_items")
    physical_object: Mapped[PhysicalObject] = relationship(back_populates="evidence_items")
    parent: Mapped[EvidenceItem | None] = relationship(remote_side=[id], back_populates="children")
    children: Mapped[list[EvidenceItem]] = relationship(back_populates="parent")
    submitted_by_user: Mapped[User] = relationship(foreign_keys=[submitted_by])
    custody_holder: Mapped[User | None] = relationship(foreign_keys=[custody_holder_id])
    deleted_by_user: Mapped[User | None] = relationship(foreign_keys=[deleted_by])
    custody_events: Mapped[list[CustodyEvent]] = relationship(
        back_populates="evidence", foreign_keys="[CustodyEvent.evidence_id]"
    )
    derivatives: Mapped[list[Derivative]] = relationship(
        back_populates="evidence", foreign_keys="[Derivative.evidence_id]"
    )
    analysis_jobs: Mapped[list[AnalysisJob]] = relationship(
        back_populates="evidence", foreign_keys="[AnalysisJob.evidence_id]"
    )
    analysis_results: Mapped[list[AnalysisResult]] = relationship(
        back_populates="evidence", foreign_keys="[AnalysisResult.evidence_id]"
    )
    case_notes: Mapped[list[CaseNote]] = relationship(
        back_populates="evidence", foreign_keys="[CaseNote.evidence_id]"
    )

    __table_args__ = (
        UniqueConstraint("case_id", "id", name="uq_evidence_items_case_id"),
        UniqueConstraint(
            "case_id", "evidence_number", name="uq_evidence_items_case_evidence_number"
        ),
        CheckConstraint(
            "deleted_at IS NULL OR (deleted_by IS NOT NULL AND deletion_justification IS NOT NULL)",
            name="soft_delete_requires_actor_and_reason",
        ),
        # §10: the composite indexes lead on case_id because the authorization choke point always
        # supplies it, and a query that does not is both slower and outside the ACL.
        Index("ix_evidence_items_case_type", "case_id", "item_type"),
        Index("ix_evidence_items_case_status", "case_id", "status"),
        Index("ix_evidence_items_physical_object", "physical_object_id"),
        Index("ix_evidence_items_parent", "parent_evidence_id"),
        Index("ix_evidence_items_tags_gin", "tags", postgresql_using="gin"),
        Index(
            "ix_evidence_items_case_created",
            "case_id",
            "created_at",
            postgresql_where=text("deleted_at IS NULL"),
        ),
        # The integrity exception queue: small, hot, and the query an operator runs first.
        Index(
            "ix_evidence_items_integrity_exception",
            "case_id",
            "integrity_status",
            postgresql_where=text("integrity_status IN ('mismatch', 'missing')"),
        ),
    )


class CustodyEvent(Base):
    """One link in a case's chain of custody — append-only (§4.3, principle DB-3).

    No ``updated_at``, no ``deleted_at``, no ``ON UPDATE`` behaviour: a custody record that can be
    edited is not a record. Migration ``0001`` revokes ``UPDATE`` and ``DELETE`` on this table from
    the application role, so the guarantee is a property of the database and not of whichever
    service happened to be written carefully.

    ``sequence`` is the authoritative order, allocated per case under an advisory lock by the
    service that appends (M6). ``id`` is UUIDv7 for index locality only — see
    :mod:`app.models.types` for why v7 is not a substitute for a sequence.

    ``prev_hash`` and ``record_hash`` are present and shape-checked now. The canonicalisation
    routine, its golden vectors and the verification walk are M6; what must not wait is the
    *columns*, because adding them later means rewriting every row of a ledger that is already in
    use.
    """

    __tablename__ = "custody_events"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("uuid_generate_v7()")
    )
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
    )
    #: NULL for case-level events (a legal hold applies to the case, not to one item).
    evidence_id: Mapped[UUID | None] = mapped_column(nullable=True, default=None)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[CustodyEventType] = mapped_column(
        native_enum(CustodyEventType), nullable=False
    )
    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, default=None
    )
    #: Set when the actor is a process rather than a person (``worker-cpu-01``, ``beat``). Naming
    #: the machine is what makes an unattended action attributable.
    system_actor: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    acted_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    #: The digest believed true at that instant. Keeping it per event is what turns a mismatch into
    #: a *located* one: the schema can say between which two events the bytes changed.
    sha256_at_event: Mapped[str] = mapped_column(SHA256, nullable=False)
    #: Mandatory for content access and export, enforced by the CHECK below. "Who looked at the
    #: original, and why" is the question a custody record exists to answer.
    purpose: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True, default=None)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    request_id: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    recipient_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, default=None
    )
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    prev_hash: Mapped[str] = mapped_column(
        SHA256, nullable=False, server_default=text(f"'{GENESIS_PREV_HASH}'")
    )
    record_hash: Mapped[str] = mapped_column(SHA256, nullable=False)

    #: ``created_at`` is deliberately absent: ``acted_at`` is the event's time and a second,
    #: insert-time timestamp would invite code to use the wrong one. The row's insertion time is
    #: recoverable from the UUIDv7 identifier if it is ever needed for an incident.

    case: Mapped[Case] = relationship(back_populates="custody_events")
    #: Pinned to `evidence_id`; see `AnalysisJob.evidence` for why.
    evidence: Mapped[EvidenceItem | None] = relationship(
        back_populates="custody_events", foreign_keys=[evidence_id]
    )
    actor: Mapped[User | None] = relationship(foreign_keys=[actor_id])
    recipient: Mapped[User | None] = relationship(foreign_keys=[recipient_id])

    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "evidence_id"],
            ["evidence_items.case_id", "evidence_items.id"],
            name="fk_custody_events_case_evidence_evidence_items",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("case_id", "sequence", name="uq_custody_events_case_sequence"),
        CheckConstraint(
            f"record_hash ~ '{HEX_SHA256_PATTERN}'", name="record_hash_is_lowercase_hex"
        ),
        CheckConstraint(f"prev_hash ~ '{HEX_SHA256_PATTERN}'", name="prev_hash_is_lowercase_hex"),
        CheckConstraint(
            f"sha256_at_event ~ '{HEX_SHA256_PATTERN}'", name="sha256_is_lowercase_hex"
        ),
        # Every event names exactly one kind of actor: a person, or a named process. An event naming
        # neither is an action nobody can be held to; an event naming both cannot say which of them
        # acted. §4.3 states the rule as "actor_id: NULL only for system jobs (then system_actor
        # set)", which is an exclusive or — so that is what is enforced, not merely "at least one".
        CheckConstraint(
            "(actor_id IS NOT NULL) <> (system_actor IS NOT NULL)", name="names_exactly_one_actor"
        ),
        # A blank process name satisfies the constraint above while answering nothing, which is the
        # same defect wearing a different disguise.
        CheckConstraint(
            "system_actor IS NULL OR btrim(system_actor) <> ''", name="system_actor_is_not_blank"
        ),
        CheckConstraint("sequence > 0", name="sequence_is_positive"),
        # §4.3: purpose is required for content access and export.
        CheckConstraint(
            "event_type NOT IN ('accessed', 'downloaded', 'exported') OR purpose IS NOT NULL",
            name="content_access_states_purpose",
        ),
        Index("ix_custody_events_case_acted", "case_id", "acted_at"),
        Index("ix_custody_events_case_type", "case_id", "event_type"),
        Index("ix_custody_events_evidence", "evidence_id", "sequence"),
        Index("ix_custody_events_actor", "actor_id", "acted_at"),
    )


class Derivative(Base):
    """A regenerated artifact: thumbnail, frame, heatmap, transcript, masked preview (§4.4).

    Derivatives are **not** evidence. They are reproducible from an original plus a known engine
    version and parameter set, so §12 lets them be purged and rebuilt — which is why this table has
    ``status`` including ``stale`` and ``purged``, and why nothing here is protected by the
    write-once trigger.

    The unique constraint is what makes a retried job safe: the same evidence, kind, engine version
    and parameters can produce only one row, so a worker that runs twice creates one artifact
    instead of two conflicting ones.
    """

    __tablename__ = "derivatives"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("uuid_generate_v7()")
    )
    #: NULL for case-level artifacts such as a rendered report, which then carries ``case_id``.
    evidence_id: Mapped[UUID | None] = mapped_column(nullable=True, default=None)
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[DerivativeKind] = mapped_column(native_enum(DerivativeKind), nullable=False)
    #: Under the derivatives root. Like ``physical_objects.storage_path``, never built from a
    #: user-supplied filename.
    path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(SHA256, nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
    mime: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    produced_by_job_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True, default=None
    )
    #: Engine identity and version, kept so an artifact can be traced to the code that produced it
    #: — the minimum needed to answer "would this look different today?"
    engine_id: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    engine_version: Mapped[str] = mapped_column(Text, nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    params_hash: Mapped[str] = mapped_column(SHA256, nullable=False)
    frame_index: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    #: Presentation timestamp for a video frame. ``numeric(12,3)`` — a float here would make
    #: "frame at 12.340s" unreproducible, and reproducibility is the whole point of a derivative.
    pts_seconds: Mapped[Decimal | None] = mapped_column(Numeric(12, 3), nullable=True, default=None)
    status: Mapped[ArtifactStatus] = mapped_column(
        native_enum(ArtifactStatus), nullable=False, server_default=text("'available'")
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, server_default=text("now()")
    )

    case: Mapped[Case] = relationship(back_populates="derivatives")
    evidence: Mapped[EvidenceItem | None] = relationship(
        back_populates="derivatives", foreign_keys=[evidence_id]
    )
    produced_by_job: Mapped[AnalysisJob | None] = relationship(back_populates="derivatives")
    #: A derivative may be the rendered PDF of one or more report versions. One-to-many, not
    #: one-to-one: the same artifact can be referenced by a re-issued version.
    report_versions_rendered: Mapped[list[ReportVersion]] = relationship(
        back_populates="pdf_derivative"
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "evidence_id"],
            ["evidence_items.case_id", "evidence_items.id"],
            name="fk_derivatives_case_evidence_evidence_items",
            ondelete="CASCADE",
        ),
        # NULLS NOT DISTINCT (PostgreSQL 15+) so case-level derivatives — where evidence_id is NULL
        # — are deduplicated too. With PostgreSQL's default NULLS DISTINCT, every retry of a
        # case-level artifact would insert a new row and the constraint would be decoration.
        UniqueConstraint(
            "evidence_id",
            "case_id",
            "kind",
            "engine_version",
            "params_hash",
            name="uq_derivatives_retry_safe",
            postgresql_nulls_not_distinct=True,
        ),
        CheckConstraint(f"sha256 ~ '{HEX_SHA256_PATTERN}'", name="sha256_is_lowercase_hex"),
        CheckConstraint(
            f"params_hash ~ '{HEX_SHA256_PATTERN}'", name="params_hash_is_lowercase_hex"
        ),
        CheckConstraint("size_bytes IS NULL OR size_bytes >= 0", name="size_not_negative"),
        Index("ix_derivatives_case_kind", "case_id", "kind"),
        Index("ix_derivatives_evidence", "evidence_id", "kind"),
        Index("ix_derivatives_job", "produced_by_job_id"),
        Index(
            "ix_derivatives_stale",
            "case_id",
            "kind",
            postgresql_where=text("status = 'stale'"),
        ),
    )


class IntegrityCheck(Base):
    """One re-hash of one stored object, and what it found (§8.4, EVID-07).

    EVID-07 is mandatory: SHA-256 is re-verified on demand and on a scheduled sweep, and any mismatch
    surfaces as a **critical integrity exception**. This table is the record of those sweeps. It
    exists separately from ``evidence_items.integrity_status`` for the same reason a lab keeps every
    reading and not just the latest one: the current status answers "is this item sound now", while
    the history answers "when did it stop being sound" — and the second question is the one that
    decides whether a mismatch is bit rot, a storage fault, or somebody with a mount point.

    Append-only, per §10 (which also partitions it monthly and rolls it to cold storage after 24
    months). A sweep result is an observation: editing one would be rewriting the platform's own
    account of what it saw. Migration ``0003`` therefore revokes ``UPDATE``/``DELETE``/``TRUNCATE``
    from the application roles, exactly as ``0001`` does for the custody and audit ledgers.

    The shared ``integrity_status`` enum
    ------------------------------------
    ``result`` reuses the type ``evidence_items.integrity_status`` uses, so the two columns cannot
    drift into different vocabularies for the same concept. One of that type's four values is not a
    sweep outcome — ``unverified`` describes an item that has never been checked, and a row in this
    table is by definition a check that ran — so a CHECK excludes it. Sharing an enum without saying
    which of its values are legal here is how a column ends up holding a state its own table cannot
    interpret.
    """

    __tablename__ = "integrity_checks"

    #: UUIDv7: append-only and high-volume (a nightly sweep writes one row per stored object), so
    #: time-ordered keys keep the primary index appending rather than scattering (§1.1).
    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("uuid_generate_v7()")
    )
    #: ``RESTRICT``. §12 permits destroying an object only with an administrator, a justification, a
    #: second approver and an audit record — and the integrity history of a destroyed object is part
    #: of what that approval was granted against. An object whose bytes once failed verification and
    #: were then deleted, taking the failed row with them, is indistinguishable from tampering. §10
    #: already gives these rows a lifecycle (cold storage after 24 months), so the approved path
    #: archives them rather than cascading them away.
    physical_object_id: Mapped[UUID] = mapped_column(
        ForeignKey("physical_objects.id", ondelete="RESTRICT"), nullable=False
    )
    #: When the sweep read the bytes. No ``created_at`` beside it: this is the observation's time, and
    #: a second insert-time column would invite code to read the wrong one — the reasoning
    #: ``custody_events`` gives for the same omission.
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    #: The digest believed true when the sweep ran, copied from ``physical_objects.sha256`` rather
    #: than joined to it: the object's row is write-once, but a check must still record the value it
    #: compared against, or "verified" is a claim with nothing to check it against.
    expected_sha256: Mapped[str] = mapped_column(SHA256, nullable=False)
    #: NULL only when the bytes could not be read at all — which is what ``result = 'missing'`` means,
    #: and the CHECK below makes the two say the same thing.
    actual_sha256: Mapped[str | None] = mapped_column(SHA256, nullable=True, default=None)
    result: Mapped[IntegrityStatus] = mapped_column(native_enum(IntegrityStatus), nullable=False)
    #: The sweep job, when there was one. ``SET NULL`` like the other artifact-to-job references
    #: (``derivatives.produced_by_job_id``, ``report_versions.job_id``): the observation is complete
    #: without it — object, time, expected, actual, result — and coupling job retention to a table
    #: §10 keeps for 24 months would fight both. NULL is also the honest value for an on-demand check
    #: that no job produced.
    job_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True, default=None
    )

    physical_object: Mapped[PhysicalObject] = relationship(back_populates="integrity_checks")
    job: Mapped[AnalysisJob | None] = relationship()

    __table_args__ = (
        # This object's integrity history, in order — the first question after a mismatch.
        Index("ix_integrity_checks_object_time", "physical_object_id", "checked_at"),
        # EVID-07's exception queue: every sweep failure the platform must surface, without scanning
        # 24 months of clean results to find them.
        Index(
            "ix_integrity_checks_exceptions",
            "checked_at",
            postgresql_where=text("result IN ('mismatch', 'missing')"),
        ),
        Index("ix_integrity_checks_result", "result"),
        CheckConstraint(
            f"expected_sha256 ~ '{HEX_SHA256_PATTERN}'", name="expected_sha256_is_lowercase_hex"
        ),
        CheckConstraint(
            f"actual_sha256 IS NULL OR actual_sha256 ~ '{HEX_SHA256_PATTERN}'",
            name="actual_sha256_is_lowercase_hex",
        ),
        # `unverified` belongs to an item nobody has checked yet. A row here is a check that ran, so
        # the value would be a result that says nothing happened.
        CheckConstraint("result <> 'unverified'", name="result_is_an_outcome"),
        # A check that read the bytes records what it read; one that could not says `missing`. Without
        # this, NULL in `actual_sha256` is ambiguous between "not readable" and "not recorded".
        CheckConstraint(
            "actual_sha256 IS NOT NULL OR result = 'missing'",
            name="a_digest_was_read_unless_missing",
        ),
        # The two rows that would otherwise be worth forging. A `verified` result holding two
        # different digests contradicts itself, and a `mismatch` holding two equal ones reports a
        # failure that did not happen — which is a false integrity exception, and EVID-07 makes that
        # a critical alert somebody will act on.
        CheckConstraint(
            "result <> 'verified' OR actual_sha256 = expected_sha256",
            name="verified_means_the_digests_agree",
        ),
        CheckConstraint(
            "result <> 'mismatch' OR actual_sha256 IS DISTINCT FROM expected_sha256",
            name="mismatch_means_the_digests_differ",
        ),
    )
