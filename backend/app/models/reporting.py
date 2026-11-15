"""Reports and their immutable versions.

``DATABASE_DESIGN.md`` §8.1 puts the version history in columns on a single ``reports`` table —
``lineage_id`` groups regenerations and ``version`` numbers them. The milestone's entity list asks
for ``report_versions`` as well, and the two are reconciled by splitting the concept along its
natural seam instead of choosing one:

* **``reports``** is the *document*: which case, which template, which title, what state it is in
  now, and which version is current. One row per report, stable for as long as the report exists.
* **``report_versions``** is the *rendering*: the manifest that says exactly which entities were
  included, its digest, the PDF it produced, who generated it, who approved it. One row per
  rendering, written once and never updated.

That split removes the ambiguity the single-table form has to carry. In §8.1's form a regenerated
report is a new row, so "the report" is a set of rows and every consumer must know to filter by
``lineage_id`` and pick the highest ``version`` — and a query that forgets silently returns an
older rendering as though it were current. Here, "the report" is one row and "what did it contain
when it was approved" is one join away.

Two consequences worth stating:

* Nothing is duplicated between the two tables. ``reports`` holds no manifest and no digest, so
  there is no cache invariant for a future service to forget to maintain. Reading the current
  rendering is ``reports`` joined to ``report_versions`` on ``(report_id, version)``, which the
  unique index makes a single index lookup.
* There is no circular foreign key. ``reports.current_version`` is an integer, not a pointer to a
  ``report_versions`` row, so ``report_versions`` can reference ``reports`` and be created in the
  same migration without ``use_alter`` and without an ``ALTER TABLE`` whose ordering a reviewer has
  to reason about.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UTCDateTime
from app.models.enums import ReportStatus, native_enum
from app.models.types import HEX_SHA256_PATTERN, SHA256

if TYPE_CHECKING:
    from app.models.analysis import AnalysisJob
    from app.models.cases import Case
    from app.models.evidence import Derivative
    from app.models.identity import User

__all__ = ["Report", "ReportVersion"]


class Report(Base, TimestampMixin, SoftDeleteMixin):
    """A report as a persistent document belonging to one case (§8.1).

    Soft delete: a report that was issued and then withdrawn is a fact about the case, and §12
    keeps case artifacts for the statutory period regardless of what anyone later wished had been
    produced.
    """

    __tablename__ = "reports"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    #: The identifier that goes in a citation. Distinct from ``id`` so that a lineage can be
    #: re-rooted onto a new report row (a corrected document, a re-issued one) without every
    #: existing reference to it breaking. Stable across regenerations by definition.
    lineage_id: Mapped[UUID] = mapped_column(nullable=False, unique=True, default=uuid4)
    #: ``full_investigation``, ``evidence_summary``, ``custody_only``, ``deepfake_advisory``,
    #: ``custom``. ``text``: the set of templates is a product decision that grows with features
    #: (§9's asymmetry rule).
    template: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    status: Mapped[ReportStatus] = mapped_column(
        native_enum(ReportStatus), nullable=False, server_default=text("'generating'")
    )
    #: Which ``report_versions.version`` is current. ``0`` means nothing has been rendered yet,
    #: which is the state a freshly commissioned report is in.
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    created_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    case: Mapped[Case] = relationship(back_populates="reports")
    created_by_user: Mapped[User] = relationship()
    versions: Mapped[list[ReportVersion]] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="ReportVersion.version",
    )
    #: Read-only convenience: the row ``current_version`` points at. ``viewonly`` because it is a
    #: derived position, not a relationship anybody should be able to assign to — writing
    #: ``report.current = some_version`` would move the pointer without updating the integer that
    #: actually defines it.
    current: Mapped[ReportVersion | None] = relationship(
        primaryjoin=(
            "and_(Report.id == ReportVersion.report_id, "
            "Report.current_version == ReportVersion.version)"
        ),
        foreign_keys="[ReportVersion.report_id]",
        viewonly=True,
        uselist=False,
    )

    __table_args__ = (
        CheckConstraint("current_version >= 0", name="current_version_not_negative"),
        # A report that has left `generating` must point at a rendering that exists. Without this,
        # a failed generation leaves a `final` report with nothing behind it — the worst possible
        # state for a document that may already have been cited.
        CheckConstraint(
            "status = 'generating' OR current_version > 0", name="issued_report_has_a_version"
        ),
        Index("ix_reports_case_status", "case_id", "status"),
        Index("ix_reports_case_created", "case_id", "created_at"),
        Index("ix_reports_created_by", "created_by"),
    )


class ReportVersion(Base):
    """One immutable rendering of a report (§8.1's per-version columns).

    Written once. There is no ``updated_at`` and no soft delete: a rendering either exists or was
    never produced, and the manifest is what makes it reproducible.

    ``manifest`` is the honesty mechanism of the whole reporting module (RPT-04). It lists every
    source entity by type, id and content hash, plus the sections selected and the filters applied,
    and ``manifest_hash`` digests it canonically. Two renderings with the same manifest hash must
    produce the same document; if they do not, the difference is in the template or engine versions,
    which ``engine_versions`` records. That is what makes "this report says X" answerable years
    later, without trusting anybody's memory of what was selected at the time.
    """

    __tablename__ = "report_versions"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    report_id: Mapped[UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    manifest_hash: Mapped[str] = mapped_column(SHA256, nullable=False)
    #: ``DRAFT``, ``FINAL``, ``COPY n OF m`` — printed into the artifact, so it belongs to the
    #: rendering rather than to the document.
    watermark: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: Derived from case sensitivity at render time and frozen here: the case may be
    #: re-classified later, and the banner on an issued document must not change with it.
    classification_banner: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    pdf_derivative_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("derivatives.id", ondelete="SET NULL"), nullable=True, default=None
    )
    #: Nullable because a ``generating`` or ``failed`` rendering has no PDF. §8.1 declares it NOT
    #: NULL, which cannot hold for the states §8.1 itself lists; the CHECK below enforces the real
    #: rule — anything approved must have a digest (recorded in §14).
    pdf_sha256: Mapped[str | None] = mapped_column(SHA256, nullable=True, default=None)
    signature_block: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )
    #: Optional PDF signing metadata (RPT-06). NULL until signing is implemented; the column exists
    #: so adding it later is a data change, not a schema change.
    crypto_signature: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )
    job_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True, default=None
    )
    #: Template and renderer versions, for reproducibility. JSONB because the set of components
    #: that can affect output is not fixed.
    engine_versions: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )
    generated_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    generated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    #: NULL until a lead marks the report FINAL (§8.1). Approval is a person and a moment; neither
    #: is inferable from the artifact.
    approved_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, server_default=text("now()")
    )

    report: Mapped[Report] = relationship(back_populates="versions")
    job: Mapped[AnalysisJob | None] = relationship(back_populates="report_versions")
    pdf_derivative: Mapped[Derivative | None] = relationship(
        back_populates="report_versions_rendered"
    )
    generated_by_user: Mapped[User | None] = relationship(foreign_keys=[generated_by])
    approved_by_user: Mapped[User | None] = relationship(foreign_keys=[approved_by])

    __table_args__ = (
        UniqueConstraint("report_id", "version", name="uq_report_versions_report_version"),
        CheckConstraint("version > 0", name="version_is_positive"),
        CheckConstraint(
            f"manifest_hash ~ '{HEX_SHA256_PATTERN}'", name="manifest_hash_is_lowercase_hex"
        ),
        CheckConstraint(
            f"pdf_sha256 IS NULL OR pdf_sha256 ~ '{HEX_SHA256_PATTERN}'",
            name="pdf_sha256_is_lowercase_hex",
        ),
        # Approval without an artifact is an approval of nothing.
        CheckConstraint(
            "approved_at IS NULL OR (approved_by IS NOT NULL AND pdf_sha256 IS NOT NULL)",
            name="approval_requires_actor_and_artifact",
        ),
        CheckConstraint(
            "generated_at IS NULL OR generated_by IS NOT NULL", name="generation_names_an_actor"
        ),
        CheckConstraint("jsonb_typeof(manifest) = 'object'", name="manifest_is_object"),
        Index("ix_report_versions_report", "report_id", "version"),
        Index("ix_report_versions_manifest_hash", "manifest_hash"),
        Index("ix_report_versions_job", "job_id"),
    )
