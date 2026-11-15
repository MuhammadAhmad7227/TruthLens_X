"""Analysis: ``analysis_jobs`` and ``analysis_results``.

``analysis_results`` is described in ``DATABASE_DESIGN.md`` §5.2 as *the honesty-critical table*,
and the schema is where that stops being an intention. Four CHECK constraints are lifted verbatim
from §5.2 and enforced by PostgreSQL, so no code path — engine, service, retry job, ``psql`` during
an incident — can persist the dishonest version of a finding:

* a score without a confidence interval;
* a confidence value with no statement of what it is based on;
* a verdict of ``confirmed`` or ``rejected`` with no notes;
* a ``verified_by`` on a result that is still ``unverified``.

``requires_human_verification`` is ``NOT NULL DEFAULT true`` and no engine may set it false
(ADR-0023). The default is the point: an omission produces the safe value, so the failure mode of a
buggy engine is "a human must look at this", never "a machine's guess was filed as a conclusion".

The column set also refuses to let a finding exist without its limits: ``limitations_code`` is
``NOT NULL`` (AR-4). A result that cannot state what it does not know is not a result this platform
will store.

``limitation_statements`` (§5.3) is the other half of that rule and lives in this module because it
is the same subject: the corpus of disclaimers ``limitations_code`` names. It is versioned —
``(code, version)`` is the primary key, with an ``effective_from``/``effective_to`` window — so the
wording a finding was published with stays retrievable after the wording changes. A report generated
years from now then prints what was true when the result was created rather than what is true now,
which is the property §5.3's heading calls staying truthful retroactively.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    SmallInteger,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UTCDateTime
from app.db.uuid7 import uuid7
from app.models.enums import JobStatus, VerificationStatus, native_enum
from app.models.types import HEX_SHA256_PATTERN, SHA256, confidence_numeric, score_numeric

if TYPE_CHECKING:
    from app.models.cases import Case
    from app.models.evidence import Derivative, EvidenceItem
    from app.models.identity import User
    from app.models.reporting import ReportVersion

__all__ = ["AnalysisJob", "AnalysisResult", "LimitationStatement"]


class AnalysisJob(Base, TimestampMixin):
    """One unit of queued work: an engine run over one item, or over a whole case (§5.1).

    ``id`` is UUIDv7 (§1.1): this is the highest-volume table in the platform apart from the
    ledgers, and time-ordered keys keep its primary index appending rather than scattering.

    ``idempotency_key`` is what makes a retry safe. A worker that is killed mid-run and restarted
    must not create a second job for the same evidence, pipeline and parameters — two jobs means two
    results, and two results for the same question is an ambiguity a report cannot resolve.
    """

    __tablename__ = "analysis_jobs"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("uuid_generate_v7()")
    )
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    #: NULL for case-wide jobs (bulk comparison, reindex). The composite foreign key below then
    #: skips its check, which is the intended ``MATCH SIMPLE`` behaviour.
    evidence_id: Mapped[UUID | None] = mapped_column(nullable=True, default=None)
    #: ``image.ela``, ``doc.revisions``, ``deepfake.indicators``… Namespaced, and the namespace is
    #: what lets a queue route by modality without a lookup table.
    pipeline: Mapped[str] = mapped_column(Text, nullable=False)
    pipeline_version: Mapped[str] = mapped_column(Text, nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    #: Digest of the canonical ``params``. Stored beside the JSON it summarises so the idempotency
    #: key can be indexed without indexing an arbitrary JSON document.
    params_hash: Mapped[str] = mapped_column(SHA256, nullable=False)
    priority: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("5"))
    #: ``analysis.cpu`` | ``analysis.gpu`` | ``ingest`` | ``reports`` | ``maintenance``. ``text``,
    #: not an enum: queues are an operational choice that changes with the hardware available.
    queue: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    status: Mapped[JobStatus] = mapped_column(
        native_enum(JobStatus), nullable=False, server_default=text("'queued'")
    )
    celery_task_id: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: NULL for scheduled jobs: a timer is not a person, and pretending otherwise would put a
    #: fabricated actor in the audit trail. The corresponding ``custody_events`` row then names a
    #: ``system_actor``.
    requested_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    worker_id: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    attempt: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("0"))
    queued_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    progress_pct: Mapped[int | None] = mapped_column(SmallInteger, nullable=True, default=None)
    progress_message: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: A coarse classification (``MODEL_UNAVAILABLE``, ``OOM``, ``DECODE_FAILED``, ``TIMEOUT``,
    #: ``INTEGRITY_MISMATCH``, ``INTERNAL``) so failures can be counted and routed without parsing
    #: prose. ``error_detail`` holds the sanitised rest — never file contents, never secrets.
    error_class: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    error_detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    resource_stats: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )

    case: Mapped[Case] = relationship(back_populates="analysis_jobs")
    #: `foreign_keys` pins this relationship to `evidence_id` alone. Without it SQLAlchemy
    #: derives the join from the composite (case_id, evidence_id) foreign key and both this
    #: relationship and `AnalysisJob.case` claim to write `case_id` — an ambiguity the ORM
    #: resolves arbitrarily. Pinned, each relationship owns exactly one column and the composite
    #: foreign key still refuses a job whose evidence belongs to another case.
    evidence: Mapped[EvidenceItem | None] = relationship(
        back_populates="analysis_jobs", foreign_keys=[evidence_id]
    )
    requested_by_user: Mapped[User | None] = relationship()
    results: Mapped[list[AnalysisResult]] = relationship(back_populates="job")
    derivatives: Mapped[list[Derivative]] = relationship(back_populates="produced_by_job")
    report_versions: Mapped[list[ReportVersion]] = relationship(back_populates="job")

    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "evidence_id"],
            ["evidence_items.case_id", "evidence_items.id"],
            name="fk_analysis_jobs_case_evidence_evidence_items",
            ondelete="CASCADE",
        ),
        Index("uq_analysis_jobs_idempotency_key", "idempotency_key", unique=True),
        CheckConstraint(
            f"params_hash ~ '{HEX_SHA256_PATTERN}'", name="params_hash_is_lowercase_hex"
        ),
        CheckConstraint("priority BETWEEN 0 AND 9", name="priority_in_range"),
        CheckConstraint(
            "progress_pct IS NULL OR progress_pct BETWEEN 0 AND 100", name="progress_in_range"
        ),
        CheckConstraint("attempt >= 0", name="attempt_not_negative"),
        CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="duration_not_negative"),
        # A job cannot be running without having started, nor finished without a finish time. These
        # are the two states an operator queries to find stuck work, so a row that says "running"
        # with no start time makes the query that finds it useless.
        CheckConstraint(
            "status <> 'running' OR started_at IS NOT NULL", name="running_has_started_at"
        ),
        CheckConstraint(
            "status NOT IN ('succeeded', 'failed', 'cancelled', 'dead_letter') "
            "OR finished_at IS NOT NULL",
            name="terminal_has_finished_at",
        ),
        CheckConstraint(
            "started_at IS NULL OR finished_at IS NULL OR finished_at >= started_at",
            name="finished_after_started",
        ),
        CheckConstraint(
            "error_class IS NULL OR status IN ('failed', 'retrying', 'dead_letter')",
            name="error_only_on_failing_states",
        ),
        Index("ix_analysis_jobs_case_status", "case_id", "status"),
        Index("ix_analysis_jobs_queue_status_priority", "queue", "status", "priority"),
        # The dispatcher's query: what is running right now. A partial index keeps it small no
        # matter how large the history grows.
        Index(
            "ix_analysis_jobs_running",
            "queue",
            "started_at",
            postgresql_where=text("status = 'running'"),
        ),
        Index("ix_analysis_jobs_evidence", "evidence_id"),
        Index("ix_analysis_jobs_requested_by", "requested_by"),
    )


class AnalysisResult(Base):
    """One indicator produced by one job — never a verdict (§5.2, AR-1).

    ``created_at`` only: a result is written once and then either superseded (``supersedes_id``,
    ``is_current``) or verified. It is never edited in place, because "the analysis said X at the
    time" has to remain answerable. Verification is recorded in dedicated columns rather than by
    mutating ``summary``, for the same reason.
    """

    __tablename__ = "analysis_results"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    job_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    evidence_id: Mapped[UUID | None] = mapped_column(nullable=True, default=None)
    pipeline: Mapped[str] = mapped_column(Text, nullable=False)
    pipeline_version: Mapped[str] = mapped_column(Text, nullable=False)
    #: ``ela_heatmap``, ``dqt_match``, ``transcript``, ``detection_set``, ``deepfake_advisory``…
    result_kind: Mapped[str] = mapped_column(Text, nullable=False)
    #: Human-readable and indicator-framed (AR-1): it says what was observed, not what it means.
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    #: The machine-readable findings: ``[{code, label, value, unit, confidence, region,
    #: interpretation}]``. JSONB because the shape is per-pipeline and queried by ``result_kind``
    #: first (DB-5); constrained to be an array so "one indicator" cannot be written as a bare
    #: object by one engine and as a list by another.
    indicators: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    #: NULL is honest when a score would not mean anything (AR-3). The CHECK below makes it
    #: impossible to publish a score without the interval that says how much it is worth.
    advisory_score: Mapped[Decimal | None] = mapped_column(
        score_numeric(), nullable=True, default=None
    )
    score_confidence_low: Mapped[Decimal | None] = mapped_column(
        score_numeric(), nullable=True, default=None
    )
    score_confidence_high: Mapped[Decimal | None] = mapped_column(
        score_numeric(), nullable=True, default=None
    )
    confidence: Mapped[Decimal | None] = mapped_column(
        confidence_numeric(), nullable=True, default=None
    )
    #: ``model_softmax`` | ``heuristic_threshold`` | ``statistical_test`` | ``not_applicable``.
    #: A 0.94 from a softmax and a 0.94 from a threshold on a hand-tuned statistic do not mean the
    #: same thing, and a number without its basis invites exactly that confusion.
    confidence_basis: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: FK-ish to ``limitation_statements.code`` (§5.3) — the design's own word, and it stays that
    #: way rather than becoming a real foreign key. A single-column key cannot express the reference,
    #: which is to a *version* of a statement resolved through its effective window, not to one row;
    #: and a code whose statements have all been retired must still read back on a historical result
    #: instead of dangling. Resolution is the reader's job, and :class:`LimitationStatement` below is
    #: the corpus it resolves against.
    limitations_code: Mapped[str] = mapped_column(Text, nullable=False)
    #: NOT NULL DEFAULT true, and no engine may set it false (ADR-0023). See the module docstring.
    requires_human_verification: Mapped[bool] = mapped_column(
        nullable=False, server_default=text("true")
    )
    verification_status: Mapped[VerificationStatus] = mapped_column(
        native_enum(VerificationStatus), nullable=False, server_default=text("'unverified'")
    )
    verified_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, default=None
    )
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    verification_notes: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: A re-run points at what it replaces, and ``is_current`` marks the live row. Keeping both
    #: means a report can cite the result that was current when it was generated while the UI shows
    #: the newest one — which is the difference between a reproducible report and a moving target.
    supersedes_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("analysis_results.id", ondelete="RESTRICT"), nullable=True, default=None
    )
    is_current: Mapped[bool] = mapped_column(nullable=False, server_default=text("true"))
    #: bbox / polygon / timecode the result pertains to. NULL for whole-item results.
    region_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    #: Derivatives illustrating this result. An array cannot enforce referential integrity, so a
    #: stale id is possible; §5.2 chooses it anyway because the list is always read as a whole with
    #: the result, and a join table would make the common read two queries. Anything that resolves
    #: these ids must treat a missing row as "artifact purged", not as an error.
    derivative_ids: Mapped[list[UUID] | None] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), nullable=True, default=None
    )
    raw_output: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True, default=None)
    #: Schema version of ``raw_output``, so a re-interpretation years later knows which reader to
    #: use. NOT NULL even when ``raw_output`` is NULL: the version of the format the engine
    #: *would have* written is still the answer to "what did this pipeline emit".
    raw_output_schema_version: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, server_default=text("now()")
    )

    job: Mapped[AnalysisJob] = relationship(back_populates="results")
    case: Mapped[Case] = relationship(back_populates="analysis_results")
    evidence: Mapped[EvidenceItem | None] = relationship(
        back_populates="analysis_results", foreign_keys=[evidence_id]
    )
    verified_by_user: Mapped[User | None] = relationship()
    supersedes: Mapped[AnalysisResult | None] = relationship(
        remote_side=[id], back_populates="superseded_by"
    )
    superseded_by: Mapped[list[AnalysisResult]] = relationship(back_populates="supersedes")

    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "evidence_id"],
            ["evidence_items.case_id", "evidence_items.id"],
            name="fk_analysis_results_case_evidence_evidence_items",
            ondelete="CASCADE",
        ),
        # ── The four constraints §5.2 requires, verbatim ────────────────────────────────────────
        CheckConstraint(
            "advisory_score IS NULL "
            "OR (score_confidence_low IS NOT NULL AND score_confidence_high IS NOT NULL)",
            name="score_requires_confidence_interval",
        ),
        CheckConstraint(
            "confidence IS NULL OR confidence_basis IS NOT NULL",
            name="confidence_requires_basis",
        ),
        CheckConstraint(
            "verification_status NOT IN ('confirmed', 'rejected') "
            "OR verification_notes IS NOT NULL",
            name="verdict_requires_notes",
        ),
        CheckConstraint(
            "verification_status <> 'unverified' OR verified_by IS NULL",
            name="unverified_has_no_verifier",
        ),
        # ── And the ones that stop the four above being satisfied nonsense ─────────────────────
        CheckConstraint(
            "score_confidence_low IS NULL OR score_confidence_high IS NULL "
            "OR score_confidence_low <= score_confidence_high",
            name="confidence_interval_is_ordered",
        ),
        CheckConstraint(
            "advisory_score IS NULL OR advisory_score BETWEEN 0 AND 100",
            name="score_in_range",
        ),
        CheckConstraint(
            "confidence IS NULL OR confidence BETWEEN 0 AND 1", name="confidence_in_range"
        ),
        CheckConstraint("jsonb_typeof(indicators) = 'array'", name="indicators_is_array"),
        CheckConstraint(
            "verified_by IS NULL OR verified_at IS NOT NULL", name="verifier_has_timestamp"
        ),
        CheckConstraint(
            "verification_status = 'unverified' OR verified_at IS NOT NULL",
            name="verdict_has_timestamp",
        ),
        Index("ix_analysis_results_case_kind_current", "case_id", "result_kind", "is_current"),
        Index("ix_analysis_results_evidence_current", "evidence_id", "is_current"),
        Index("ix_analysis_results_job", "job_id"),
        Index("ix_analysis_results_indicators_gin", "indicators", postgresql_using="gin"),
        # §10: the verification backlog. This is the query that tells a reviewer what is waiting,
        # and it must stay cheap as the table grows to millions of rows.
        Index(
            "ix_analysis_results_verification_backlog",
            "case_id",
            "created_at",
            postgresql_where=text("verification_status = 'unverified' AND is_current"),
        ),
        Index("ix_analysis_results_pipeline", "pipeline", "pipeline_version"),
    )


class LimitationStatement(Base):
    """One version of one AR-4 disclaimer (§5.3).

    ``analysis_results.limitations_code`` names a *code*; this table is what the code means, and the
    version is why the table exists. Wording changes — a sentence is tightened after a case shows it
    was misread, a qualifier is added — and every result ever published keeps pointing at the text
    that was in force when it was created. Without versions, correcting a disclaimer would rewrite
    the meaning of old findings; with them, a correction is a new row.

    ``(code, version)`` is the primary key, so the table cannot hold two different texts that both
    claim to be ``ELA`` version 3. That ambiguity is the one this schema least tolerates: it is the
    difference between a report reproducing its own reasoning and a report reproducing *a* reasoning.

    §5.3 specifies no ``id`` and no timestamps, and neither is added here. A surrogate key would sit
    beside the composite one without adding an identity, and an ``updated_at`` on a versioned
    statement would record edits to text a report may already have printed — the version number and
    the ``effective_from``/``effective_to`` window are the honest answer to "which wording was this,
    and when did it apply". The column set is asserted exactly in ``tests/db/test_models.py``, so
    this stays a transcription of §5.3 rather than a table that grows by convenience.
    """

    __tablename__ = "limitation_statements"

    #: ``ELA``, ``DEEPFAKE``, ``ALPR``, ``ASR``, ``DQT``, ``COPY_MOVE``, ``GEO_PLAUSIBILITY``, …
    #: (§5.3). Text rather than an enum for the reason §9 gives for growing sets: every new engine
    #: adds a code, and adding an enum label is migration-safe while retiring one is not.
    code: Mapped[str] = mapped_column(Text, primary_key=True)
    #: The version of the wording, ascending. A correction is a new version, never an edit.
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: The exact disclaimer rendered in the UI and embedded in reports (AR-4, RPT-01). NOT NULL and
    #: never blank: a finding whose limitation statement is an empty string has satisfied the column
    #: and defeated the rule.
    text_en: Mapped[str] = mapped_column(Text, nullable=False)
    #: The window the wording was in force. ``effective_to`` NULL means "still current". Resolution
    #: reads the statement whose window covers the result's ``created_at`` — which is what lets a
    #: report printed years later reproduce what the reader was told at the time.
    effective_from: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True, default=None
    )
    effective_to: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    #: Who approved this wording. NULL on the seeded corpus, which no account existed to approve when
    #: a fresh database was built — its approval of record is the ratified text of MASTER_PRD AR-4.
    #: ``SET NULL`` matches ``retention_policies.approved_by``: §12 deactivates accounts rather than
    #: erasing them, and a disclaimer that outlives its approver is still the disclaimer a report
    #: printed. An approver is attribution, not a load-bearing reference.
    approved_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )

    approved_by_user: Mapped[User | None] = relationship()

    __table_args__ = (
        # §5.3 names no constraints; these four are the ones without which the columns above cannot
        # do what §5.3 says they do. Each is recorded in backend/migrations/README.md.
        CheckConstraint("btrim(code) <> ''", name="code_is_not_blank"),
        # Version 0 or -1 would make "the latest version" a query with no natural floor, and a
        # corpus whose first entry is numbered 0 is a corpus somebody renumbered by hand.
        CheckConstraint("version >= 1", name="version_is_at_least_one"),
        CheckConstraint("btrim(text_en) <> ''", name="statement_text_is_not_blank"),
        # An inverted window resolves to nothing, so the statement would silently stop existing at
        # the moment it was meant to take effect.
        CheckConstraint(
            "effective_from IS NULL OR effective_to IS NULL OR effective_to >= effective_from",
            name="window_does_not_end_before_it_starts",
        ),
    )
