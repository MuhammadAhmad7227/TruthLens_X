"""Native PostgreSQL enum types — the canonical vocabulary of ``DATABASE_DESIGN.md`` §9.

Every enum here is a **native PostgreSQL type** (``CREATE TYPE … AS ENUM``), not a
``VARCHAR … CHECK``. §9 makes that choice and also states its one asymmetry, which is why the
module does not use enums everywhere:

    Adding a value is migration-safe (``ALTER TYPE … ADD VALUE``). Removing one is not — PostgreSQL
    has no ``DROP VALUE``, so a shrink means creating a new type, rewriting every column, and
    dropping the old one, inside a transaction that locks the table.

So: native enums for **small, stable, ratified** vocabularies (the ones below, each fixed by an ADR
or by §9), and ``text`` + a service-level or CHECK constraint for vocabularies that are expected to
grow — ``ai_provider_settings.provider``, ``notifications.kind``, ``cases.case_type``,
``analysis_jobs.queue``, ``audit_logs.action``. Putting a growing vocabulary into a native enum is
how a project ends up performing a table rewrite during an incident.

Labels are stored as the enum **values** (``admin``, ``lead_investigator``), never the Python
member names. ``values_callable`` is what makes that happen; without it SQLAlchemy would store
``ADMIN`` and ``LEAD_INVESTIGATOR``, every ``CHECK`` constraint and seeded row in the documentation
would silently disagree with the database, and the disagreement would only surface as a query that
matches nothing.
"""

from __future__ import annotations

from enum import StrEnum, unique

from sqlalchemy import Enum as SAEnum

__all__ = [
    "AIMessageStatus",
    "ArtifactStatus",
    "AuditResult",
    "CaseRole",
    "CaseStatus",
    "ChatRole",
    "CustodyEventType",
    "DerivativeKind",
    "EncState",
    "EvidenceStatus",
    "EvidenceType",
    "GlobalRole",
    "IntegrityStatus",
    "JobStatus",
    "ModelStatus",
    "PasswordAlgorithm",
    "ReportStatus",
    "Sensitivity",
    "SourceType",
    "UserStatus",
    "VerificationStatus",
    "native_enum",
]


def _snake(name: str) -> str:
    """``GlobalRole`` → ``global_role``. Derived, not repeated, so the two cannot disagree."""
    out: list[str] = []
    for index, char in enumerate(name):
        if char.isupper() and index:
            out.append("_")
        out.append(char.lower())
    return "".join(out)


def _labels(enum_cls: type[StrEnum]) -> list[str]:
    """The values stored in the database, in declaration order.

    A named function rather than a lambda so the return type is checked: ``values_callable`` is
    where the enum's Python spelling and the database's spelling meet, and an untyped lambda there
    is how ``ADMIN`` ends up in a column that every CHECK constraint calls ``admin``.
    """
    return [member.value for member in enum_cls]


def native_enum(py_enum: type[StrEnum], *, name: str | None = None) -> SAEnum:
    """Build the PostgreSQL ``ENUM`` type for a Python enum.

    The type name is derived from the class name (``GlobalRole`` → ``global_role``) unless given
    explicitly. Deriving is the default because a hand-written name can drift from the class it
    belongs to; the override exists for the one case where §9 already fixed a shorter spelling than
    the class name would produce (``password_alg``).

    A fresh instance per call: SQLAlchemy binds an ``Enum`` type to the columns and metadata that
    use it, and sharing one instance across a schema makes ``CREATE TYPE``/``DROP TYPE`` emission
    depend on import order.
    """
    return SAEnum(
        py_enum,
        name=name or _snake(py_enum.__name__),
        native_enum=True,
        values_callable=_labels,
    )


# ── Identity & authorization (§3.1, §3.3, §3.4) ────────────────────────────────────────────────


@unique
class GlobalRole(StrEnum):
    """Layer 1 of the authorization model (SECURITY_ARCHITECTURE §4.1).

    Materialised as rows in ``roles`` by migration ``0002`` so that ``role_permissions`` and
    ``user_roles`` can reference a role by primary key; the enum remains the column type of
    ``users.global_role`` because §3.1 indexes and queries on it directly.
    """

    ADMIN = "admin"
    LEAD_INVESTIGATOR = "lead_investigator"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    REVIEWER = "reviewer"
    AUDITOR = "auditor"


@unique
class UserStatus(StrEnum):
    """Lifecycle of a user account. ``deactivated`` is terminal but never deleted (§3.1)."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING_ACTIVATION = "pending_activation"
    DEACTIVATED = "deactivated"


@unique
class PasswordAlgorithm(StrEnum):
    """Which hasher produced ``users.password_hash``.

    ``bcrypt_legacy`` exists so a row imported from an older system can be rehashed to argon2id on
    the next successful login. Storing the algorithm next to the hash is what makes that migration
    possible without ever storing a plaintext password to re-hash from.
    """

    ARGON2ID = "argon2id"
    BCRYPT_LEGACY = "bcrypt_legacy"


@unique
class CaseRole(StrEnum):
    """Layer 2: the role a user holds *inside one case* (§3.4)."""

    OWNER = "owner"
    LEAD = "lead"
    MEMBER = "member"
    CONTRIBUTOR = "contributor"
    VIEWER = "viewer"


@unique
class CaseStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    UNDER_REVIEW = "under_review"
    CLOSED = "closed"
    ARCHIVED = "archived"


@unique
class Sensitivity(StrEnum):
    """Drives download, masking and export policy (§3.3, §4.2)."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# ── Evidence & integrity (§4) ──────────────────────────────────────────────────────────────────


@unique
class EvidenceType(StrEnum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    TEXT = "text"
    OTHER = "other"


@unique
class EvidenceStatus(StrEnum):
    """Where an item is in the ingest pipeline. ``integrity_failed`` is never transient."""

    INGESTING = "ingesting"
    HASHING = "hashing"
    STORED = "stored"
    ANALYSIS_PENDING = "analysis_pending"
    FAILED = "failed"
    QUARANTINED = "quarantined"
    INTEGRITY_FAILED = "integrity_failed"


@unique
class IntegrityStatus(StrEnum):
    """Result of the last hash verification against the stored digest (§4.2)."""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    MISSING = "missing"


@unique
class SourceType(StrEnum):
    """How the item entered the platform — provenance, kept separate from what it *is*."""

    UPLOAD = "upload"
    INTAKE_DIRECTORY = "intake_directory"
    API = "api"
    THIRD_PARTY = "third_party"
    EXTRACTED_CHILD = "extracted_child"


@unique
class EncState(StrEnum):
    """At-rest encryption state of the stored bytes (§4.1, D-006)."""

    NONE = "none"
    AES256GCM_ENVELOPE = "aes256gcm_envelope"


@unique
class CustodyEventType(StrEnum):
    """The append-only custody vocabulary (§4.3). Fourteen events, no more, no fewer.

    Deliberately a native enum even though the ledger grows without limit: the *kinds* of thing
    that can happen to evidence are ratified by the forensic process, not by whatever a feature
    needs this quarter. A new event type is a design decision that deserves a migration and a
    review, which is exactly what ``ALTER TYPE … ADD VALUE`` forces.
    """

    INGESTED = "ingested"
    HASH_COMPUTED = "hash_computed"
    HASH_VERIFIED = "hash_verified"
    ACCESSED = "accessed"
    DOWNLOADED = "downloaded"
    ANALYZED = "analyzed"
    VERIFICATION_SET = "verification_set"
    CUSTODY_TRANSFERRED = "custody_transferred"
    CUSTODY_ACCEPTED = "custody_accepted"
    LEGAL_HOLD = "legal_hold"
    RELEASED = "released"
    EXPORTED = "exported"
    QUARANTINED = "quarantined"
    INTEGRITY_ALERT = "integrity_alert"


@unique
class DerivativeKind(StrEnum):
    """§4.4. Every derivative is regenerable from the original, so this set can grow — but each
    value is a *kind of artifact the pipeline knows how to produce*, which is a design decision,
    not a per-case one."""

    THUMBNAIL = "thumbnail"
    FRAME = "frame"
    HEATMAP = "heatmap"
    OVERLAY = "overlay"
    TRANSCRIPT = "transcript"
    SPECTROGRAM = "spectrogram"
    WAVEFORM = "waveform"
    EXTRACTED_AUDIO = "extracted_audio"
    EXTRACTED_FILE = "extracted_file"
    REPORT_PDF = "report_pdf"
    GRAPH_IMAGE = "graph_image"
    ANNOTATION = "annotation"
    MASKED_PREVIEW = "masked_preview"


@unique
class ArtifactStatus(StrEnum):
    """``stale`` marks derivatives whose engine version changed; a reindex job regenerates them."""

    AVAILABLE = "available"
    STALE = "stale"
    PURGED = "purged"
    FAILED = "failed"


# ── Analysis (§5) ──────────────────────────────────────────────────────────────────────────────


@unique
class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"


@unique
class VerificationStatus(StrEnum):
    """Human verification of an indicator (AR-5, §5.2).

    ``unverified`` is the default and the honest state of everything an engine produces. Note what
    is *not* here: there is no ``auto_confirmed``. A machine cannot verify its own output, and the
    schema backs that with ``analysis_results.requires_human_verification`` defaulting to true and
    a CHECK that forbids a verdict without notes.
    """

    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


# ── Models, reports, audit (§3.5, §8) ──────────────────────────────────────────────────────────


@unique
class ModelStatus(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


@unique
class ReportStatus(StrEnum):
    GENERATING = "generating"
    DRAFT = "draft"
    FINAL = "final"
    SUPERSEDED = "superseded"
    FAILED = "failed"


@unique
class AuditResult(StrEnum):
    """Outcome of an audited action (§8.3). ``denied`` is first-class, not a variant of failure.

    A denied action is the most security-relevant row in the ledger — it is the record that an
    authorization decision was made and refused — so collapsing it into ``failure`` would lose the
    distinction operators query on.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


# ── AI assistant (§8.2) ────────────────────────────────────────────────────────────────────────


@unique
class ChatRole(StrEnum):
    """Who is speaking in an assistant turn (§9 names the type ``chat_role``).

    Deliberately a native enum, and deliberately four values. A message's role is the one field the
    citation rule in §8.2 keys on — ``role <> 'assistant' OR …`` — so a role that could be spelled
    freely would make that constraint advisory. ``tool`` is included because §9 lists it: a
    retrieval result is a turn in the transcript, and dropping it would push tool output into a
    ``user`` message, where the citation check would then demand citations for a chunk listing.
    """

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@unique
class AIMessageStatus(StrEnum):
    """Outcome of one assistant turn (§8.2: ``succeeded``, ``failed``, ``refused``).

    ``refused`` is its own value rather than a flavour of ``failed``, for the same reason
    ``AuditResult.denied`` is: a guardrail that declined to answer is the system working, and an
    operator counting refusals is measuring guardrail behaviour, not outages. Collapsing the two
    would make "the assistant is broken" and "the assistant declined" the same number.

    Not in §9's canonical list, which is recorded in ``migrations/README.md``: §8.2 specifies these
    three values in prose without declaring a type, so the type is named here (``ai_message_status``)
    rather than borrowed. ``invocation_status`` was considered and rejected — it carries ``partial``,
    which describes a forensic engine that produced some indicators, and a chat turn is either
    answered, not answered, or declined.
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUSED = "refused"
