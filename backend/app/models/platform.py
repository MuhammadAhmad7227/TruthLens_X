"""Platform administration tables: ``system_settings``, ``feature_flags``, ``retention_policies``.

§8.4 lists these three among the supporting tables. They are grouped here because they share a
property that no other table in the schema has: **their rows change what the platform does**, rather
than recording what happened to evidence. That makes their defaults a security decision, and every
default in this module is the closed one.

* ``feature_flags.enabled`` defaults to ``false`` — the same direction ``ai_provider_settings`` takes
  for ``is_enabled`` and ``allow_external_egress``, and the same one the ``ai_services`` registry takes
  with ``capability_enabled(name, default=False)``. A flag created by a migration with nothing else set
  therefore switches nothing on.
* ``retention_policies.action`` defaults to ``retain``. ADR-0020's first decision is that retention
  jobs delete nothing until an operator specifies a statutory period on the advice of counsel; a
  policy row that defaulted to ``delete`` would undo that decision by omission.
* ``system_settings`` is an **allowlist by construction** (ADM-06: a curated set of runtime-adjustable
  settings, all others environment-driven). Nothing is seeded here, so until a migration or an
  administrator with ``manage_settings`` inserts a row, there is nothing the UI can adjust — which is
  the correct empty state for a list nobody has curated yet.

None of these tables holds a secret. ``system_settings.value`` is JSONB and could in principle be
pointed at a credential; the column is not encrypted, and ``tests/db/test_models.py`` asserts that the
encrypted-secret columns in this schema are exactly the two the design specifies
(``users.mfa_secret_encrypted``, ``ai_provider_settings.api_key_encrypted``). A setting that needs to
be secret belongs in the environment or the secret store, not here — which is also what ADM-06's "all
others stay environment-driven" implies.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Interval, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.models.enums import EvidenceType, native_enum
from app.models.types import sql_value_list

if TYPE_CHECKING:
    from app.models.identity import User

__all__ = ["FeatureFlag", "RetentionPolicy", "SystemSetting"]

#: The data classes §12's retention table enumerates, transcribed rather than invented: Originals,
#: Derivatives, Analysis results, Custody/audit, Embeddings, User PII. A ``scope`` outside this list
#: is a policy about data the design does not recognise.
RETENTION_SCOPES: tuple[str, ...] = (
    "original",
    "derivative",
    "analysis_result",
    "custody_audit",
    "embedding",
    "user_pii",
)

#: The actions §12 and ADR-0020 describe, and no others: retain (the safe state), archive (custody and
#: audit go to cold storage and are never deleted), purge (derivatives — regenerable, automated, no
#: approval, but logged), delete (an original, under ADR-0020's four conditions).
RETENTION_ACTIONS: tuple[str, ...] = ("retain", "archive", "purge", "delete")


class SystemSetting(Base, TimestampMixin):
    """One runtime-adjustable setting, its value, and the shape that value must have (§8.4, ADM-06).

    ``value_schema`` is what makes the setting *curated* rather than arbitrary: the admin UI validates
    against it before writing, so a typo cannot put a string where a number of days belongs. The
    attribute is named ``value_schema`` while the **column** stays ``schema``, exactly as
    ``audit_logs`` keeps a column named ``metadata`` behind an attribute called ``event_metadata``:
    §8.4 names the column, and ``SystemSetting.schema`` in Python would read as the database schema.

    Validation against that shape happens in the service layer, not here, and that is a limit worth
    stating plainly: PostgreSQL has no JSON Schema validator, so no CHECK constraint can enforce
    conformance. What the database does enforce is that a setting always *has* a declared shape —
    a value with no schema beside it is a value nothing can validate.

    ``previous_value`` is one level of history, not an audit trail. It answers "what did this say
    before somebody changed it", which is what an operator needs when a change turns out to be wrong.
    The full trail — who changed it, when, from where, and whether they were allowed to — is an
    ``audit_logs`` row (§8.3), and a settings table that tried to be its own audit log would end up
    with neither.
    """

    __tablename__ = "system_settings"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    #: The allowlist entry itself. PostgreSQL accepts ``key`` as a column name (verified on 16.2), so
    #: §8.4's spelling is kept rather than worked around.
    key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    value: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    #: Column name ``schema`` per §8.4; see the class docstring for the attribute name.
    value_schema: Mapped[dict[str, Any]] = mapped_column(
        "schema", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    #: NULL until the setting has been changed once — so a NULL here means "this is the value it was
    #: created with", which is a fact, not a gap.
    previous_value: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )
    #: ``SET NULL``: deactivating an administrator must not be blocked by settings they once touched,
    #: and the durable attribution is the audit row, not this pointer.
    updated_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )

    updated_by_user: Mapped[User | None] = relationship()

    __table_args__ = (
        # A blank key is a setting nothing can address, and the unique index would happily hold one.
        CheckConstraint("btrim(key) <> ''", name="key_is_not_blank"),
        Index("ix_system_settings_updated_at", "updated_at"),
    )


class FeatureFlag(Base, TimestampMixin):
    """A licence or rollout switch (§8.4), off until somebody turns it on and says why.

    ``reason`` is NOT NULL with a non-blank CHECK. That is stricter than §8.4's column list, which
    does not state a nullability, and it is deliberate: a flag this platform flips is a statement about
    a licence position (ADR-0001's copyleft gates), a rollout decision, or a legal constraint — and
    "``ENABLE_AGPL_PYMUPDF`` was on" with nothing beside it is not answerable six months later when
    somebody asks who accepted that obligation and on what basis. A flag nobody wrote a reason for is
    a switch nobody can explain to an auditor, so the row is refused instead.

    The vocabulary of keys is *not* constrained here, for the reason §9 gives: flags are added by
    features. ``config.py`` is the authority on which environment-driven flags exist, and this table
    holds the ones an administrator may change at runtime.
    """

    __tablename__ = "feature_flags"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    #: Fail closed: a row created by a migration with no other values enables nothing.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )

    updated_by_user: Mapped[User | None] = relationship()

    __table_args__ = (
        CheckConstraint("btrim(key) <> ''", name="key_is_not_blank"),
        CheckConstraint("btrim(reason) <> ''", name="reason_is_not_blank"),
        # The enabled population, which is the only thing a startup check reads. Small table, so this
        # index exists for the partial predicate rather than for selectivity.
        Index("ix_feature_flags_enabled", "key", postgresql_where=text("enabled")),
    )


class RetentionPolicy(Base, TimestampMixin):
    """A configured lifecycle rule (§8.4, AUD-06), bounded by §12 and ADR-0020.

    This table is where a retention decision becomes data, and it is written so that the decisions
    ADR-0020 already ratified cannot be unmade by inserting a row:

    * **The default action is ``retain``.** ADR-0020's first decision is that until an operator sets
      ``RETENTION_STATUTORY_DAYS`` on legal advice, retention jobs delete nothing. A policy row that
      defaulted to anything else would be a deletion nobody authorised.
    * **Audit and custody can never be deleted.** ADR-0020's second decision and §12's "never deleted
      in v1; archival only" are enforced by a CHECK on ``scope``, so the most destructive mistake
      available in an admin UI is not available at all.
    * **Deleting an original names an approver.** ADR-0020's fourth decision requires an administrator,
      a written justification, a second approver and a permanent audit record before an original is
      destroyed. This schema holds the approver and refuses the row without one; the justification and
      the audit record are §8.3's and the service layer's, and M19 wires them together.
    * **Purging a derivative does not.** §12 is explicit that derivatives are automated with no
      approval, because they are regenerable from the original — so requiring an approver there would
      be a constraint contradicting the rule it was written to serve.

    ``keep_until_event`` is ``text`` with no CHECK and ``keep_duration`` is a PostgreSQL ``interval``.
    The two compose the way §12 describes retention — an event the clock starts at, plus a duration —
    and both are nullable, because ADR-0020 sources the statutory period from configuration rather
    than from a row here. An event vocabulary is deliberately not fixed: the events a clock can start
    at grow with the lifecycle features (M4's case states), and §9 is explicit that a growing
    vocabulary must not be a native enum.
    """

    __tablename__ = "retention_policies"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    #: One of §12's data classes, listed in ``RETENTION_SCOPES`` and enforced by a CHECK. ``text``
    #: rather than an enum for §9's reason, but constrained rather than free: unlike a provider name or
    #: a notification kind, a retention scope selects which deletion rule applies to evidence, and a
    #: scope nobody defined would match no rule at all — silently retaining everything it was meant to
    #: govern.
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    #: NULL means the policy covers every evidence type in its scope. Reuses the canonical
    #: ``evidence_type`` (§9), so a policy cannot name a type the platform does not have.
    evidence_type: Mapped[EvidenceType | None] = mapped_column(
        native_enum(EvidenceType), nullable=True, default=None
    )
    keep_until_event: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    keep_duration: Mapped[timedelta | None] = mapped_column(Interval(), nullable=True, default=None)
    action: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'retain'"))
    approved_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )

    approved_by_user: Mapped[User | None] = relationship()

    __table_args__ = (
        CheckConstraint(
            f"scope IN {sql_value_list(RETENTION_SCOPES)}", name="scope_is_a_known_data_class"
        ),
        CheckConstraint(
            f"action IN {sql_value_list(RETENTION_ACTIONS)}", name="action_is_a_known_action"
        ),
        # ADR-0020 (2), §12: custody and audit outlive their cases and are archived, never deleted.
        CheckConstraint(
            "scope <> 'custody_audit' OR action IN ('retain', 'archive')",
            name="audit_is_never_deleted",
        ),
        # ADR-0020 (4): destroying an original is a dual-approved act, so the row names an approver.
        CheckConstraint(
            "action <> 'delete' OR approved_by IS NOT NULL", name="deletion_names_an_approver"
        ),
        # "Which policy governs this item" is the only query a retention job makes.
        Index("ix_retention_policies_scope_type", "scope", "evidence_type"),
        # There is deliberately no UNIQUE on (scope, evidence_type). Two rows may legitimately
        # overlap — a scope-wide policy and a narrower type-specific one — and which of them wins is a
        # resolution rule that belongs to the retention service in M19, not to a constraint that would
        # forbid the override before anybody had decided how it works.
    )
