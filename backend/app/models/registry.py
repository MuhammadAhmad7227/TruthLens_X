"""The model registry (``ai_models``) and AI provider settings.

``ai_models`` is what ``DATABASE_DESIGN.md`` §3.5 calls the model registry — the milestone's entity
list names it ``model_registry``, and it is the same table (§14 records the mapping). The name
``ai_models`` is kept because the rest of the schema already refers to it that way:
``ai_conversations.model_id`` and ``model_invocations`` both point at ``ai_models``.

Two columns carry the platform's honesty requirements about its own machinery:

* ``measured_performance`` is **our** measurement — dataset name, its digest, sample count, and the
  resulting rates. AR-6 forbids publishing a vendor's claim as though it were a property of this
  deployment, and a column that has nowhere to put the dataset digest cannot support that rule.
* ``licence`` is an SPDX identifier, which is what the CI licence gate reasons about
  (``docs/THIRD_PARTY_LICENSE_AUDIT.md``). A free-text licence *name* would make that gate a
  string-matching exercise against whatever anybody typed.

``ai_provider_settings`` is where the external-AI master switch lives in the database. Every
default here is the closed one: ``is_enabled`` false, ``allow_external_egress`` false,
``requires_confirmation`` true, ``allowed_categories`` empty. A row created by a migration with no
other values therefore permits nothing, which is the state a misconfiguration should produce.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
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
from sqlalchemy.types import LargeBinary

from app.db.base import Base, TimestampMixin, UTCDateTime
from app.models.enums import ModelStatus, native_enum
from app.models.types import HEX_SHA256_PATTERN, SHA256, text_array

if TYPE_CHECKING:
    from app.models.identity import User

__all__ = ["AIModel", "AIProviderSettings"]


class AIModel(Base, TimestampMixin):
    """A registered model or algorithmic engine, pinned by identity and digest (§3.5).

    ``(family, name, version)`` is unique, so a registry cannot hold two different artifacts that
    claim to be the same model — the ambiguity that makes "which model produced this finding"
    unanswerable.
    """

    __tablename__ = "ai_models"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    #: ``whisper``, ``yolo``, ``clip``, ``easyocr``, ``ela``…
    family: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    #: ``asr``, ``detection``, ``ocr``, ``embedding``, ``deepfake_indicator``…
    task: Mapped[str] = mapped_column(Text, nullable=False)
    #: NULL for algorithmic engines (ELA, DQT) which have no weights. NOT NULL for anything with
    #: weights is a rule the schema cannot express without a column saying which kind of engine this
    #: is, so it is enforced where the distinction is known — the registration service, in the
    #: milestone that ships model management. Recording the omission here rather than inventing a
    #: ``has_weights`` flag that §3.5 does not specify.
    weights_sha256: Mapped[str | None] = mapped_column(SHA256, nullable=True, default=None)
    #: Relative to the read-only model mount (ADR-0011: no downloads at runtime).
    weights_path: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    framework: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    framework_version: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: SPDX identifier, checked against policy by the CI licence gate.
    licence: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
    #: NULL for CPU engines.
    min_vram_mb: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    status: Mapped[ModelStatus] = mapped_column(
        native_enum(ModelStatus), nullable=False, server_default=text("'active'")
    )
    #: One default per ``(family, task)``, enforced by the partial unique index below. Without it,
    #: two rows could both claim to be the default detector and the choice would depend on query
    #: order — an arbitrary decision in a place where reproducibility is the requirement.
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    measured_performance: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True, default=None
    )
    model_card_summary: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    registered_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    registered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)

    registered_by_user: Mapped[User | None] = relationship()
    provider_defaults: Mapped[list[AIProviderSettings]] = relationship(
        back_populates="default_model"
    )

    __table_args__ = (
        UniqueConstraint("family", "name", "version", name="uq_ai_models_family_name_version"),
        CheckConstraint(
            f"weights_sha256 IS NULL OR weights_sha256 ~ '{HEX_SHA256_PATTERN}'",
            name="weights_sha256_is_lowercase_hex",
        ),
        CheckConstraint("size_bytes IS NULL OR size_bytes >= 0", name="size_not_negative"),
        CheckConstraint("min_vram_mb IS NULL OR min_vram_mb >= 0", name="vram_not_negative"),
        CheckConstraint(
            # A default is a property of a model that is in service. A deprecated row keeping its
            # default flag would leave the family with a default nothing should select.
            "is_default = false OR status = 'active'",
            name="only_active_models_are_default",
        ),
        Index(
            "uq_ai_models_default_per_family_task",
            "family",
            "task",
            unique=True,
            postgresql_where=text("is_default AND status = 'active'"),
        ),
        Index("ix_ai_models_task_status", "task", "status"),
        Index("ix_ai_models_family", "family"),
    )


class AIProviderSettings(Base, TimestampMixin):
    """Per-provider configuration for the assistant (AI-01, AI-03, ADR-0012).

    ``provider`` is ``text``, not an enum: §8.2 lists ``local_ollama``, ``vllm`` and
    ``external_api`` today, and the set grows whenever a deployment wants another backend. §9 is
    explicit that a growing vocabulary must not be a native PostgreSQL enum, because removing a
    value later means rebuilding the type and every column that uses it.

    No column here can hold a credential in the clear. ``api_key_ref`` names a secret held
    elsewhere (an environment variable or the secret store), and ``api_key_encrypted`` is ``bytea``
    ciphertext under the application KEK — the same rule ``users.mfa_secret_encrypted`` follows.
    """

    __tablename__ = "ai_provider_settings"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: Endpoint for networked providers. NULL for in-process ones. Never a credential, never a
    #: path into the evidence mount.
    base_url: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: The *name* of the secret, not the secret. Storing a reference means rotating a key is a
    #: deployment action and never a database write.
    api_key_ref: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: Ciphertext, for deployments that keep the key in the database under the KEK (D-006).
    api_key_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True, default=None
    )
    #: The master switch, per provider (ADR-0012). Defaults to false so that a row created by a
    #: migration sends nothing anywhere.
    allow_external_egress: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    #: Egress must be confirmed by a user with the capability (SECURITY_ARCHITECTURE §7,
    #: ``EgressConfirmationRequiredError``). Enforced against the flag above by a CHECK, so the two
    #: cannot be configured into the unsafe combination — 403-or-nothing is a database property
    #: here, not a convention.
    requires_confirmation: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    #: Which evidence categories may leave the host at all. Empty means none, and the authorization
    #: check is fail-closed on an empty list (ADR-0012).
    allowed_categories: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, server_default=text("'{}'")
    )
    #: Optional default model for this provider. ``SET NULL`` rather than ``RESTRICT``: retiring a
    #: model must not be blocked by a settings row, and a provider with no default simply requires
    #: the caller to name one.
    default_model_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("ai_models.id", ondelete="SET NULL"), nullable=True, default=None
    )
    rate_limit_rpm: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    timeout_ms: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    #: Disabled by default. An enabled provider is a deliberate act by someone with
    #: ``manage_settings``.
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    #: Provider-specific knobs (sampling defaults, context window, TLS options). JSONB because the
    #: shape differs per provider and nothing queries inside it (DB-5).
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )

    default_model: Mapped[AIModel | None] = relationship(back_populates="provider_defaults")
    created_by_user: Mapped[User | None] = relationship()

    __table_args__ = (
        # Fail closed at the schema level: external egress without confirmation is not a
        # configurable state.
        CheckConstraint(
            "allow_external_egress = false OR requires_confirmation = true",
            name="egress_requires_confirmation",
        ),
        # One credential mechanism, not two. If both were populated, which one is authoritative
        # would depend on the order a service happened to read them in — and an ambiguity about
        # which key is in use is an ambiguity about what was sent where.
        CheckConstraint(
            "api_key_ref IS NULL OR api_key_encrypted IS NULL", name="one_credential_mechanism"
        ),
        CheckConstraint("rate_limit_rpm IS NULL OR rate_limit_rpm > 0", name="rate_limit_positive"),
        CheckConstraint("timeout_ms IS NULL OR timeout_ms > 0", name="timeout_positive"),
        # A provider that may send data out must say which categories it may send.
        CheckConstraint(
            "allow_external_egress = false OR cardinality(allowed_categories) > 0",
            name="egress_names_allowed_categories",
        ),
        Index("ix_ai_provider_settings_enabled", "is_enabled"),
    )
