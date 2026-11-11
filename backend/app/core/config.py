"""Typed application configuration with fail-closed validation.

This module is the enforcement point for the ratified decisions in ``docs/adr/``. A configuration
that violates one of them **aborts startup** rather than starting in a weakened state — a forensic
platform that silently runs with a security control switched off is worse than one that refuses to
boot.

Design rules:

* Every field carries an ``alias`` matching the variable name in ``.env.example`` **exactly**, so the
  documentation and the code cannot drift apart unnoticed.
* ``ConfigurationError`` messages name the offending variable and the rule, and **never echo a
  secret value** — an error message ends up in logs, on consoles and in issue trackers.
* Outside production, missing secrets are replaced with **ephemeral generated values** and the fact
  is recorded in ``ephemeral_secrets`` and ``config_warnings``. A weak hardcoded default would be
  invisible; a generated one is loud.

See ``docs/SECURITY_ARCHITECTURE.md`` §5.3 and ``docs/AI_ARCHITECTURE.md`` §3.1.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment. ``TLX_ENV`` in ``.env.example`` §1."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def is_prod_like(self) -> bool:
        """Staging is held to production standards: it runs on real infrastructure with real data
        shapes, and a control that is only enforced in production is a control nobody tests."""
        return self in (Environment.STAGING, Environment.PRODUCTION)


class ConfigurationError(RuntimeError):
    """Raised when configuration violates a ratified decision. Aborts startup."""


#: Values that indicate a secret was never actually set.
PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "change_me",
        "change-me",
        "dev",
        "development",
        "example",
        "foo",
        "placeholder",
        "secret",
        "secrets",
        "test",
        "testing",
        "todo",
        "toor",
        "truthlens",
        "unset",
        "xxx",
        "your_secret_here",
        "your-secret-here",
        "password",
        "admin",
        "none",
        "null",
    }
)

#: Minimum entropy (characters) for critical secrets in prod-like environments.
MIN_SECRET_LENGTH = 32

_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

#: Secrets whose absence outside production is survivable because we generate an ephemeral value.
_EPHEMERAL_ELIGIBLE = (
    "secret_key",
    "signed_url_key",
    "jwt_private_key",
    "jwt_public_key",
    "encryption_key",
)

#: Variables that must be real, long and non-placeholder in prod-like environments.
_CRITICAL_SECRETS = (
    ("secret_key", "SECRET_KEY"),
    ("signed_url_key", "SIGNED_URL_KEY"),
    ("jwt_private_key", "JWT_PRIVATE_KEY"),
    ("jwt_public_key", "JWT_PUBLIC_KEY"),
)


def _is_placeholder(value: str | None) -> bool:
    """Whether a secret value is one a human would recognise as "not really set"."""
    if value is None:
        return True
    lowered = value.strip().lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    # A single repeated character ("aaaa...", "xxxx...") has no entropy despite its length.
    if len(set(lowered)) == 1:
        return True
    # Common template markers.
    return any(marker in lowered for marker in ("<", ">", "${", "insert_", "replace_me", "todo"))


class Settings(BaseSettings):
    """The single typed view of all TruthLens X configuration.

    Field names match the variables documented in ``.env.example`` exactly.
    """

    model_config = SettingsConfigDict(
        # .env is loaded by the process supervisor, not by the app: that keeps precedence explicit
        # and prevents a stray file from silently overriding the deployment's real configuration.
        env_file=None,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
        # `models_root` would otherwise collide with pydantic's reserved `model_` namespace.
        protected_namespaces=(),
        # Allow construction by field name as well as by env alias (used throughout the tests).
        populate_by_name=True,
    )

    # ── 1. Runtime ───────────────────────────────────────────────────────────
    tlx_env: Environment = Field(default=Environment.DEVELOPMENT, alias="TLX_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    timezone: str = Field(default="UTC", alias="TZ")
    request_id_header: str = Field(default="X-Request-ID", alias="REQUEST_ID_HEADER")
    service_name: str = Field(default="truthlens", alias="SERVICE_NAME")
    #: Binding 0.0.0.0 is required inside the container so the compose network can reach it. This
    #: is NOT the same as exposing the service: per DEPLOYMENT_GUIDE's port-exposure rule only nginx
    #: publishes 80/443, and the api service publishes no host port at all. Bandit's B104 is a true
    #: positive for a bare-metal bind and a false positive for this topology, so it is scoped and
    #: justified here rather than disabled project-wide.
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")  # noqa: S104  # nosec B104
    api_port: int = Field(default=8000, ge=1, le=65535, alias="API_PORT")
    workers: int = Field(default=4, ge=1, le=64, alias="WORKERS")
    enable_metrics: bool = Field(default=True, alias="ENABLE_METRICS")

    #: Never true outside a deliberate development session; refused entirely in production.
    debug: bool = Field(default=False, alias="DEBUG")
    testing: bool = Field(default=False, alias="TESTING")

    # ── 1b. Web / CORS / cookies ─────────────────────────────────────────────
    #: Empty means same-origin only, which is the recommended posture: the frontend is served
    #: through nginx from the same origin, so no CORS is needed at all. A wildcard is never
    #: combined with credentials.
    cors_allowed_origins: str = Field(default="", alias="CORS_ALLOWED_ORIGINS")
    cookie_secure: bool = Field(default=True, alias="COOKIE_SECURE")
    cookie_samesite: str = Field(default="strict", alias="COOKIE_SAMESITE")
    cookie_httponly: bool = Field(default=True, alias="COOKIE_HTTPONLY")
    csrf_enabled: bool = Field(default=True, alias="CSRF_ENABLED")
    trust_proxy_headers: bool = Field(default=True, alias="TRUST_PROXY_HEADERS")

    # ── 2. Secrets ───────────────────────────────────────────────────────────
    secret_key: str | None = Field(default=None, alias="SECRET_KEY")
    signed_url_key: str | None = Field(default=None, alias="SIGNED_URL_KEY")
    jwt_private_key: str | None = Field(default=None, alias="JWT_PRIVATE_KEY")
    jwt_public_key: str | None = Field(default=None, alias="JWT_PUBLIC_KEY")
    #: NOT USED IN v1 — reserved for the v2 envelope-encryption path (ADR-0006). Still validated as
    #: a critical secret in production so a future migration is not blocked by a missing key.
    encryption_key: str | None = Field(default=None, alias="ENCRYPTION_KEY")
    #: The `kid` claim naming which signing key issued a token, so keys can be rotated inside an
    #: overlap window instead of invalidating every live session at once. The default is
    #: deliberately undated: operators should set a dated identifier per rotation (see
    #: `.env.example`), and a dated value baked into the source would only read like a secret.
    jwt_key_id: str = Field(default="truthlens-signing-key", alias="JWT_KEY_ID")
    jwt_issuer: str = Field(default="https://truthlens.example.local", alias="JWT_ISSUER")
    jwt_audience: str = Field(default="truthlens-web", alias="JWT_AUDIENCE")
    access_token_ttl_seconds: int = Field(
        default=900, ge=60, le=900, alias="ACCESS_TOKEN_TTL_SECONDS"
    )
    refresh_token_ttl_seconds: int = Field(
        default=43200, ge=300, le=2592000, alias="REFRESH_TOKEN_TTL_SECONDS"
    )
    #: ADR-0004: signed evidence URLs are short-lived, and a `purpose` is mandatory.
    signed_url_ttl_seconds: int = Field(default=120, ge=10, le=900, alias="SIGNED_URL_TTL_SECONDS")

    # ── 3. Database ──────────────────────────────────────────────────────────
    database_url: str | None = Field(default=None, alias="DATABASE_URL")
    db_pool_size: int = Field(default=10, ge=1, le=200, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, ge=0, le=200, alias="DB_MAX_OVERFLOW")
    db_pool_timeout_seconds: int = Field(default=30, ge=1, le=300, alias="DB_POOL_TIMEOUT_SECONDS")
    db_pool_recycle_seconds: int = Field(default=1800, ge=60, alias="DB_POOL_RECYCLE_SECONDS")
    db_statement_timeout_ms: int = Field(default=30000, ge=100, alias="DB_STATEMENT_TIMEOUT_MS")
    #: Logs SQL, which can contain personal data. Refused in production.
    db_echo: bool = Field(default=False, alias="DB_ECHO")

    # ── 4. Redis / Celery ────────────────────────────────────────────────────
    redis_url: str | None = Field(default=None, alias="REDIS_URL")
    #: ADR-0022: the Celery result backend is PostgreSQL, so Redis holds nothing durable.
    celery_result_backend: str | None = Field(default=None, alias="CELERY_RESULT_BACKEND")
    celery_task_always_eager: bool = Field(default=False, alias="CELERY_TASK_ALWAYS_EAGER")

    # ── 5. Evidence storage ──────────────────────────────────────────────────
    #: ADR-0011: `filesystem` is the ONLY accepted value in v1. No S3 code ships.
    storage_backend: str = Field(default="filesystem", alias="STORAGE_BACKEND")
    evidence_root: Path = Field(default=Path("/evidence/originals"), alias="EVIDENCE_ROOT")
    derivatives_root: Path = Field(default=Path("/evidence/derivatives"), alias="DERIVATIVES_ROOT")
    intake_root: Path = Field(default=Path("/evidence/intake"), alias="INTAKE_ROOT")
    quarantine_root: Path = Field(default=Path("/evidence/quarantine"), alias="QUARANTINE_ROOT")
    models_root: Path = Field(default=Path("/models"), alias="MODELS_ROOT")
    models_lock_file: Path = Field(default=Path("infra/models.lock.json"), alias="MODELS_LOCK_FILE")
    #: ADR-0012: weights are provisioned offline by script, never fetched at runtime.
    allow_model_download: bool = Field(default=False, alias="ALLOW_MODEL_DOWNLOAD")
    #: A mismatch fails closed — never load, never fall back.
    model_fetch_verify_checksum: bool = Field(default=True, alias="MODEL_FETCH_VERIFY_CHECKSUM")
    max_upload_bytes: int = Field(default=4294967296, ge=1, alias="MAX_UPLOAD_BYTES")
    max_chunk_bytes: int = Field(default=8388608, ge=4096, alias="MAX_CHUNK_BYTES")
    #: 1 MiB streaming block bounds RAM regardless of evidence size.
    hash_block_bytes: int = Field(default=1048576, ge=4096, alias="HASH_BLOCK_BYTES")
    merkle_enabled: bool = Field(default=False, alias="MERKLE_ENABLED")
    merkle_block_bytes: int = Field(default=4194304, ge=4096, alias="MERKLE_BLOCK_BYTES")
    #: ADR-0006: `disabled` is the ONLY accepted value in v1.
    evidence_encryption: str = Field(default="disabled", alias="EVIDENCE_ENCRYPTION")
    intake_retention_hours: int = Field(default=24, ge=1, alias="INTAKE_RETENTION_HOURS")
    derivative_retention_days: int = Field(default=90, ge=1, alias="DERIVATIVE_RETENTION_DAYS")
    #: ADR-0020: NO DEFAULT ON PURPOSE. Unset means retention jobs delete nothing.
    retention_statutory_days: int | None = Field(default=None, alias="RETENTION_STATUTORY_DAYS")

    # ── 6. Host preflight (ADR-0006 §5.4) ────────────────────────────────────
    #: MUST be true in production: the encrypted-volume check runs before the app starts.
    preflight_required: bool = Field(default=True, alias="PREFLIGHT_REQUIRED")
    evidence_volume_device: str = Field(
        default="/dev/mapper/truthlens-evidence", alias="EVIDENCE_VOLUME_DEVICE"
    )
    evidence_mount_point: Path = Field(default=Path("/srv/truthlens"), alias="EVIDENCE_MOUNT_POINT")
    nginx_doc_root: Path = Field(default=Path("/usr/share/nginx/html"), alias="NGINX_DOC_ROOT")

    # ── 7. Copyleft and egress flags (ADR-0001, ADR-0012) ────────────────────
    enable_ultralytics: bool = Field(default=False, alias="ENABLE_ULTRALYTICS")
    enable_agpl_pymupdf: bool = Field(default=False, alias="ENABLE_AGPL_PYMuPDF")
    #: ADR-0003: the one flag that defaults ON — subprocess-isolated and removable.
    enable_exiftool: bool = Field(default=True, alias="ENABLE_EXIFTOOL")
    exiftool_binary: Path | None = Field(default=None, alias="EXIFTOOL_BINARY")
    exiftool_timeout_seconds: int = Field(
        default=120, ge=5, le=3600, alias="EXIFTOOL_TIMEOUT_SECONDS"
    )
    enable_poppler: bool = Field(default=False, alias="ENABLE_POPPLER")
    enable_online_geocoding: bool = Field(default=False, alias="ENABLE_ONLINE_GEOCODING")
    #: ADR-0015: DISABLED by default; dataset licence unverified (finding L-7).
    gazetteer_enabled: bool = Field(default=False, alias="GAZETTEER_ENABLED")
    gazetteer_path: Path | None = Field(default=None, alias="GAZETTEER_PATH")
    #: Mandatory if the gazetteer is enabled: every plausible candidate licence requires attribution.
    gazetteer_attribution: str = Field(default="", alias="GAZETTEER_ATTRIBUTION")
    #: The master egress switch. Governs every per-feature flag (ADR-0012).
    enable_external_enrichment: bool = Field(default=False, alias="ENABLE_EXTERNAL_ENRICHMENT")
    enable_av_scan: bool = Field(default=False, alias="ENABLE_AV_SCAN")
    enable_av_updates: bool = Field(default=False, alias="ENABLE_AV_UPDATES")

    # ── 8. ALPR (ADR-0013) ───────────────────────────────────────────────────
    #: HARD DISABLED. Setting this true aborts startup in EVERY environment. The ALPR module
    #: contains no HTTP client at all, so the prohibition is architectural, not just configured.
    alpr_allow_registry_lookup: bool = Field(default=False, alias="ALPR_ALLOW_REGISTRY_LOOKUP")
    #: No default on purpose: jurisdiction must never be inferred from deployment geography.
    alpr_jurisdiction: str = Field(default="", alias="ALPR_JURISDICTION")

    # ── 9. AI assistant (ADR-0007, ADR-0021) ─────────────────────────────────
    #: Fixed at startup — no runtime switch, so cloud fallback is structurally impossible.
    llm_provider: str = Field(default="local", alias="LLM_PROVIDER")
    #: MASTER GATE for external AI. Admin activation only; grants expire within 30 days.
    enable_external_ai: bool = Field(default=False, alias="ENABLE_EXTERNAL_AI")
    llm_allow_external_egress: bool = Field(default=False, alias="LLM_ALLOW_EXTERNAL_EGRESS")
    #: Cannot be false in production — ADR-0021 requirement 9 is not negotiable.
    llm_egress_confirmation_required: bool = Field(
        default=True, alias="LLM_EGRESS_CONFIRMATION_REQUIRED"
    )
    #: EMPTY by default: enabling external AI alone authorises the transmission of NOTHING.
    llm_external_allowed_categories: str = Field(
        default="", alias="LLM_EXTERNAL_ALLOWED_CATEGORIES"
    )
    llm_external_grant_max_days: int = Field(
        default=30, ge=1, le=30, alias="LLM_EXTERNAL_GRANT_MAX_DAYS"
    )
    #: Server-side only. Never a NEXT_PUBLIC_* variable — CI greps the built bundle.
    llm_external_api_key: str = Field(default="", alias="LLM_EXTERNAL_API_KEY")
    llm_prompt_template_version: str = Field(default="v1.0.0", alias="LLM_PROMPT_TEMPLATE_VERSION")
    #: Below this score the assistant returns a templated refusal WITHOUT calling the model.
    llm_retrieval_min_score: float = Field(
        default=0.62, ge=0.0, le=1.0, alias="LLM_RETRIEVAL_MIN_SCORE"
    )
    #: Deterministic by default: this is an evidential context, not a creative one.
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0, alias="LLM_TEMPERATURE")

    # ── 10. Rate limiting ────────────────────────────────────────────────────
    rate_limit_default: str = Field(default="300/m", alias="RATE_LIMIT_DEFAULT")
    rate_limit_auth: str = Field(default="10/m", alias="RATE_LIMIT_AUTH")
    rate_limit_upload: str = Field(default="30/m", alias="RATE_LIMIT_UPLOAD")
    rate_limit_assistant: str = Field(default="60/h", alias="RATE_LIMIT_ASSISTANT")

    # ── Internal state (not configurable) ────────────────────────────────────
    #: Names of secrets that were generated for this process because none was supplied.
    ephemeral_secrets: list[str] = Field(default_factory=list, exclude=True)
    #: Human-readable warnings an operator must see at startup and via /api/v1/status.
    config_warnings: list[str] = Field(default_factory=list, exclude=True)

    # ── Field validators ─────────────────────────────────────────────────────
    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: Any) -> str:
        level = str(value).strip().upper()
        if level not in _VALID_LOG_LEVELS:
            msg = f"LOG_LEVEL must be one of {sorted(_VALID_LOG_LEVELS)}, got {value!r}"
            raise ConfigurationError(msg)
        return level

    @field_validator("log_format", mode="before")
    @classmethod
    def _normalise_log_format(cls, value: Any) -> str:
        fmt = str(value).strip().lower()
        if fmt not in {"json", "console"}:
            msg = f"LOG_FORMAT must be 'json' or 'console', got {value!r}"
            raise ConfigurationError(msg)
        return fmt

    @field_validator("storage_backend", mode="before")
    @classmethod
    def _validate_storage_backend(cls, value: Any) -> str:
        backend = str(value).strip().lower()
        if backend != "filesystem":
            # ADR-0011: no S3 implementation ships. Refusing beats pretending.
            msg = (
                f"STORAGE_BACKEND={value!r} is not available in v1. Only 'filesystem' is "
                "implemented (ADR-0011: the StorageBackend interface exists so an object store "
                "can be added later, but no S3 code ships in v1 and a disabled adapter would be "
                "an untested placeholder)."
            )
            raise ConfigurationError(msg)
        return backend

    @field_validator("evidence_encryption", mode="before")
    @classmethod
    def _validate_evidence_encryption(cls, value: Any) -> str:
        mode = str(value).strip().lower()
        if mode != "disabled":
            msg = (
                f"EVIDENCE_ENCRYPTION={value!r} is NOT IMPLEMENTED in v1. Only 'disabled' is "
                "accepted, because application-level envelope encryption does not exist yet "
                "(ADR-0006). At-rest protection is LUKS2 volume encryption; see "
                "docs/BACKUP_RECOVERY.md §5. Accepting this value would imply a protection the "
                "code does not provide."
            )
            raise ConfigurationError(msg)
        return mode

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, value: str) -> str:
        if value.strip().upper() != "UTC":
            msg = (
                "TZ must be UTC. Timestamps are evidence: a local-timezone deployment makes "
                "every recorded time ambiguous and undermines the audit chain."
            )
            raise ConfigurationError(msg)
        return "UTC"

    # ── Policy enforcement ───────────────────────────────────────────────────
    @model_validator(mode="after")
    def _enforce_policy(self) -> Self:
        warnings: list[str] = []
        errors: list[str] = []

        # (a) Generate ephemeral secrets outside production, and say so loudly.
        self._generate_ephemeral_secrets(warnings)

        # Each rule group is a separate method so a reviewer can read one ratified decision at a
        # time, and a failing test names the rule rather than a line inside a 60-branch validator.
        self._check_production_hardening(errors)
        self._check_critical_secrets(errors)
        self._check_alpr_policy(errors)
        self._check_ai_policy(errors)
        self._check_egress_policy(errors)
        self._check_gazetteer(errors)
        self._check_web_root_isolation(errors)
        self._validate_storage_roots(errors)
        self._warn_on_copyleft_flags(warnings)
        self._warn_on_retention(warnings)
        self._check_no_ephemeral_secrets_in_production(errors)

        if errors:
            msg = (
                "Configuration is invalid and startup is refused (fail-closed, "
                "SECURITY_ARCHITECTURE §5.3):\n  - " + "\n  - ".join(errors)
            )
            raise ConfigurationError(msg)

        self.config_warnings = warnings
        return self

    # ── Rule groups (one method per ratified decision area) ───────────────────
    def _check_production_hardening(self, errors: list[str]) -> None:
        """Refuse to run a weakened production process (SECURITY_ARCHITECTURE §5.3)."""
        if self.tlx_env is not Environment.PRODUCTION:
            return
        if self.debug:
            errors.append("DEBUG=true is refused when TLX_ENV=production.")
        if self.testing:
            errors.append("TESTING=true is refused when TLX_ENV=production.")
        if self.log_format == "console":
            errors.append(
                "LOG_FORMAT=console is refused when TLX_ENV=production; use 'json' so logs are "
                "machine-parseable and redaction is verifiable."
            )
        if self.db_echo:
            errors.append(
                "DB_ECHO=true is refused when TLX_ENV=production; it logs SQL that can contain "
                "personal data."
            )
        # ADR-0006 §5.4: the encrypted-volume preflight is mandatory.
        if not self.preflight_required:
            errors.append(
                "PREFLIGHT_REQUIRED=false is refused when TLX_ENV=production. The "
                "encrypted-volume check must run before the application starts (ADR-0006); a "
                "silently unmounted volume would write evidence to unencrypted storage."
            )

    def _check_critical_secrets(self, errors: list[str]) -> None:
        """Real, long, non-placeholder secrets and connection strings in prod-like environments."""
        if not self.tlx_env.is_prod_like:
            return
        for attr, env_name in _CRITICAL_SECRETS:
            value = getattr(self, attr)
            if not value or _is_placeholder(value):
                errors.append(
                    f"{env_name} is required when TLX_ENV={self.tlx_env.value} and must not be a "
                    "placeholder. Generate one with: openssl rand -hex 32   (or "
                    "./infra/scripts/genkeys.sh). Startup refuses to continue without it."
                )
            elif len(value) < MIN_SECRET_LENGTH and not value.startswith("-----BEGIN"):
                errors.append(
                    f"{env_name} must be at least {MIN_SECRET_LENGTH} characters when "
                    f"TLX_ENV={self.tlx_env.value}; the supplied value is too short to be a "
                    "credible secret. (Values are never echoed here.)"
                )
        if not self.database_url or _is_placeholder(self.database_url):
            errors.append(
                f"DATABASE_URL must be set to a real connection string when "
                f"TLX_ENV={self.tlx_env.value}."
            )
        if not self.redis_url or _is_placeholder(self.redis_url):
            errors.append(
                f"REDIS_URL must be set to a real connection string when "
                f"TLX_ENV={self.tlx_env.value}."
            )
        # ADR-0021: the confirmation step cannot be switched off where it matters.
        if not self.llm_egress_confirmation_required:
            errors.append(
                "LLM_EGRESS_CONFIRMATION_REQUIRED=false is refused when "
                f"TLX_ENV={self.tlx_env.value}. ADR-0021 requires an explicit confirmation step "
                "before any external transmission; it is not negotiable in a production-like "
                "environment."
            )

    def _check_alpr_policy(self, errors: list[str]) -> None:
        """ADR-0013 — hard-disabled in EVERY environment, including development."""
        if self.alpr_allow_registry_lookup:
            errors.append(
                "ALPR_ALLOW_REGISTRY_LOOKUP=true is refused in every environment. ADR-0013 "
                "hard-disables external vehicle-registry lookup: no flag value activates it, and "
                "the ALPR module contains no HTTP client. Registry integration is v2 backlog and "
                "would require a new ADR plus a jurisdictional legal review."
            )

    def _check_ai_policy(self, errors: list[str]) -> None:
        """ADR-0007 / ADR-0021 — external AI is a gated, confirmed, never-fallback path."""
        if self.llm_provider == "external" and not self.enable_external_ai:
            errors.append(
                "LLM_PROVIDER=external requires ENABLE_EXTERNAL_AI=true. External providers are "
                "disabled by default (ADR-0007) and activation is an authorized administrator "
                "action recorded in the audit log (ADR-0021)."
            )
        if self.llm_allow_external_egress and not self.enable_external_ai:
            errors.append(
                "LLM_ALLOW_EXTERNAL_EGRESS=true requires ENABLE_EXTERNAL_AI=true. The master gate "
                "must be opened deliberately before any egress flag has effect (ADR-0021)."
            )
        if self.llm_provider == "external" and _is_placeholder(self.llm_external_api_key):
            errors.append(
                "LLM_PROVIDER=external requires a real LLM_EXTERNAL_API_KEY. The key is held "
                "server-side only and must never appear in a NEXT_PUBLIC_* variable (ADR-0007)."
            )

    def _check_egress_policy(self, errors: list[str]) -> None:
        """ADR-0012 — one master switch governs every per-feature egress flag; ADR-0014 for AV."""
        if not self.enable_external_enrichment:
            if self.enable_online_geocoding:
                errors.append(
                    "ENABLE_ONLINE_GEOCODING=true requires ENABLE_EXTERNAL_ENRICHMENT=true. The "
                    "master egress switch governs every per-feature flag (ADR-0012); there is no "
                    "per-feature override."
                )
            if self.allow_model_download:
                errors.append(
                    "ALLOW_MODEL_DOWNLOAD=true requires ENABLE_EXTERNAL_ENRICHMENT=true (ADR-0012). "
                    "Model artifacts are provisioned offline by infra/scripts/fetch-models.sh and "
                    "verified against models.lock.json."
                )
            if self.enable_av_scan:
                errors.append(
                    "ENABLE_AV_SCAN=true requires ENABLE_EXTERNAL_ENRICHMENT=true when signature "
                    "updates are wanted, because updates are outbound traffic (ADR-0012, ADR-0014)."
                )
        # ADR-0014: updating signatures for a scanner that is not running is pointless egress.
        if self.enable_av_updates and not self.enable_av_scan:
            errors.append(
                "ENABLE_AV_UPDATES=true requires ENABLE_AV_SCAN=true (ADR-0014). Signature updates "
                "are outbound traffic; fetching them for a disabled scanner is egress with no "
                "benefit."
            )

    def _check_gazetteer(self, errors: list[str]) -> None:
        """ADR-0015 — dataset licence unverified (L-7), so attribution is mandatory if enabled."""
        if self.gazetteer_enabled and not self.gazetteer_attribution.strip():
            errors.append(
                "GAZETTEER_ENABLED=true requires GAZETTEER_ATTRIBUTION to be set. The gazetteer "
                "dataset licence could not be verified (finding L-7), so it ships disabled; if an "
                "operator enables it, attribution is mandatory because every plausible candidate "
                "licence requires it (ADR-0015)."
            )

    def _check_web_root_isolation(self, errors: list[str]) -> None:
        """The nginx document root must not reach the evidence volume, in either direction.

        ``.env.example`` documents this as an asserted invariant, and it is the cheapest
        authorisation bypass on the platform: a static file server pointed at the evidence tree
        serves every original to anyone who can reach the host, with no session, no capability
        check and no signed URL (ADR-0004, SECURITY_ARCHITECTURE §5). Containment is checked both
        ways because either nesting makes evidence web-reachable.

        A symlink is the realistic way this happens by accident, so paths are resolved before
        comparison.
        """
        if not self.nginx_doc_root.is_absolute():
            errors.append(
                f"NGINX_DOC_ROOT must be an absolute path so web-root isolation can be checked; "
                f"got {str(self.nginx_doc_root)!r}."
            )
            return
        if not self.evidence_mount_point.is_absolute():
            errors.append(
                f"EVIDENCE_MOUNT_POINT must be an absolute path so web-root isolation can be "
                f"checked; got {str(self.evidence_mount_point)!r}."
            )
            return

        web_root = self.nginx_doc_root.resolve()
        mount = self.evidence_mount_point.resolve()
        rationale = (
            "The web root and the evidence volume must be disjoint: nginx would serve evidence "
            "originals with no session, no capability check and no signed URL, which is a complete "
            "authorisation bypass (ADR-0004, SECURITY_ARCHITECTURE §5)."
        )
        if web_root == mount or mount.is_relative_to(web_root):
            errors.append(
                f"EVIDENCE_MOUNT_POINT ({mount}) must not be inside NGINX_DOC_ROOT ({web_root}). "
                + rationale
            )
        elif web_root.is_relative_to(mount):
            errors.append(
                f"NGINX_DOC_ROOT ({web_root}) must not be inside EVIDENCE_MOUNT_POINT ({mount}). "
                + rationale
            )

    def _warn_on_copyleft_flags(self, warnings: list[str]) -> None:
        """ADR-0001 — a copyleft component is never activated silently."""
        for attr, env_name, licence in (
            ("enable_ultralytics", "ENABLE_ULTRALYTICS", "AGPL-3.0"),
            ("enable_agpl_pymupdf", "ENABLE_AGPL_PYMuPDF", "AGPL-3.0"),
            ("enable_poppler", "ENABLE_POPPLER", "GPL-2.0+"),
            ("enable_av_scan", "ENABLE_AV_SCAN", "GPL-2.0"),
        ):
            if getattr(self, attr):
                warnings.append(
                    f"{env_name}=true activates a copyleft ({licence}) component. This is an "
                    "explicit, audited operator action — see docs/THIRD_PARTY_LICENSE_AUDIT.md and "
                    "ADR-0001. Confirm the licensing obligation has been accepted."
                )

    def _warn_on_retention(self, warnings: list[str]) -> None:
        """ADR-0020 — no default statutory period; unset means delete nothing."""
        if self.retention_statutory_days is None:
            warnings.append(
                "RETENTION_STATUTORY_DAYS is not set. Per ADR-0020 this is a safe state: retention "
                "jobs will DELETE NOTHING and the admin dashboard shows a persistent warning. Set "
                "it only on legal advice — the platform deliberately has no default, because a "
                "software default would become a legal position."
            )

    def _check_no_ephemeral_secrets_in_production(self, errors: list[str]) -> None:
        """Ephemeral secrets are a development convenience and are never acceptable in production."""
        if self.tlx_env.is_prod_like and self.ephemeral_secrets:
            errors.append(
                "Ephemeral secrets were generated for "
                f"{', '.join(sorted(self.ephemeral_secrets))}, which is refused when "
                f"TLX_ENV={self.tlx_env.value}. Supply real values."
            )

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _generate_ephemeral_secrets(self, warnings: list[str]) -> None:
        """Fill missing secrets **outside production** with process-lifetime random values.

        A generated secret is recorded so it can be reported. A hardcoded weak default would be
        invisible, and invisibility is the actual danger.

        In prod-like environments this is a no-op on purpose: generating a value would mask the
        missing secret and produce a confusing error. Refusing with the variable's name is the
        actionable outcome.
        """
        generated: list[str] = []
        if self.tlx_env.is_prod_like:
            self.ephemeral_secrets = []
            return
        for attr in _EPHEMERAL_ELIGIBLE:
            current = getattr(self, attr)
            if current is None or _is_placeholder(str(current)):
                # A key id rather than a key pair: JWT signing is M3, and generating a valid
                # Ed25519 PEM here would imply a capability that does not exist yet.
                if attr in ("jwt_private_key", "jwt_public_key"):
                    value = f"ephemeral-{attr}-{secrets.token_hex(16)}"
                else:
                    value = secrets.token_hex(32)
                object.__setattr__(self, attr, value)
                generated.append(_field_for(attr))
        if generated:
            warnings.append(
                "EPHEMERAL SECRETS were generated for "
                f"{', '.join(sorted(generated))} because none was supplied. They exist for this "
                "process only: sessions, signed URLs and any derived material will NOT survive a "
                "restart, and they are not valid in any other environment. This is acceptable "
                f"for TLX_ENV={self.tlx_env.value} and refused in production."
            )
        self.ephemeral_secrets = generated

    def _validate_storage_roots(self, errors: list[str]) -> None:
        roots = {
            "EVIDENCE_ROOT": self.evidence_root,
            "DERIVATIVES_ROOT": self.derivatives_root,
            "INTAKE_ROOT": self.intake_root,
            "QUARANTINE_ROOT": self.quarantine_root,
        }
        for name, root in roots.items():
            if not root.is_absolute():
                errors.append(
                    f"{name} must be an absolute path so a derivatives purge can never resolve "
                    f"into the originals tree; got {str(root)!r}."
                )
        # Overlapping roots would let a purge of one delete contents of another. Originals are
        # write-once and irreplaceable, so this is checked rather than trusted.
        resolved = {name: root.resolve() for name, root in roots.items() if root.is_absolute()}
        for name, path in resolved.items():
            for other_name, other in resolved.items():
                if name == other_name:
                    continue
                if name == "EVIDENCE_ROOT" and other.is_relative_to(path):
                    errors.append(
                        f"{other_name} ({other}) must not overlap {name} ({path}). Derived "
                        "artifacts are disposable and originals are not; a shared tree would let "
                        "a derivatives purge destroy evidence (ADR-0011)."
                    )
                elif path == other:
                    errors.append(f"{name} and {other_name} must not be the same path ({path}).")

    # ── Derived views ────────────────────────────────────────────────────────
    @property
    def retention_configured(self) -> bool:
        """Whether a statutory retention period has been set (ADR-0020)."""
        return self.retention_statutory_days is not None

    @property
    def external_ai_allowed_categories(self) -> tuple[str, ...]:
        """Parsed allowlist of data categories permitted to leave the host.

        Empty by default: enabling external AI alone authorises the transmission of *nothing*
        (ADR-0021). Categories must be listed explicitly.
        """
        raw = self.llm_external_allowed_categories or ""
        return tuple(part.strip() for part in raw.split(",") if part.strip())

    @property
    def external_ai_effectively_enabled(self) -> bool:
        """Whether an external provider could actually be reached right now.

        Requires **all three** switches plus a real key, so no single misconfiguration enables
        egress (ADR-0007, ADR-0021).
        """
        return bool(
            self.enable_external_ai
            and self.llm_provider == "external"
            and self.llm_allow_external_egress
            and not _is_placeholder(self.llm_external_api_key)
        )

    def secret_names_set(self) -> dict[str, bool]:
        """Which critical secrets are configured — **names only, never values**.

        Safe to expose via ``/api/v1/status`` and to log: the return type makes leaking a value
        impossible, because it contains only booleans.
        """
        return {
            _field_for(attr): bool(getattr(self, attr))
            and not _is_placeholder(str(getattr(self, attr)))
            for attr, _env in (
                ("secret_key", "SECRET_KEY"),
                ("signed_url_key", "SIGNED_URL_KEY"),
                ("jwt_private_key", "JWT_PRIVATE_KEY"),
                ("jwt_public_key", "JWT_PUBLIC_KEY"),
                ("encryption_key", "ENCRYPTION_KEY"),
            )
        }


#: Field attribute -> the environment variable name it is read from.
_ALIAS_CACHE: dict[str, str] | None = None


def _alias_map() -> dict[str, str]:
    """Field attribute -> the environment variable name it is read from.

    The alias is used **verbatim**: ``ENABLE_AGPL_PYMuPDF`` is mixed-case in ``.env.example``, and
    upper-casing it would produce a name that appears nowhere in the documentation.
    """
    global _ALIAS_CACHE  # noqa: PLW0603 — module-level cache, populated once
    if _ALIAS_CACHE is None:
        _ALIAS_CACHE = {
            name: (field.alias or name.upper()) for name, field in Settings.model_fields.items()
        }
    return _ALIAS_CACHE


def _field_for(attr: str) -> str:
    """The environment variable name for a field attribute."""
    return _alias_map().get(attr, attr.upper())


# ── Process-wide accessor ────────────────────────────────────────────────────
_settings: Settings | None = None


def get_settings(force_reload: bool = False) -> Settings:
    """Return the process configuration, building it on first use.

    Raises:
        ConfigurationError: if configuration violates a ratified decision. Propagates so the
            process exits non-zero rather than starting in a weakened state.
    """
    global _settings  # noqa: PLW0603
    if _settings is None or force_reload:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Drop the cached configuration. Used by tests to keep cases hermetic."""
    global _settings  # noqa: PLW0603
    _settings = None


__all__ = [
    "MIN_SECRET_LENGTH",
    "PLACEHOLDER_VALUES",
    "ConfigurationError",
    "Environment",
    "Settings",
    "get_settings",
    "reset_settings",
]
