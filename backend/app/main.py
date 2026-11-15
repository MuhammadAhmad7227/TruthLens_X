"""TruthLens X application factory.

The app is built by :func:`create_app` rather than as a module-level global so that tests can
construct isolated instances with overridden dependencies, and so configuration validation happens
at a defined point in the lifecycle.

Milestone M1 wires: configuration validation, structured logging with redaction, request-id
correlation, security headers, the RFC 9457 error model, and the system (health/readiness/status)
endpoints. Domain routers arrive from M3 onward.

**Startup is fail-closed.** Invalid configuration raises before the server accepts a single request:
a forensic platform that boots with a security control silently switched off is worse than one that
refuses to start.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.router import api_router
from app.core.config import ConfigurationError, Settings, get_settings
from app.core.exception_handlers import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware

logger = get_logger(__name__)

OPENAPI_TAGS: list[dict[str, Any]] = [
    {"name": "system", "description": "Liveness, readiness and platform status."},
]


def _cors_origins(settings: Settings) -> list[str]:
    """Parse the CORS allowlist.

    Empty (the default) means **same-origin only**, which is the recommended posture: the frontend is
    served through nginx from the same origin, so no CORS is needed at all. A wildcard is never
    permitted together with credentials — that combination lets any site make authenticated
    cross-origin requests.
    """
    raw = settings.cors_allowed_origins or ""
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown."""
    settings: Settings = app.state.settings
    configure_logging(level=settings.log_level, json_format=settings.log_format == "json")

    logger.info(
        "application.starting",
        version=__version__,
        env=str(settings.tlx_env.value),
        service=settings.service_name,
        storage_backend=settings.storage_backend,
        evidence_encryption=settings.evidence_encryption,
        llm_provider=settings.llm_provider,
        enable_external_ai=settings.enable_external_ai,
        # Log the GAPS, not the presence: "SECRET_KEY is missing" is actionable, "SECRET_KEY: true"
        # is not. The field name `config_gaps` deliberately does NOT match the redactor's
        # sensitive-key pattern — a field named `secrets_set` would be replaced wholesale by
        # `[REDACTED]`, which is safe but useless to an operator. The values here are variable
        # NAMES only; secret_names_set() returns booleans and cannot yield a value.
        config_gaps=[name for name, present in settings.secret_names_set().items() if not present],
    )

    # Configuration warnings are logged loudly rather than swallowed. Each one describes a state an
    # operator should know about (a copyleft flag enabled, retention unset, ephemeral secrets in use).
    for warning in settings.config_warnings:
        logger.warning("configuration.warning", detail=warning)

    if settings.ephemeral_secrets:
        logger.warning(
            "configuration.ephemeral_secrets",
            secrets=sorted(settings.ephemeral_secrets),
            detail=(
                "Ephemeral secrets were generated for a non-production environment. Sessions, signed "
                "URLs and any derived material will NOT survive a restart."
            ),
        )

    if not settings.retention_configured:
        logger.warning(
            "configuration.retention_not_configured",
            detail=(
                "RETENTION_STATUTORY_DAYS is unset. Per ADR-0020 retention jobs will DELETE NOTHING "
                "until an operator sets it on legal advice. This is a safe state, not an error, but "
                "storage will grow until it is resolved."
            ),
        )

    logger.info("application.started", version=__version__)
    try:
        yield
    finally:
        logger.info("application.stopping", version=__version__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build a configured application instance.

    Args:
        settings: explicit configuration. When omitted, :func:`get_settings` builds it from the
            environment. Tests pass an explicit instance to stay hermetic.

    Raises:
        ConfigurationError: if configuration violates a ratified decision. Propagates so the process
            exits non-zero rather than starting in a weakened state.
    """
    if settings is None:
        try:
            resolved = get_settings()
        except ConfigurationError:
            # Re-raise unchanged: the message already names the offending variable and the rule.
            raise
        except Exception as exc:
            msg = (
                "Configuration is invalid and startup is refused (fail-closed, "
                f"SECURITY_ARCHITECTURE §5.3):\n  - {type(exc).__name__}: {exc}"
            )
            raise ConfigurationError(msg) from exc
    else:
        resolved = settings

    app = FastAPI(
        title="TruthLens X API",
        version=__version__,
        summary=(
            "AI-powered digital forensics and evidence intelligence platform. AI outputs are "
            "investigative indicators, never confirmed facts: every result carries provenance, "
            "confidence with a stated basis, limitations and a human verification state."
        ),
        description=(
            "## Status\n\n"
            "**Milestone M1 — repository foundation.** Only the `system` namespace is implemented. "
            "Authentication, cases, evidence, custody and all forensic analysis modules arrive in "
            "M3-M16; see `docs/IMPLEMENTATION_ROADMAP.md`. No forensic capability exists yet and "
            "none is implied by this document.\n\n"
            "## Conventions\n\n"
            "* Errors are RFC 9457 `application/problem+json` with a stable `error_code` and a "
            "`request_id`. Parse `error_code`, never `title`.\n"
            "* Case-scoped resources are always nested under `/cases/{case_id}/` so access control "
            "has one unavoidable entry point.\n"
            "* Resources in a case the caller cannot access return **404**, not 403, so case "
            "existence is not enumerable (ADR-0004).\n"
        ),
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        # `license` and `contact` are intentionally OMITTED. The repository is deliberately
        # unlicensed (ADR-0008), and publishing a licence hint in generated API metadata would
        # imply a grant that has not been made. A contract test asserts `license` is absent.
    )
    app.state.settings = resolved

    # ── Middleware. Starlette applies these in reverse registration order, so the LAST added runs
    #    FIRST on the way in. Security headers are added first so they wrap everything and are set
    #    even on responses produced by the request-context middleware itself.
    app.add_middleware(RequestContextMiddleware, settings=resolved)
    app.add_middleware(SecurityHeadersMiddleware)

    origins = _cors_origins(resolved)
    if origins:
        # Only added when an allowlist is configured. With no origins set there is no CORS
        # middleware at all, which is stricter than an empty allowlist: the browser enforces
        # same-origin with no preflight surface exposed.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials="*" not in origins,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-Request-ID",
                "Idempotency-Key",
                "X-Egress-Confirmation",
            ],
            expose_headers=["X-Request-ID", "ETag", "X-RateLimit-Remaining", "Retry-After"],
            max_age=600,
        )

    register_exception_handlers(app)
    app.include_router(api_router)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, Any]:
        return {
            "service": resolved.service_name,
            "version": __version__,
            "status": "milestone-M1-foundation",
            "api": "/api/v1",
            "health": "/healthz",
            "readiness": "/readyz",
            "status_endpoint": "/api/v1/status",
            "docs": "/docs",
            "note": (
                "TruthLens X is under construction. Forensic analysis, authentication and evidence "
                "handling are NOT implemented yet — see docs/IMPLEMENTATION_ROADMAP.md. Nothing "
                "here should be read as an available capability."
            ),
        }

    logger.debug("application.created", version=__version__, env=str(resolved.tlx_env.value))
    return app


# There is deliberately NO module-level `app = create_app()`.
#
# Constructing the app at import time validated configuration as a side effect of importing, which
# made the module unimportable in any environment whose ambient variables were invalid, and forced
# every test to defer its imports. Serving through the ASGI factory means configuration is validated
# when the server actually starts — in each worker process, which is also where it belongs.
#
#   uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
#
# The compose files and Dockerfile entrypoints use `--factory`; see infra/.

__all__ = ["create_app"]
