"""System endpoints: liveness, readiness and platform status.

These are the only unauthenticated endpoints in M1 besides ``/openapi.json`` and ``/``.
See ``docs/API_SPECIFICATION.md`` §2.14.

**Known M1 limitation, stated rather than hidden:** ``/api/v1/status`` is unauthenticated because no
authentication exists yet — that arrives in M3. It is safe in M1 only because it exposes no
sensitive data: configuration *names* and booleans, never values. From M19 it requires an admin
capability. ``secret_names_set()`` is defined to return booleans, so leaking a value through this
endpoint would require changing that method's signature, not a careless call here.
"""

from __future__ import annotations

from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from app import __version__
from app.core.config import Settings, get_settings
from app.core.health import (
    LivenessReport,
    ReadinessRegistry,
    ReadinessReport,
    build_default_registry,
)
from app.core.logging import redact_value

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["system"])


def get_readiness_registry() -> ReadinessRegistry:
    """Readiness registry dependency. Overridden in tests to inject deterministic outcomes."""
    return build_default_registry()


def get_current_settings() -> Settings:
    """Settings dependency, so tests can override configuration without touching the singleton."""
    return get_settings()


ReadinessRegistryDep = Annotated[ReadinessRegistry, Depends(get_readiness_registry)]
SettingsDep = Annotated[Settings, Depends(get_current_settings)]


@router.get(
    "/healthz",
    response_model=LivenessReport,
    summary="Liveness probe",
    description=(
        "Returns 200 whenever the process is alive. **Checks no dependencies on purpose** — a probe "
        "that fails because PostgreSQL is briefly unreachable would cause a supervisor to restart "
        "healthy processes in a loop, turning a dependency blip into an outage. Use `/readyz` for "
        "dependency state."
    ),
)
async def healthz(settings: SettingsDep) -> LivenessReport:
    return LivenessReport(status="ok", version=__version__, service=settings.service_name)


@router.get(
    "/readyz",
    response_model=ReadinessReport,
    summary="Readiness probe",
    description=(
        "Returns 200 only when every **required** dependency is reachable. Returns 503 with a "
        "per-check breakdown otherwise. A required check reporting `not_configured` counts as NOT "
        "ready: an unconfigured dependency is a misconfiguration, not a pass."
    ),
)
async def readyz(registry: ReadinessRegistryDep) -> Any:
    report = await registry.evaluate()
    if report.is_ready:
        return report

    logger.warning(
        "readiness.not_ready",
        failed=[c.name for c in report.checks if c.status != "ok"],
        detail={c.name: c.detail for c in report.checks if c.status != "ok"},
    )
    # Emit problem+json for consistency with every other non-2xx response, while carrying the
    # structured report an operator or orchestrator actually needs.
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        media_type="application/problem+json",
        content={
            "type": "https://errors.truthlens.local/dependency-unavailable",
            "title": "A required service is unavailable",
            "status": 503,
            "detail": "One or more required readiness checks did not pass.",
            "error_code": "DEPENDENCY_UNAVAILABLE",
            "remediation": "Inspect the 'report.checks' array for the failing dependency.",
            # A JSONResponse bypasses the structlog redaction processor entirely, so a driver
            # error that echoes its DSN would reach the client verbatim. Anything leaving the
            # process over HTTP passes the same redaction as anything written to a log.
            "report": redact_value(report.model_dump(mode="json")),
        },
    )


@router.get(
    "/api/v1/status",
    summary="Detailed platform status",
    description=(
        "Configuration and dependency state for operators. **Secret names are reported, never "
        "values.** Also reports which copyleft and egress flags are active, so an operator can verify "
        "a deployment's licensing and data-residency posture at a glance (ADR-0001, ADR-0012), and "
        "which capabilities are **not yet implemented**, so nothing is implied that does not exist."
    ),
)
async def status_endpoint(settings: SettingsDep, registry: ReadinessRegistryDep) -> dict[str, Any]:
    readiness = await registry.evaluate()
    return {
        "service": settings.service_name,
        "version": __version__,
        "environment": str(settings.tlx_env.value),
        "readiness": readiness.model_dump(mode="json"),
        "configuration": {
            # Names and booleans only. secret_names_set() cannot return a value.
            "secrets_set": settings.secret_names_set(),
            "ephemeral_secrets_generated": sorted(settings.ephemeral_secrets),
            "warnings": settings.config_warnings,
            "storage_backend": settings.storage_backend,
            "evidence_encryption": settings.evidence_encryption,
            "retention_configured": settings.retention_configured,
            "preflight_required": settings.preflight_required,
        },
        "feature_flags": {
            "enable_ultralytics": settings.enable_ultralytics,
            "enable_agpl_pymupdf": settings.enable_agpl_pymupdf,
            "enable_exiftool": settings.enable_exiftool,
            "enable_poppler": settings.enable_poppler,
            "enable_av_scan": settings.enable_av_scan,
            "enable_online_geocoding": settings.enable_online_geocoding,
            "enable_external_enrichment": settings.enable_external_enrichment,
            "gazetteer_enabled": settings.gazetteer_enabled,
            "enable_external_ai": settings.enable_external_ai,
            "llm_provider": settings.llm_provider,
            "external_ai_effectively_enabled": settings.external_ai_effectively_enabled,
            "external_ai_allowed_categories": list(settings.external_ai_allowed_categories),
            # Always false, in every environment, by decision (ADR-0013).
            "alpr_allow_registry_lookup": settings.alpr_allow_registry_lookup,
        },
        "milestone": {
            "current": "M1",
            "implemented": [
                "configuration with fail-closed validation of ratified decisions",
                "structured logging with unconditional secret redaction",
                "request-id correlation",
                "RFC 9457 error model",
                "liveness and readiness probes",
                "security response headers",
            ],
            "not_yet_implemented": [
                "authentication, MFA and authorisation (M3)",
                "case management (M4)",
                "evidence ingest and integrity (M5)",
                "chain of custody (M6)",
                "background processing with Celery (M7)",
                "all forensic analysis modules (M8-M16)",
                "AI assistant and inference providers (M17)",
                "report generation (M18)",
            ],
        },
    }


__all__ = ["get_current_settings", "get_readiness_registry", "router"]
