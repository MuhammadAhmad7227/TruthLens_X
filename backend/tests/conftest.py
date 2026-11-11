"""Shared pytest fixtures.

Design notes (``docs/TESTING_STRATEGY.md`` §4.1):

* Settings are constructed **explicitly**, never read from the ambient environment, so tests are
  hermetic and order-independent. The ``hermetic_env`` fixture strips any TruthLens variable that
  could bleed in from the host.
* The readiness registry is **injectable**, so both the ready and not-ready paths are tested without
  any live PostgreSQL or Redis. Neither exists in CI or in the development sandbox.
* A **canary secret** is injected into every settings fixture. The security suite asserts that this
  canary never appears in any captured response, log line or serialised object — a leak test that
  works by looking for a value that should be impossible to find.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import system
from app.core.config import Environment, Settings, reset_settings
from app.core.health import CheckName, CheckResult, CheckStatus, ReadinessRegistry
from app.main import create_app

#: Canary value asserted absent from all output by tests/security/test_no_secret_leakage.py.
CANARY_SECRET = "CANARY-SECRET-9f3b7d2e1a5c4806-do-not-leak"
CANARY_KEY_ID = "CANARY-KEY-2c8e41b7a9d04f6e"
CANARY_DB_PASSWORD = "c4n4ry-db-p4ssw0rd-value"
CANARY_REDIS_PASSWORD = "c4n4ry-r3d1s-p4ssw0rd-value"

#: Environment variables that could bleed into a hermetic test from the host.
_ENV_KEYS = (
    "TLX_ENV",
    "DEBUG",
    "TESTING",
    "SECRET_KEY",
    "SIGNED_URL_KEY",
    "JWT_PRIVATE_KEY",
    "JWT_PUBLIC_KEY",
    "ENCRYPTION_KEY",
    "JWT_KEY_ID",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "DATABASE_URL",
    "REDIS_URL",
    "DB_ECHO",
    "LOG_FORMAT",
    "LOG_LEVEL",
    "TZ",
    "STORAGE_BACKEND",
    "EVIDENCE_ENCRYPTION",
    "EVIDENCE_ROOT",
    "DERIVATIVES_ROOT",
    "INTAKE_ROOT",
    "QUARANTINE_ROOT",
    "MODELS_ROOT",
    "PREFLIGHT_REQUIRED",
    "ENABLE_EXTERNAL_AI",
    "LLM_PROVIDER",
    "LLM_ALLOW_EXTERNAL_EGRESS",
    "LLM_EGRESS_CONFIRMATION_REQUIRED",
    "LLM_EXTERNAL_ALLOWED_CATEGORIES",
    "LLM_EXTERNAL_API_KEY",
    "ALPR_ALLOW_REGISTRY_LOOKUP",
    "ALPR_JURISDICTION",
    "GAZETTEER_ENABLED",
    "GAZETTEER_ATTRIBUTION",
    "ENABLE_ONLINE_GEOCODING",
    "ENABLE_EXTERNAL_ENRICHMENT",
    "ALLOW_MODEL_DOWNLOAD",
    "ENABLE_AV_SCAN",
    "ENABLE_AV_UPDATES",
    "ENABLE_ULTRALYTICS",
    "ENABLE_AGPL_PYMuPDF",
    "ENABLE_POPPLER",
    "RETENTION_STATUTORY_DAYS",
    "CORS_ALLOWED_ORIGINS",
    "SERVICE_NAME",
    "API_HOST",
    "CELERY_TASK_ALWAYS_EAGER",
    "ENABLE_METRICS",
)


@pytest.fixture(autouse=True)
def hermetic_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove ambient TruthLens configuration and reset the settings singleton.

    Autouse and unconditional: a test that reads a real ``DATABASE_URL`` from the developer's shell
    would pass locally and fail in CI, or worse, pass in CI and fail locally.
    """
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    reset_settings()
    yield
    reset_settings()


def _storage_roots(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Disjoint absolute storage roots. Overlapping roots abort startup by design (ADR-0011)."""
    base = tmp_path_factory.mktemp("evidence")
    return {
        "evidence_root": base / "originals",
        "derivatives_root": base / "derivatives",
        "intake_root": base / "intake",
        "quarantine_root": base / "quarantine",
        "models_root": base / "models",
    }


@pytest.fixture
def storage_roots(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return _storage_roots(tmp_path_factory)


@pytest.fixture
def dev_settings(storage_roots: dict[str, Any]) -> Settings:
    """A valid **development** configuration using the canary secrets.

    The database and Redis URLs embed canary passwords so the leak test can prove that connection
    strings never reach a log line or an API response.
    """
    return Settings(
        tlx_env=Environment.DEVELOPMENT,
        secret_key=CANARY_SECRET,
        signed_url_key=CANARY_SECRET,
        jwt_private_key=CANARY_KEY_ID,
        jwt_public_key=CANARY_KEY_ID,
        encryption_key=CANARY_SECRET,
        database_url=f"postgresql+psycopg://tlx_app:{CANARY_DB_PASSWORD}@localhost:5432/truthlens",
        redis_url=f"redis://:{CANARY_REDIS_PASSWORD}@localhost:6379/0",
        **storage_roots,
    )


@pytest.fixture
def prod_settings(storage_roots: dict[str, Any]) -> dict[str, Any]:
    """Keyword arguments for a valid **production** configuration.

    Returned as a dict so each test can remove or corrupt exactly one field and assert the specific
    rule that fires. Values are high-entropy and non-repeating: ``config.py`` deliberately rejects a
    weak secret such as ``"a" * 48`` as a placeholder, so fixtures must not use one.
    """
    return {
        "tlx_env": Environment.PRODUCTION,
        "log_format": "json",
        "preflight_required": True,
        "secret_key": "9c4e17ab3d8f0625ea71b9c4d0f83e62a5b71c9d4e0f83a6b1c5d9e2f7a30864",
        "signed_url_key": "41f8b3d0c7e29a6510d4b8f3e7a26c9d05b1e4f8a3c7d26095b4e1f8a7c3d062",
        # Shaped like a PEM only so the `-----BEGIN` length exemption in config.py is exercised.
        # The body is deliberately NOT base64: these are self-describing test fixtures, not keys,
        # and a realistic-looking private key in a public repository would (rightly) trip secret
        # scanning and mislead anyone reading the source.
        "jwt_private_key": (
            "-----BEGIN PRIVATE KEY-----\nTEST-FIXTURE-INVALID-BODY-NOT-A-REAL-KEY\n"
            "-----END PRIVATE KEY-----"
        ),
        "jwt_public_key": (
            "-----BEGIN PUBLIC KEY-----\nTEST-FIXTURE-INVALID-BODY-NOT-A-REAL-KEY\n"
            "-----END PUBLIC KEY-----"
        ),
        "database_url": "postgresql+psycopg://tlx_app:prodpass@postgres:5432/truthlens",
        "redis_url": "redis://:prodpass@redis:6379/0",
        **storage_roots,
    }


def _registry_with(statuses: dict[CheckName, CheckStatus]) -> ReadinessRegistry:
    """Build a registry whose checks return the given statuses deterministically.

    ``database`` and ``redis`` are registered **required**; anything else is optional, matching
    ``build_default_registry``.
    """
    registry = ReadinessRegistry()
    for name, status_value in statuses.items():

        async def _check(name: str = name, status_value: CheckStatus = status_value) -> CheckResult:
            return CheckResult(
                name=name,  # type: ignore[arg-type]
                status=status_value,
                detail=f"test stub: {status_value}",
            )

        registry.register(name, _check, required=name in {"database", "redis"})
    return registry


@pytest.fixture
def ready_registry() -> ReadinessRegistry:
    """All required dependencies healthy."""
    return _registry_with({"database": "ok", "redis": "ok"})


@pytest.fixture
def degraded_registry() -> ReadinessRegistry:
    """Redis down — readiness must fail, liveness must not."""
    return _registry_with({"database": "ok", "redis": "unavailable"})


@pytest.fixture
def unconfigured_registry() -> ReadinessRegistry:
    """A required dependency that is merely ``not_configured`` must NOT count as ready.

    This is the fail-closed rule in ``ReadinessRegistry``: an unconfigured dependency is a
    misconfiguration, not a pass.
    """
    return _registry_with({"database": "not_configured", "redis": "not_configured"})


def _registry_dependency() -> Any:
    return system.get_readiness_registry


def _settings_dependency() -> Any:
    return system.get_current_settings


@pytest.fixture
def app(dev_settings: Settings, ready_registry: ReadinessRegistry) -> Iterator[FastAPI]:
    """An application with hermetic settings and a deterministic, healthy readiness registry."""

    application = create_app(dev_settings)
    application.dependency_overrides[_settings_dependency()] = lambda: dev_settings
    application.dependency_overrides[_registry_dependency()] = lambda: ready_registry
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    """A test client that does NOT re-raise server exceptions.

    ``raise_server_exceptions=False`` is required to exercise the unhandled-exception handler: with
    the default, the handler never runs and the test proves nothing.
    """
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
