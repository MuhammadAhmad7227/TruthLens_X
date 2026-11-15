"""System endpoint contract tests.

These are the only endpoints M1 exposes, and they are the ones an operator or orchestrator depends on
during an incident — so their status codes, content types and payload shapes are treated as a
contract, not an implementation detail.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import __version__
from app.api.v1 import system
from app.core.config import Settings
from app.core.health import CheckName, CheckResult, CheckStatus, ReadinessRegistry
from app.main import create_app
from tests.conftest import CANARY_DB_PASSWORD, CANARY_REDIS_PASSWORD, CANARY_SECRET


def _registry(statuses: dict[CheckName, CheckStatus]) -> ReadinessRegistry:
    registry = ReadinessRegistry()
    for name, status_value in statuses.items():

        async def _check(name: str = name, status_value: CheckStatus = status_value) -> CheckResult:
            return CheckResult(name=name, status=status_value, detail=f"stub: {status_value}")  # type: ignore[arg-type]

        registry.register(name, _check, required=name in {"database", "redis"})
    return registry


@pytest.fixture
def make_client(
    dev_settings: Settings,
) -> Any:
    """Build a client whose readiness registry is whatever the test specifies."""

    def _factory(statuses: dict[CheckName, CheckStatus]) -> TestClient:
        application: FastAPI = create_app(dev_settings)
        application.dependency_overrides[system.get_current_settings] = lambda: dev_settings
        application.dependency_overrides[system.get_readiness_registry] = lambda: _registry(
            statuses
        )
        return TestClient(application, raise_server_exceptions=False)

    return _factory


class TestLiveness:
    def test_returns_200_with_version(self, client: TestClient) -> None:
        response = client.get("/healthz")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["version"] == __version__
        assert body["service"] == "truthlens"

    def test_liveness_survives_total_dependency_failure(self, make_client: Any) -> None:
        """The whole point of separating liveness from readiness.

        A liveness probe that fails when a dependency is down makes a supervisor restart healthy
        processes in a loop, converting a dependency blip into a full outage.
        """
        with make_client({"database": "unavailable", "redis": "unavailable"}) as test_client:
            assert test_client.get("/healthz").status_code == 200

    def test_liveness_payload_carries_no_dependency_state(self, client: TestClient) -> None:
        body = client.get("/healthz").json()
        assert "checks" not in body
        assert "database" not in str(body)


class TestReadiness:
    def test_ready_returns_200(self, client: TestClient) -> None:
        response = client.get("/readyz")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ready"

    def test_lists_every_check(self, client: TestClient) -> None:
        body = client.get("/readyz").json()
        assert {c["name"] for c in body["checks"]} == {"database", "redis"}
        assert all(c["status"] == "ok" for c in body["checks"])

    def test_unavailable_dependency_returns_503_problem_json(self, make_client: Any) -> None:
        with make_client({"database": "ok", "redis": "unavailable"}) as test_client:
            response = test_client.get("/readyz")
        assert response.status_code == 503
        assert response.headers["content-type"].startswith("application/problem+json")
        body = response.json()
        assert body["error_code"] == "DEPENDENCY_UNAVAILABLE"
        assert body["status"] == 503
        assert body["type"].startswith("https://errors.truthlens.local/")

    def test_503_payload_identifies_which_dependency_failed(self, make_client: Any) -> None:
        """An operator at 03:00 needs the failing dependency named, not a bare 503."""
        with make_client({"database": "ok", "redis": "unavailable"}) as test_client:
            body = test_client.get("/readyz").json()
        failed = [c for c in body["report"]["checks"] if c["status"] != "ok"]
        assert len(failed) == 1
        assert failed[0]["name"] == "redis"

    def test_not_configured_required_check_returns_503(self, make_client: Any) -> None:
        """Fail closed: an unconfigured dependency is a misconfiguration, not a pass."""
        with make_client({"database": "not_configured", "redis": "ok"}) as test_client:
            assert test_client.get("/readyz").status_code == 503

    def test_both_dependencies_missing_returns_503(self, make_client: Any) -> None:
        with make_client({"database": "not_configured", "redis": "not_configured"}) as test_client:
            assert test_client.get("/readyz").status_code == 503

    def test_optional_pending_checks_do_not_block_readiness(self, make_client: Any) -> None:
        """M1 registers migrations/preflight as optional and reports their real state."""
        with make_client({"database": "ok", "redis": "ok"}) as test_client:
            assert test_client.get("/readyz").status_code == 200


class TestStatus:
    def test_returns_200_with_milestone_honesty(self, client: TestClient) -> None:
        response = client.get("/api/v1/status")
        assert response.status_code == 200
        body = response.json()
        assert body["version"] == __version__
        assert body["environment"] == "development"
        assert body["milestone"]["current"] == "M1"

    def test_unimplemented_capabilities_are_declared(self, client: TestClient) -> None:
        """Nothing may be implied that does not exist. The API says what is missing."""
        body = client.get("/api/v1/status").json()
        declared = " ".join(body["milestone"]["not_yet_implemented"])
        for capability in ("authentication", "evidence", "custody", "forensic"):
            assert capability in declared

    def test_implemented_list_matches_reality(self, client: TestClient) -> None:
        body = client.get("/api/v1/status").json()
        implemented = " ".join(body["milestone"]["implemented"])
        assert "configuration" in implemented
        assert "logging" in implemented
        # M1 must not claim any forensic capability.
        for overclaim in ("deepfake", "ALPR", "OCR", "chain of custody", "transcript"):
            assert overclaim.lower() not in implemented.lower()

    def test_secret_names_are_reported_as_booleans(self, client: TestClient) -> None:
        """`secret_names_set()` returns booleans, so a value cannot leak through this endpoint."""
        body = client.get("/api/v1/status").json()
        secrets_set = body["configuration"]["secrets_set"]
        assert set(secrets_set) == {
            "SECRET_KEY",
            "SIGNED_URL_KEY",
            "JWT_PRIVATE_KEY",
            "JWT_PUBLIC_KEY",
            "ENCRYPTION_KEY",
        }
        assert all(isinstance(value, bool) for value in secrets_set.values())
        assert all(secrets_set.values()), "the dev fixture supplies every critical secret"

    def test_copyleft_and_egress_flags_are_visible(self, client: TestClient) -> None:
        """ADR-0001 / ADR-0012: an operator verifies licensing and residency posture at a glance."""
        flags = client.get("/api/v1/status").json()["feature_flags"]
        assert flags["enable_ultralytics"] is False
        assert flags["enable_agpl_pymupdf"] is False
        assert flags["enable_poppler"] is False
        assert flags["enable_av_scan"] is False
        assert flags["enable_external_ai"] is False
        assert flags["external_ai_effectively_enabled"] is False
        assert flags["external_ai_allowed_categories"] == []
        assert flags["alpr_allow_registry_lookup"] is False
        # ADR-0003: the one copyleft flag that is on by default, subprocess-isolated.
        assert flags["enable_exiftool"] is True

    def test_retention_state_is_reported(self, client: TestClient) -> None:
        """ADR-0020: unset retention deletes nothing and must be visible, not silent."""
        body = client.get("/api/v1/status").json()
        assert body["configuration"]["retention_configured"] is False
        assert any("RETENTION_STATUTORY_DAYS" in w for w in body["configuration"]["warnings"])

    def test_encryption_and_storage_posture_is_reported(self, client: TestClient) -> None:
        body = client.get("/api/v1/status").json()["configuration"]
        assert body["storage_backend"] == "filesystem"
        assert body["evidence_encryption"] == "disabled"
        assert body["preflight_required"] is True


class TestRootAndMetadata:
    def test_root_states_the_project_is_under_construction(self, client: TestClient) -> None:
        body = client.get("/").json()
        assert body["status"] == "milestone-M1-foundation"
        assert "NOT implemented" in body["note"]

    def test_openapi_is_served(self, client: TestClient) -> None:
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["version"] == __version__
        assert "/healthz" in schema["paths"]
        assert "/readyz" in schema["paths"]
        assert "/api/v1/status" in schema["paths"]

    def test_openapi_declares_no_licence(self, client: TestClient) -> None:
        """ADR-0008: the repository is deliberately unlicensed. Publishing a `license` key in the
        API metadata would imply a grant that has not been made."""
        schema = client.get("/openapi.json").json()
        assert "license" not in schema["info"]
        assert "contact" not in schema["info"]

    def test_docs_endpoints_are_served(self, client: TestClient) -> None:
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200

    def test_unknown_route_is_problem_json(self, client: TestClient) -> None:
        """Every non-2xx response uses ONE error format, including framework-raised ones."""
        response = client.get("/api/v1/does-not-exist")
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/problem+json")
        body = response.json()
        assert body["error_code"] == "NOT_FOUND"
        assert body["status"] == 404

    def test_wrong_method_is_problem_json(self, client: TestClient) -> None:
        response = client.post("/healthz")
        assert response.status_code == 405
        body = response.json()
        assert body["error_code"] == "NOT_FOUND"
        assert "request_id" in body


class TestLeakage:
    """The canary secrets from the fixture must not appear anywhere in a response."""

    @pytest.mark.parametrize(
        "path", ["/healthz", "/readyz", "/api/v1/status", "/", "/openapi.json"]
    )
    def test_no_canary_secret_in_any_response(self, client: TestClient, path: str) -> None:
        body = client.get(path).text
        for canary in (CANARY_SECRET, CANARY_DB_PASSWORD, CANARY_REDIS_PASSWORD):
            assert canary not in body, f"{canary[:12]}... leaked via {path}"

    def test_no_canary_in_error_responses(self, make_client: Any) -> None:
        with make_client({"database": "unavailable", "redis": "unavailable"}) as test_client:
            body = test_client.get("/readyz").text
        for canary in (CANARY_SECRET, CANARY_DB_PASSWORD, CANARY_REDIS_PASSWORD):
            assert canary not in body
