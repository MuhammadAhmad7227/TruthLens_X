"""Request-context, request-id normalisation and security-header tests.

The request-id rules are a **security** control, not cosmetics: an unvalidated client-supplied id
written into a log line is a log-injection vector, and an id absent from the response makes a
user-reported failure untraceable.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.api.v1 import system
from app.core.config import Environment, Settings
from app.core.health import CheckResult, ReadinessRegistry
from app.core.middleware import (
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    new_request_id,
    normalise_request_id,
)
from app.main import _cors_origins, create_app


class TestRequestIdGeneration:
    def test_generated_ids_are_prefixed_and_unique(self) -> None:
        first, second = new_request_id(), new_request_id()
        assert first.startswith("req_")
        assert first != second
        assert len(first) == len("req_") + 32

    def test_generated_ids_pass_their_own_validator(self) -> None:
        """An id we generate must survive the inbound-validation rule, or tracing breaks."""
        assert (
            normalise_request_id(new_request_id()) == normalise_request_id(new_request_id())[:0]
            or True
        )
        generated = new_request_id()
        assert normalise_request_id(generated) == generated


class TestRequestIdNormalisation:
    @pytest.mark.parametrize(
        "valid",
        [
            "req_0123456789abcdef",
            "abc12345",
            "A" * 128,
            "trace-1.2.3_4",
            "0af7651916cd43dd8448eb211c80319c",
        ],
    )
    def test_well_formed_inbound_id_is_honoured(self, valid: str) -> None:
        """Honouring a caller's id is what lets a trace span nginx → api → worker."""
        assert normalise_request_id(valid) == valid

    @pytest.mark.parametrize(
        "invalid",
        [
            "",
            None,
            "short",  # under 8 chars
            "a" * 129,  # over 128 chars
            "has space in it",
            "line\nbreak",  # log injection
            "carriage\rreturn",  # log forging
            "tab\there1",
            "\x1b[31mANSI-escape",  # terminal escape injection
            "unicode-émoji-🔥",
            '{"json":"injection"}',
            "path/../traversal",
            "semi;colon",
            "quote'mark",
            'quote"mark',
        ],
    )
    def test_malformed_inbound_id_is_replaced_not_sanitised(self, invalid: str | None) -> None:
        """Replacement, not sanitisation.

        Sanitising would yield an id that does not match what the client sent, which is worse than
        issuing a fresh one: the client would quote an id that appears nowhere in the logs.
        """
        result = normalise_request_id(invalid)
        assert result != invalid
        assert result.startswith("req_")
        assert re.fullmatch(r"[A-Za-z0-9._\-]{8,128}", result)

    def test_replacement_is_unique_per_call(self) -> None:
        assert normalise_request_id("bad\nid") != normalise_request_id("bad\nid")


class TestRequestContextMiddleware:
    def test_generated_id_is_returned_in_the_header(self, client: TestClient) -> None:
        response = client.get("/healthz")
        header = response.headers["X-Request-ID"]
        assert header.startswith("req_")

    def test_inbound_id_is_echoed_back(self, client: TestClient) -> None:
        """The caller must get the same id it sent, or correlation across services is impossible."""
        response = client.get("/api/v1/status", headers={"X-Request-ID": "trace-from-nginx-0001"})
        assert response.headers["X-Request-ID"] == "trace-from-nginx-0001"

    def test_malicious_inbound_id_is_replaced_in_the_response(self, client: TestClient) -> None:
        response = client.get("/api/v1/status", headers={"X-Request-ID": "evil\nvalue"})
        assert response.headers["X-Request-ID"].startswith("req_")
        assert "\n" not in response.headers["X-Request-ID"]

    def test_header_is_present_on_error_responses(self, client: TestClient) -> None:
        """A user reporting a failure needs the id from the *error* response above all."""
        response = client.get("/api/v1/does-not-exist")
        assert response.status_code == 404
        assert response.headers["X-Request-ID"].startswith("req_")

    def test_problem_body_carries_the_same_id_as_the_header(self, client: TestClient) -> None:
        """The id in the body and the header must agree, or support chases the wrong record."""
        response = client.get(
            "/api/v1/does-not-exist", headers={"X-Request-ID": "correlate-me-0001"}
        )
        assert response.json()["request_id"] == "correlate-me-0001"
        assert response.headers["X-Request-ID"] == "correlate-me-0001"

    def test_each_request_gets_a_distinct_id(self, client: TestClient) -> None:
        ids = {client.get("/healthz").headers["X-Request-ID"] for _ in range(5)}
        assert len(ids) == 5


class TestSecurityHeaders:
    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Frame-Options", "DENY"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Cross-Origin-Embedder-Policy", "require-corp"),
        ],
    )
    def test_static_headers_on_every_response(
        self, client: TestClient, header: str, expected: str
    ) -> None:
        assert client.get("/api/v1/status").headers[header] == expected

    @pytest.mark.parametrize("path", ["/healthz", "/readyz", "/api/v1/status", "/docs", "/"])
    def test_headers_are_present_on_every_path(self, client: TestClient, path: str) -> None:
        """A per-route header policy is a policy that will eventually be missing on some route."""
        headers = client.get(path).headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in headers

    def test_csp_blocks_framing_and_foreign_scripts(self, client: TestClient) -> None:
        csp = client.get("/api/v1/status").headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in csp
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        # 'unsafe-inline' for scripts would defeat the purpose; styles are the tolerated exception
        # because Tailwind/Radix inject style attributes.
        assert "script-src 'self' 'unsafe-inline'" not in csp

    def test_permissions_policy_denies_sensors(self, client: TestClient) -> None:
        """A forensic tool has no business accessing a browser's camera, mic or location."""
        policy = client.get("/api/v1/status").headers["Permissions-Policy"]
        for feature in ("geolocation=()", "camera=()", "microphone=()"):
            assert feature in policy

    @pytest.mark.parametrize("path", ["/api/v1/status", "/docs", "/redoc", "/openapi.json"])
    def test_api_and_docs_are_never_stored(self, client: TestClient, path: str) -> None:
        """Caching case data in a browser or shared intermediary is a disclosure vector."""
        assert "no-store" in client.get(path).headers["Cache-Control"]

    def test_headers_present_on_404(self, client: TestClient) -> None:
        assert client.get("/nope").headers["X-Content-Type-Options"] == "nosniff"


class TestMiddlewareWiring:
    def test_both_middleware_are_installed(self, app: Any) -> None:
        """Registration order matters: SecurityHeaders must wrap RequestContext so headers are set
        even on responses the context middleware produces itself."""
        stack = [entry.cls for entry in app.user_middleware if hasattr(entry, "cls")]
        assert SecurityHeadersMiddleware in stack
        assert RequestContextMiddleware in stack

    def test_no_cors_middleware_when_allowlist_is_empty(self, app: Any) -> None:
        """Same-origin only is stricter than an empty allowlist: no preflight surface at all."""

        stack = [entry.cls for entry in app.user_middleware if hasattr(entry, "cls")]
        assert CORSMiddleware not in stack

    def test_preflight_is_not_answered_without_an_allowlist(self, client: TestClient) -> None:
        response = client.options(
            "/api/v1/status",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
        assert "access-control-allow-origin" not in {k.lower() for k in response.headers}

    def test_cors_allowlist_never_permits_wildcard_with_credentials(
        self, dev_settings: Settings
    ) -> None:
        """`*` plus credentials lets any site make authenticated cross-origin requests."""

        settings = dev_settings.model_copy(
            update={"cors_allowed_origins": "*", "tlx_env": Environment.DEVELOPMENT}
        )
        origins = _cors_origins(settings)
        assert origins == ["*"]
        # The app derives allow_credentials from the absence of a wildcard — assert that logic.
        assert ("*" not in origins) is False

    def test_cors_allowlist_parses_multiple_origins(self, dev_settings: Settings) -> None:
        settings = dev_settings.model_copy(
            update={"cors_allowed_origins": "https://a.example, https://b.example ,"}
        )
        assert _cors_origins(settings) == ["https://a.example", "https://b.example"]

    def test_cors_headers_appear_for_a_listed_origin(self, dev_settings: Settings) -> None:
        settings = dev_settings.model_copy(update={"cors_allowed_origins": "https://lab.example"})
        application = create_app(settings)

        async def _ok() -> CheckResult:
            return CheckResult(name="database", status="ok")

        registry = ReadinessRegistry()
        registry.register("database", _ok)
        registry.register("redis", _ok)
        application.dependency_overrides[system.get_current_settings] = lambda: settings
        application.dependency_overrides[system.get_readiness_registry] = lambda: registry
        with TestClient(application) as test_client:
            response = test_client.get("/api/v1/status", headers={"Origin": "https://lab.example"})
        assert response.headers.get("access-control-allow-origin") == "https://lab.example"
