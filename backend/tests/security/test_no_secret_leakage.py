"""Security assertions that cross module boundaries.

These tests are marked ``security`` and each one names the ADR or threat it enforces. They exist
because the individual unit tests can each pass while the *combination* leaks: configuration is safe,
logging is safe, and the error handler is safe, yet an exception message carrying a connection string
still reaches a response body. Only an end-to-end assertion catches that.
"""

from __future__ import annotations

import io
import json
import socket as _socket
from typing import Any

import pytest
import structlog
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import system
from app.core.config import ConfigurationError, Environment, Settings
from app.core.errors import (
    ForbiddenCaseAccessError,
    IntegrityError,
    InternalError,
    NotFoundError,
    ProblemDetail,
    ValidationError,
)
from app.core.exception_handlers import _field_error_from
from app.core.health import (
    CheckResult,
    ReadinessRegistry,
    _redis_ping,
    check_database,
    check_redis,
)
from app.core.logging import REDACTED, configure_logging
from app.main import create_app
from tests.conftest import (
    CANARY_DB_PASSWORD,
    CANARY_KEY_ID,
    CANARY_REDIS_PASSWORD,
    CANARY_SECRET,
)

ALL_CANARIES = (CANARY_SECRET, CANARY_KEY_ID, CANARY_DB_PASSWORD, CANARY_REDIS_PASSWORD)


class TestResponseLeakage:
    @pytest.mark.parametrize(
        "path", ["/healthz", "/readyz", "/api/v1/status", "/", "/openapi.json"]
    )
    def test_no_canary_in_any_successful_response(self, client: TestClient, path: str) -> None:
        body = client.get(path).text
        for canary in ALL_CANARIES:
            assert canary not in body, f"leaked via {path}"

    def test_no_canary_in_a_503_readiness_response(self, dev_settings: Settings) -> None:
        """The not-ready path serialises check details, which may embed a connection string."""

        async def _db_down() -> CheckResult:
            # A realistic driver error: psycopg echoes the DSN it failed to connect to.
            return CheckResult(
                name="database",
                status="unavailable",
                detail=(
                    "OperationalError: connection failed: could not connect to server "
                    f"postgresql+psycopg://tlx_app:{CANARY_DB_PASSWORD}@localhost:5432/truthlens"
                ),
            )

        async def _redis_down() -> CheckResult:
            # Realistic: a driver echoes the DSN it failed on, never the bare password as prose.
            return CheckResult(
                name="redis",
                status="unavailable",
                detail=(
                    "ConnectionError: Error 111 connecting to "
                    f"redis://:{CANARY_REDIS_PASSWORD}@redis:6379/0 - Connection refused"
                ),
            )

        registry = ReadinessRegistry()
        registry.register("database", _db_down)
        registry.register("redis", _redis_down)
        application = create_app(dev_settings)
        application.dependency_overrides[system.get_current_settings] = lambda: dev_settings
        application.dependency_overrides[system.get_readiness_registry] = lambda: registry
        with TestClient(application, raise_server_exceptions=False) as test_client:
            response = test_client.get("/readyz")
        assert response.status_code == 503
        body = response.text
        assert CANARY_DB_PASSWORD not in body
        assert CANARY_REDIS_PASSWORD not in body
        assert REDACTED in body, "the credential must be replaced, not merely dropped"


class TestCheckDetailsAreCredentialFree:
    """Redaction is a net, not a design.

    A value-pattern redactor cannot recognise an arbitrary bare password in free prose — no
    redactor can. The real invariant is that the checks we write never put a credential into
    `detail` in the first place. These tests pin that, so the redactor stays defence-in-depth
    rather than being the only thing standing between a DSN and an HTTP response.
    """

    async def test_redis_auth_failure_does_not_name_the_password(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        settings = Settings(
            tlx_env=Environment.TEST,
            redis_url="redis://:sup3r-s3cret-pass@127.0.0.1:1/0",
            **storage_roots,
        )
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        # Nothing is listening on port 1, so this fails for real.
        result = await check_redis()
        assert result.status == "unavailable"
        assert "sup3r-s3cret-pass" not in (result.detail or "")

        rejected = _redis_ping("127.0.0.1", 1, "sup3r-s3cret-pass", 0, False)
        assert "sup3r-s3cret-pass" not in (rejected.detail or "")

    async def test_database_detail_carries_no_plaintext_password(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        with _socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        settings = Settings(
            tlx_env=Environment.TEST,
            database_url=f"postgresql+psycopg://tlx_app:db-s3cret@127.0.0.1:{free_port}/truthlens",
            db_pool_timeout_seconds=1,
            **storage_roots,
        )
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        result = await check_database()
        assert result.status == "unavailable"
        # Either the driver omitted the DSN, or the API-boundary redactor caught it. Either way the
        # plaintext password must not survive into `detail`.
        assert "db-s3cret" not in (result.detail or "")


class TestLogLeakage:
    """Assert on bytes that would actually be written to stdout."""

    def _capture(self, settings: Settings, fn: Any) -> str:
        stream = io.StringIO()
        configure_logging(level="INFO", json_format=True, stream=stream)
        fn()
        return stream.getvalue()

    def test_settings_dump_does_not_reveal_secrets(self, dev_settings: Settings) -> None:
        """The most natural logging mistake: dumping the settings object at startup."""
        output = self._capture(
            dev_settings,
            lambda: structlog.get_logger("t").info("config", settings=dev_settings.model_dump()),
        )
        for canary in ALL_CANARIES:
            assert canary not in output

    def test_secret_names_set_is_safe_to_log(self, dev_settings: Settings) -> None:
        """The names are useful and must survive; the values must not exist to leak.

        Note the field is named `config_gaps`, not `secrets`: the redactor replaces any field whose
        NAME matches wholesale, so `secrets=...` would become `[REDACTED]` — safe, but useless to an
        operator. ``main.py`` logs the gaps for exactly this reason, and the next test pins that
        conservative behaviour so nobody "fixes" the field name and reintroduces a leak path.
        """
        gaps = [n for n, ok in dev_settings.secret_names_set().items() if not ok]
        output = self._capture(
            dev_settings,
            lambda: structlog.get_logger("t").info("config", config_gaps=gaps),
        )
        for canary in ALL_CANARIES:
            assert canary not in output
        assert gaps == [], "the dev fixture supplies every critical secret"

    def test_a_field_named_like_a_secret_is_redacted_wholesale(
        self, dev_settings: Settings
    ) -> None:
        """Conservative by design: key-name redaction wins over value inspection.

        `secret_names_set()` returns only booleans, so redacting it destroys no information — but a
        future caller might pass real values under the same name. The key rule must not depend on
        what the value happens to look like.
        """
        output = self._capture(
            dev_settings,
            lambda: structlog.get_logger("t").info(
                "config", secrets_set=dev_settings.secret_names_set()
            ),
        )
        assert REDACTED in output
        assert "SECRET_KEY" not in output

    def test_error_context_with_a_secret_is_redacted(self, dev_settings: Settings) -> None:
        error = IntegrityError(
            "mismatch",
            context={"database_url": dev_settings.database_url, "path": "/srv/truthlens/evidence"},
        )
        output = self._capture(
            dev_settings,
            lambda: structlog.get_logger("t").error("integrity", context=error.context),
        )
        assert CANARY_DB_PASSWORD not in output
        assert "/srv/truthlens/evidence" in output, "non-secret context must survive for diagnosis"

    def test_exception_carried_by_an_error_handler_is_redacted(
        self, dev_settings: Settings
    ) -> None:
        """format_exc_info runs before redaction, so a traceback embedding a DSN is cleaned."""

        def _raise_and_log() -> None:
            log = structlog.get_logger("t")
            try:
                msg = f"cannot reach redis://:{CANARY_REDIS_PASSWORD}@redis:6379/0"
                raise InternalError(msg)
            except InternalError as exc:
                log.error("failed", exc_info=exc)

        output = self._capture(dev_settings, _raise_and_log)
        assert CANARY_REDIS_PASSWORD not in output

    def test_production_startup_log_is_clean(self, prod_settings: dict[str, Any]) -> None:
        """Simulate the real lifespan log line and assert nothing sensitive escapes."""
        settings = Settings(**prod_settings)
        stream = io.StringIO()
        configure_logging(level="INFO", json_format=True, stream=stream)
        structlog.get_logger("app").info(
            "application.starting",
            env=str(settings.tlx_env.value),
            secrets_set=settings.secret_names_set(),
            database_url=settings.database_url,
            redis_url=settings.redis_url,
            jwt_private_key=settings.jwt_private_key,
        )
        output = stream.getvalue()
        # Typed as list[str] deliberately: these settings fields are `str | None`, and a `None` in
        # the list would make the assertion below ill-typed AND vacuously true. Asserting the
        # fixture really supplies each secret is what makes the leak check meaningful.
        secrets: list[str] = ["prodpass"]
        for candidate in (settings.secret_key, settings.signed_url_key):
            assert candidate, "the production fixture must supply every critical secret"
            secrets.append(candidate)
        for secret in secrets:
            assert secret not in output
        record = json.loads(output.strip().splitlines()[-1])
        assert record["database_url"] == REDACTED
        assert record["redis_url"] == REDACTED
        assert record["jwt_private_key"] == REDACTED
        # `secrets_set` matches the sensitive-KEY pattern, so the redactor replaces it wholesale.
        # That is the conservative behaviour; main.py therefore logs `config_gaps` instead.
        assert record["secrets_set"] == REDACTED

    def test_evidence_bytes_are_never_rendered(self, dev_settings: Settings) -> None:
        """The only large byte values this platform handles are evidence content."""
        payload = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 40
        output = self._capture(
            dev_settings,
            lambda: structlog.get_logger("t").info("upload", content=payload),
        )
        assert "PNG" not in output
        assert f"<{len(payload)} bytes omitted>" in output

    def test_decoded_binary_content_is_also_omitted(self, dev_settings: Settings) -> None:
        """Defence in depth behind the type check.

        ``bytes.decode()`` anywhere in application code turns evidence content into an ordinary
        ``str``. Redacting by type alone would then pass it straight through, so the SHAPE of the
        value is checked too.
        """
        decoded = (b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4).decode("latin-1")
        output = self._capture(
            dev_settings,
            lambda: structlog.get_logger("t").info("upload", content=decoded),
        )
        assert "PNG" not in output
        assert "binary data omitted" in output

    def test_a_nul_byte_marks_a_string_as_binary(self, dev_settings: Settings) -> None:
        output = self._capture(
            dev_settings,
            lambda: structlog.get_logger("t").info("x", content="head\x00tail-padding-to-exceed"),
        )
        assert "\x00" not in output
        assert "binary data omitted" in output


class TestErrorModelLeakage:
    def test_validation_error_does_not_echo_submitted_values(self, app: FastAPI) -> None:
        """A validation error is exactly where a caller's input would otherwise be reflected back."""

        raw = {
            "loc": ("body", "password"),
            "msg": "String should have at least 8 characters",
            "type": "string_too_short",
        }
        field_error = _field_error_from(raw)
        assert field_error.field == "body.password"
        assert "at least 8 characters" in field_error.message
        # The submitted value is not part of the message pydantic produces, and we add nothing.
        assert "hunter2" not in field_error.message

    def test_problem_detail_has_no_channel_for_internals(self) -> None:
        """Leaking context would require changing the model, not a careless call."""

        assert "context" not in ProblemDetail.model_fields
        assert "audit_reason" not in ProblemDetail.model_fields
        assert "exc_info" not in ProblemDetail.model_fields

    def test_case_denial_does_not_reveal_that_the_case_exists(self) -> None:
        """ADR-0004 conflict #4: 404/NOT_FOUND to the client, FORBIDDEN_CASE_ACCESS to the audit log."""

        denied = ForbiddenCaseAccessError("no membership").to_problem().model_dump(mode="json")
        absent = NotFoundError("not found").to_problem().model_dump(mode="json")
        assert denied["status"] == absent["status"] == 404
        assert denied["error_code"] == absent["error_code"] == "NOT_FOUND"
        assert "FORBIDDEN_CASE_ACCESS" not in json.dumps(denied)
        assert ForbiddenCaseAccessError("x").audit_reason == "FORBIDDEN_CASE_ACCESS"

    def test_validation_error_is_not_reported_as_a_server_error(self) -> None:
        """A client mistake must not page an on-call engineer."""
        assert ValidationError("bad").log_with_traceback is False
        assert ValidationError("bad").status == 400


class TestAIPolicyEnforcement:
    """ADR-0007 / ADR-0021: the default posture must be provably closed."""

    def test_default_configuration_transmits_nothing(self) -> None:
        settings = Settings(tlx_env=Environment.TEST)
        assert settings.enable_external_ai is False
        assert settings.llm_provider == "local"
        assert settings.external_ai_effectively_enabled is False
        assert settings.external_ai_allowed_categories == ()
        assert settings.enable_external_enrichment is False
        assert settings.allow_model_download is False

    def test_api_key_is_never_reported_by_status(self, client: TestClient) -> None:
        """`/api/v1/status` reports flag *states*, never the values behind them.

        Both the env-var name and the field name must be absent: a status endpoint that echoed
        ``llm_external_api_key`` would be advertising whether a key is configured, and one that
        echoed the value would be a disclosure. The disjunction this test replaced passed if either
        half held, so it proved nothing.
        """
        body = client.get("/api/v1/status").text
        assert "LLM_EXTERNAL_API_KEY" not in body
        assert "llm_external_api_key" not in body
        assert "sk-" not in body
        # The flag itself IS reported, as a boolean — that is the useful, safe half.
        assert '"enable_external_ai":false' in body.replace(" ", "")

    def test_external_ai_key_is_not_echoed_in_configuration_errors(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            Settings(
                tlx_env=Environment.TEST,
                llm_provider="external",
                llm_external_api_key="sk-live-abcdefghijklmnop",
            )
        assert "abcdefghijklmnop" not in str(excinfo.value)

    def test_egress_confirmation_cannot_be_disabled_in_production(
        self, prod_settings: dict[str, Any]
    ) -> None:
        """ADR-0021 requirement 9 — not negotiable in a production-like environment."""

        prod_settings["llm_egress_confirmation_required"] = False
        with pytest.raises(ConfigurationError, match="not negotiable"):
            Settings(**prod_settings)

    def test_alpr_registry_lookup_is_refused_in_every_environment(self) -> None:
        """ADR-0013: hard-disabled, including development, where a permissive default is tempting."""

        for env in Environment:
            with pytest.raises(ConfigurationError, match="ADR-0013"):
                Settings(tlx_env=env, alpr_allow_registry_lookup=True)
