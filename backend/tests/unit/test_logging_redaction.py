"""Log redaction tests.

Logging is the most likely place for a secret or evidence content to escape, so these tests assert on
the **rendered output**, not only on the redaction helper in isolation. ``SECURITY_ARCHITECTURE.md``
§5.4 requires redaction to be unconditional — it is a processor applied to every event, not an opt-in
per call site.
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest
import structlog

from app.core.logging import (
    REDACTED,
    SHA256_PATTERN,
    configure_logging,
    is_configured,
    redact_processor,
    redact_value,
)

#: A real-shaped SHA-256 evidence digest. Must survive redaction — operators grep logs for it.
EVIDENCE_SHA256 = "9f2c1a4b7d8e0536fa19c2b4d7e08a3156f9c2d4b7e1a0386c5f9d2e7b4a10c8"


@pytest.fixture(autouse=True)
def _reset_structlog() -> Any:
    """Return structlog to its default configuration after each test."""
    yield
    structlog.reset_defaults()


class TestRedactValue:
    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "db_password",
            "SECRET_KEY",
            "api_key",
            "apiKey",
            "api-key",
            "access_token",
            "refresh_token",
            "private_key",
            "jwt_private_key",
            "credentials",
            "authorization",
            "cookie",
            "session_id",
            "totp_secret",
            "mfa_secret",
            "dek",
            "kek",
            "database_url",
            "redis_url",
            "dsn",
            "connection_string",
        ],
    )
    def test_sensitive_keys_are_redacted_wholesale(self, key: str) -> None:
        """A key-based rule is the reliable control: the value may not look like a secret at all."""
        event = redact_processor(None, "info", {key: "short", "safe": "ok"})
        assert event[key] == REDACTED
        assert event["safe"] == "ok"

    def test_sha256_evidence_hash_is_preserved(self) -> None:
        """An evidence digest is operationally essential and is not a secret."""
        assert SHA256_PATTERN.fullmatch(EVIDENCE_SHA256) is not None
        assert redact_value(EVIDENCE_SHA256) == EVIDENCE_SHA256

    def test_sha256_preserved_inside_a_sentence(self) -> None:
        text = f"verified integrity of {EVIDENCE_SHA256} against manifest"
        assert EVIDENCE_SHA256 in redact_value(text)

    def test_multiple_sha256_values_are_all_preserved(self) -> None:
        other = "1" * 63 + "a"
        text = f"{EVIDENCE_SHA256} superseded by {other}"
        result = redact_value(text)
        assert EVIDENCE_SHA256 in result
        assert other in result

    def test_long_hex_that_is_not_a_digest_is_redacted(self) -> None:
        """A 32-char hex token is a secret, not an evidence digest (which is exactly 64)."""
        result = redact_value("session=" + "ab12cd34ef56ab12cd34ef56ab12cd34")
        assert REDACTED in result

    def test_pem_private_key_is_redacted(self) -> None:
        pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIH\n-----END PRIVATE KEY-----"
        result = redact_value(pem)
        assert REDACTED in result
        assert "MC4CAQAwBQYDK2VwBCIEIH" not in result

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql://tlx_app:Sup3rS3cret@db.internal:5432/truthlens",
            "postgres://u:p@h/db",
            "redis://:r3d1spass@redis:6379/0",
            "rediss://:tlspass@redis:6380/0",
            "https://user:apitoken@api.example.com/v1",
            "amqp://guest:guestpass@broker:5672/",
        ],
    )
    def test_connection_string_credentials_are_redacted(self, url: str) -> None:
        result = redact_value(url)
        assert REDACTED in result, url
        for secret in ("Sup3rS3cret", "r3d1spass", "tlspass", "apitoken", "guestpass"):
            assert secret not in result

    def test_bearer_token_is_redacted(self) -> None:
        token = "Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"
        assert "eyJhbGciOiJFZERTQSJ9" not in redact_value(token)

    def test_provider_api_key_shape_is_redacted(self) -> None:
        result = redact_value("using sk-proj-AbCdEf1234567890XyZ for the request")
        assert "AbCdEf1234567890XyZ" not in result

    # These fixtures are deliberately *shape-valid but credential-invalid*: the redactor's rule
    # matches provider token shapes, so the test has to supply one to prove the rule fires. None of
    # these values has ever authenticated against anything.
    #   - The AWS value is AWS's own documentation example (`AKIA` + `IOSFODNN7EXAMPLE`, assembled
    #     below), not a real access key id. It is written split, like the others.
    #   - The GitHub and Slack values are assembled at runtime from parts, ON PURPOSE. A contiguous
    #     Slack-shaped literal in source trips GitHub push protection — it rejected this very
    #     commit — which would have left the redaction rule untested. Splitting the prefix from the
    #     body keeps the value handed to redact_value() shape-valid while guaranteeing that no
    #     credential-shaped literal exists anywhere in the repository. The same technique is why the
    #     rule in logging.py is written as `xox[baprs]-` rather than listing whole prefixes.
    @pytest.mark.parametrize(
        "token",
        [
            # Split for the same reason as the Slack value below: no contiguous provider-shaped
            # literal anywhere in the repository. The assembled value is still AWS's documentation
            # example, which is what the redaction rule has to catch.
            "AKIA" + "IOSFODNN7EXAMPLE",
            "ghp_" + "TestFixtureNotARealToken" * 2,
            "xox" + "b-1234567890-FixtureNotARealToken",
        ],
    )
    def test_cloud_and_scm_token_shapes_are_redacted(self, token: str) -> None:
        result = redact_value(f"found {token} in the environment")
        assert token not in result

    def test_bytes_are_never_rendered(self) -> None:
        """Evidence content must never reach a log line, even as a preview."""
        result = redact_value(b"\x89PNG\r\n\x1a\n" + b"\x00" * 4096)
        assert result == "<4104 bytes omitted>"

    def test_bytearray_is_never_rendered(self) -> None:
        assert redact_value(bytearray(b"evidence")) == "<8 bytes omitted>"

    def test_nested_structures_are_recursed(self) -> None:
        payload: dict[str, Any] = {
            "case": {"id": "case-1", "password": "leak"},
            "items": [{"token": "leak2"}, "plain"],
            "hash": EVIDENCE_SHA256,
        }
        result = redact_value(payload)
        assert result["case"]["password"] == REDACTED
        assert result["case"]["id"] == "case-1", "non-secret siblings must survive"
        assert result["items"][0]["token"] == REDACTED
        assert result["items"][1] == "plain"
        assert result["hash"] == EVIDENCE_SHA256

    def test_forbidden_keys_are_redacted_even_when_the_value_looks_benign(self) -> None:
        event = redact_processor(None, "info", {"file_content": "just some text"})
        assert event["file_content"] == REDACTED

    def test_non_secret_values_pass_through_unchanged(self) -> None:
        assert redact_value("GET /api/v1/cases") == "GET /api/v1/cases"
        assert redact_value(42) == 42
        assert redact_value(True) is True
        assert redact_value(None) is None
        assert redact_value(3.14) == 3.14

    def test_empty_string_is_not_rewritten(self) -> None:
        assert redact_value("") == ""


class TestRenderedOutput:
    """Assert on what would actually be written to stdout."""

    def _capture(self, event_kwargs: dict[str, Any], *, json_format: bool = True) -> str:
        stream = io.StringIO()
        configure_logging(level="INFO", json_format=json_format, stream=stream)
        structlog.get_logger("test").info("evidence.processed", **event_kwargs)
        return stream.getvalue()

    def test_secret_in_json_log_is_redacted(self) -> None:
        output = self._capture({"database_url": "postgresql://u:p@h/db", "sha256": EVIDENCE_SHA256})
        record = json.loads(output.strip().splitlines()[-1])
        assert record["database_url"] == REDACTED
        assert record["sha256"] == EVIDENCE_SHA256
        assert record["event"] == "evidence.processed"

    def test_json_output_is_machine_parseable(self) -> None:
        output = self._capture({"path": "/api/v1/cases"})
        record = json.loads(output.strip().splitlines()[-1])
        assert record["level"] == "info"
        assert "timestamp" in record

    def test_service_context_is_attached(self) -> None:
        output = self._capture({"path": "/api/v1/cases"})
        record = json.loads(output.strip().splitlines()[-1])
        assert record["service"] == "truthlens"
        assert record["env"] in {"development", "test", "unconfigured"}

    def test_secret_in_console_log_is_redacted(self) -> None:
        output = self._capture({"api_key": "sk-live-abcdefghijklmnop"}, json_format=False)
        assert "abcdefghijklmnop" not in output
        assert REDACTED in output

    def test_exception_text_is_redacted(self) -> None:
        """format_exc_info runs BEFORE redaction, so a traceback carrying a secret is cleaned.

        This ordering is the single most important property of the logging chain: exception messages
        routinely embed connection strings, and a redactor that ran earlier would miss them.
        """
        stream = io.StringIO()
        configure_logging(level="INFO", json_format=True, stream=stream)
        log = structlog.get_logger("test")
        try:
            msg = "connection refused for redis://:s3cr3tpass@redis:6379/0"
            raise RuntimeError(msg)
        except RuntimeError as exc:
            log.error("redis.failed", exc_info=exc)
        output = stream.getvalue()
        assert "s3cr3tpass" not in output
        assert REDACTED in output
        # The exception type must survive — operators need to know what failed.
        assert "RuntimeError" in output

    def test_level_filtering_suppresses_below_threshold(self) -> None:
        stream = io.StringIO()
        configure_logging(level="WARNING", json_format=True, stream=stream)
        log = structlog.get_logger("test")
        log.info("should.not.appear")
        log.warning("should.appear")
        output = stream.getvalue()
        assert "should.not.appear" not in output
        assert "should.appear" in output

    def test_is_configured_reports_true_after_setup(self) -> None:
        configure_logging(level="INFO", json_format=True, stream=io.StringIO())
        assert is_configured() is True

    def test_reconfiguration_does_not_double_output(self) -> None:
        """Idempotence: two calls must not stack handlers and emit every event twice."""
        stream = io.StringIO()
        configure_logging(level="INFO", json_format=True, stream=stream)
        configure_logging(level="INFO", json_format=True, stream=stream)
        structlog.get_logger("test").info("once")
        assert stream.getvalue().count("once") == 1
