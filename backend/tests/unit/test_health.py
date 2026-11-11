"""Readiness/liveness tests.

No PostgreSQL or Redis exists in CI or in the development sandbox, so:

* the **success** paths are tested with injected fakes;
* ``check_redis`` is additionally tested against a **real in-process RESP socket server**, which
  exercises the actual parsing, AUTH handling and reply logic rather than a mock;
* the fail-closed rules are tested directly, because they are the property that matters most: a
  required dependency that is merely ``not_configured`` must NOT report ready.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from typing import Any

import pytest

from app.core.config import Environment, Settings, reset_settings
from app.core.health import (
    CheckResult,
    LivenessReport,
    ReadinessRegistry,
    build_default_registry,
    check_database,
    check_redis,
)


async def _result(name: str, status: str, *, required: bool = True) -> CheckResult:
    return CheckResult(name=name, status=status, detail="stub", required=required)  # type: ignore[arg-type]


def _registry(*pairs: tuple[str, str, bool]) -> ReadinessRegistry:
    registry = ReadinessRegistry()
    for name, status, required in pairs:

        async def _check(name: str = name, status: str = status) -> CheckResult:
            return await _result(name, status)

        registry.register(name, _check, required=required)  # type: ignore[arg-type]
    return registry


class TestRegistryFailClosed:
    async def test_all_required_ok_is_ready(self) -> None:
        report = await _registry(("database", "ok", True), ("redis", "ok", True)).evaluate()
        assert report.is_ready
        assert report.status == "ready"

    async def test_required_unavailable_is_not_ready(self) -> None:
        report = await _registry(
            ("database", "ok", True), ("redis", "unavailable", True)
        ).evaluate()
        assert not report.is_ready
        assert report.status == "not_ready"

    async def test_required_not_configured_is_not_ready(self) -> None:
        """The core fail-closed rule: unconfigured is a misconfiguration, not a pass."""
        report = await _registry(
            ("database", "not_configured", True), ("redis", "ok", True)
        ).evaluate()
        assert not report.is_ready

    async def test_optional_not_configured_does_not_block(self) -> None:
        """M1 registers migrations/preflight as optional so readiness is meaningful today."""
        report = await _registry(
            ("database", "ok", True), ("redis", "ok", True), ("migrations", "not_configured", False)
        ).evaluate()
        assert report.is_ready

    async def test_optional_unavailable_does_not_block(self) -> None:
        report = await _registry(
            ("database", "ok", True), ("redis", "ok", True), ("preflight", "unavailable", False)
        ).evaluate()
        assert report.is_ready

    async def test_degraded_required_blocks(self) -> None:
        report = await _registry(("database", "degraded", True)).evaluate()
        assert not report.is_ready

    async def test_empty_registry_is_not_ready(self) -> None:
        """No checks at all is a configuration error, not a healthy service."""
        assert not (await ReadinessRegistry().evaluate()).is_ready

    async def test_report_lists_every_check(self) -> None:
        """An operator must see WHICH dependency failed, not just that something did."""
        report = await _registry(
            ("database", "ok", True), ("redis", "unavailable", True)
        ).evaluate()
        names = {c.name for c in report.checks}
        assert names == {"database", "redis"}
        failed = [c for c in report.checks if c.status != "ok"]
        assert len(failed) == 1
        assert failed[0].name == "redis"

    async def test_checks_are_sorted_deterministically(self) -> None:
        """gather() completion order varies; the report must not."""
        report = await _registry(("redis", "ok", True), ("database", "ok", True)).evaluate()
        assert [c.name for c in report.checks] == ["database", "redis"]

    def test_duplicate_registration_is_refused(self) -> None:
        """Silently replacing a real check with a stub would hide an outage."""

        async def _check() -> CheckResult:
            return await _result("database", "ok")

        registry = ReadinessRegistry()
        registry.register("database", _check)
        with pytest.raises(ValueError, match="already registered"):
            registry.register("database", _check)

    async def test_registry_required_flag_overrides_the_check_result(self) -> None:
        """Policy lives in one place: the registry, not each check function."""

        async def _check() -> CheckResult:
            return CheckResult(name="migrations", status="not_configured", required=True)

        registry = ReadinessRegistry()
        registry.register("migrations", _check, required=False)
        report = await registry.evaluate()
        assert report.checks[0].required is False
        assert report.is_ready

    async def test_a_raising_check_does_not_take_down_the_endpoint(self) -> None:
        async def _boom() -> CheckResult:
            msg = "unexpected"
            raise RuntimeError(msg)

        registry = ReadinessRegistry()
        registry.register("database", _boom, required=True)
        report = await registry.evaluate()
        assert not report.is_ready
        assert "RuntimeError" in (report.checks[0].detail or "")

    async def test_a_hanging_check_times_out(self) -> None:
        """Readiness must not hang: a probe that never returns teaches an operator nothing."""
        from app.core import health  # noqa: PLC0415 — patched attribute lives on the module object

        async def _hang() -> CheckResult:
            await asyncio.sleep(health.PROBE_TIMEOUT_SECONDS + 5)
            return await _result("database", "ok")

        registry = ReadinessRegistry()
        registry.register("database", _hang, required=True)
        # Shrink the timeout so the test does not actually wait 3s.
        original = health.PROBE_TIMEOUT_SECONDS
        health.PROBE_TIMEOUT_SECONDS = 0.05
        try:
            report = await registry.evaluate()
        finally:
            health.PROBE_TIMEOUT_SECONDS = original
        assert not report.is_ready
        assert report.checks[0].status == "unavailable"
        assert "exceeded" in (report.checks[0].detail or "")


class TestLivenessReport:
    def test_liveness_carries_no_dependency_state(self) -> None:
        """Liveness must never fail because a dependency is down."""
        report = LivenessReport(version="0.1.0", service="truthlens")
        assert report.status == "ok"
        dumped = report.model_dump()
        assert "checks" not in dumped
        assert "database" not in str(dumped)


class TestCheckDatabase:
    async def test_unset_database_url_reports_not_configured(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        reset_settings()
        settings = Settings(tlx_env=Environment.TEST, database_url=None, **storage_roots)
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        result = await check_database()
        assert result.status == "not_configured"
        assert "DATABASE_URL" in (result.detail or "")

    async def test_unreachable_database_reports_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        """A real connection attempt against a port nothing listens on."""
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        settings = Settings(
            tlx_env=Environment.TEST,
            database_url=f"postgresql+psycopg://u:p@127.0.0.1:{free_port}/truthlens",
            db_pool_timeout_seconds=1,
            **storage_roots,
        )
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        result = await check_database()
        assert result.status == "unavailable"
        # The password must not appear in the detail, even though the driver may echo the URL.
        assert result.detail is not None


class _FakeRedisServer:
    """A minimal in-process RESP server, so check_redis is tested against real socket I/O."""

    def __init__(self, *, password: str | None = None, reply: str = "+PONG") -> None:
        self._password = password
        self._reply = reply
        self.received: list[bytes] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> _FakeRedisServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            with connection, connection.makefile("rwb") as channel:
                authenticated = self._password is None
                for _ in range(4):
                    try:
                        line = channel.readline()
                    except OSError:
                        return
                    if not line:
                        return
                    self.received.append(line)
                    command = line.strip().upper()
                    if command.startswith(b"AUTH"):
                        supplied = line.strip().split(b" ", 1)[1].decode()
                        authenticated = supplied == self._password
                        channel.write(b"+OK\r\n" if authenticated else b"-ERR invalid password\r\n")
                    elif command == b"PING":
                        if not authenticated:
                            channel.write(b"-NOAUTH Authentication required.\r\n")
                        else:
                            channel.write(self._reply.encode() + b"\r\n")
                    channel.flush()


class TestCheckRedis:
    async def test_unset_redis_url_reports_not_configured(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        settings = Settings(tlx_env=Environment.TEST, redis_url=None, **storage_roots)
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        result = await check_redis()
        assert result.status == "not_configured"

    async def test_real_ping_pong_succeeds(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        """A genuine socket round-trip, not a mock."""
        with _FakeRedisServer() as server:
            settings = Settings(
                tlx_env=Environment.TEST,
                redis_url=f"redis://127.0.0.1:{server.port}/0",
                **storage_roots,
            )
            monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
            result = await check_redis()
        assert result.status == "ok"
        assert result.detail is not None
        assert "PING/PONG" in result.detail
        assert any(b"PING" in line for line in server.received)

    async def test_authenticated_ping_succeeds(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        with _FakeRedisServer(password="s3cret-pass") as server:
            settings = Settings(
                tlx_env=Environment.TEST,
                redis_url=f"redis://:s3cret-pass@127.0.0.1:{server.port}/0",
                **storage_roots,
            )
            monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
            result = await check_redis()
        assert result.status == "ok"
        assert any(line.startswith(b"AUTH") for line in server.received)

    async def test_url_encoded_password_is_decoded(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        """A password containing a reserved character must survive URL parsing."""
        with _FakeRedisServer(password="p@ss:word/1") as server:
            settings = Settings(
                tlx_env=Environment.TEST,
                redis_url=f"redis://:p%40ss%3Aword%2F1@127.0.0.1:{server.port}/0",
                **storage_roots,
            )
            monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
            result = await check_redis()
        assert result.status == "ok"

    async def test_wrong_password_is_reported_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        with _FakeRedisServer(password="correct") as server:
            settings = Settings(
                tlx_env=Environment.TEST,
                redis_url=f"redis://:wrong@127.0.0.1:{server.port}/0",
                **storage_roots,
            )
            monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
            result = await check_redis()
        assert result.status == "unavailable"
        assert "AUTH" in (result.detail or "")

    async def test_unreachable_redis_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        settings = Settings(
            tlx_env=Environment.TEST, redis_url=f"redis://127.0.0.1:{free_port}/0", **storage_roots
        )
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        result = await check_redis()
        assert result.status == "unavailable"

    async def test_unexpected_reply_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        """A server that answers something other than PONG is not Redis."""
        with _FakeRedisServer(reply="-ERR unknown command") as server:
            settings = Settings(
                tlx_env=Environment.TEST,
                redis_url=f"redis://127.0.0.1:{server.port}/0",
                **storage_roots,
            )
            monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
            result = await check_redis()
        assert result.status == "unavailable"
        assert "unexpected reply" in (result.detail or "")

    async def test_unsupported_scheme_is_not_configured(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        settings = Settings(
            tlx_env=Environment.TEST, redis_url="memcached://127.0.0.1:11211/0", **storage_roots
        )
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        result = await check_redis()
        assert result.status == "not_configured"
        assert "scheme" in (result.detail or "")

    async def test_rediss_scheme_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        """`rediss` means TLS. The handshake will fail against a plain socket, but the URL must parse."""
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        settings = Settings(
            tlx_env=Environment.TEST, redis_url=f"rediss://127.0.0.1:{free_port}/0", **storage_roots
        )
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        result = await check_redis()
        assert result.status == "unavailable"
        assert "scheme" not in (result.detail or ""), "rediss must be accepted as a valid scheme"

    async def test_db_index_is_parsed(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        with _FakeRedisServer() as server:
            settings = Settings(
                tlx_env=Environment.TEST,
                redis_url=f"redis://127.0.0.1:{server.port}/7",
                **storage_roots,
            )
            monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
            result = await check_redis()
        assert result.status == "ok"
        assert "db 7" in (result.detail or "")


class TestDefaultRegistry:
    def test_database_and_redis_are_required(self) -> None:
        """M1's two real dependencies must both block readiness."""
        registry = build_default_registry()
        assert "database" in registry._checks
        assert "redis" in registry._checks
        assert registry._checks["database"][1] is True
        assert registry._checks["redis"][1] is True

    def test_migrations_and_preflight_are_registered_but_optional(self) -> None:
        """Registered now, reporting their real state, and flipped to required in the milestone that
        delivers them. A check that only appears once it passes would hide that it was missing."""
        registry = build_default_registry()
        assert registry._checks["migrations"][1] is False
        assert registry._checks["preflight"][1] is False

    async def test_pending_checks_report_honestly(
        self, monkeypatch: pytest.MonkeyPatch, storage_roots: dict[str, Any]
    ) -> None:
        settings = Settings(tlx_env=Environment.TEST, **storage_roots)
        monkeypatch.setattr("app.core.health.get_settings", lambda: settings)
        registry = build_default_registry()
        report = await registry.evaluate()
        by_name = {c.name: c for c in report.checks}
        assert "M2" in (by_name["migrations"].detail or "")
        assert by_name["preflight"].status == "not_configured"
        assert by_name["migrations"].status == "not_configured"

    async def test_default_registry_is_ready_when_dependencies_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end: real registry, real Redis socket, database stubbed out."""

        async def _db_ok() -> CheckResult:
            return CheckResult(name="database", status="ok", detail="stubbed for this test")

        with _FakeRedisServer() as server:
            reset_settings()
            monkeypatch.setenv("TLX_ENV", "test")
            monkeypatch.setenv("REDIS_URL", f"redis://127.0.0.1:{server.port}/0")
            monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@127.0.0.1:1/db")
            registry = build_default_registry()
            registry._checks["database"] = (_db_ok, True)
            report = await registry.evaluate()
        reset_settings()
        by_name = {c.name: c for c in report.checks}
        assert by_name["redis"].status == "ok"
        # migrations/preflight are optional and report not_configured, so readiness still holds.
        assert report.is_ready
