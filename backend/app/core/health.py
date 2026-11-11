"""Liveness, readiness and the dependency-check registry.

The distinction matters operationally and is easy to get wrong:

* **Liveness** (``/healthz``) answers "is this process alive?". It checks **no dependencies on
  purpose.** A liveness probe that fails because PostgreSQL is briefly unreachable causes an
  orchestrator or supervisor to restart healthy processes in a loop, converting a dependency blip
  into a full outage.
* **Readiness** (``/readyz``) answers "can this process serve traffic?". It checks every required
  dependency for real, and returns **503** with a per-check breakdown when any of them fails.

One fail-closed rule drives the registry: a **required** check that reports ``not_configured`` is
treated as **NOT ready**. An unconfigured dependency is a misconfiguration, not a pass — reporting
"ready" because we forgot to configure Redis would be exactly the kind of false assurance this
platform exists to avoid.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Awaitable, Callable
from typing import Any, Literal
from urllib.parse import unquote, urlparse

import structlog
from pydantic import BaseModel, Field

from app.core.config import get_settings

logger = structlog.get_logger(__name__)

CheckName = Literal[
    "database",
    "redis",
    "storage",
    "migrations",
    "preflight",
    "models",
    "inference",
]

#: ``not_configured`` is distinct from ``unavailable``: the first means nobody told us how to reach
#: the dependency, the second means we tried and it did not answer. Operators act on them differently.
CheckStatus = Literal["ok", "degraded", "unavailable", "not_configured"]

#: How long a single dependency probe may take before it is reported unavailable. Readiness must not
#: hang: an operator staring at a probe that never returns learns nothing.
PROBE_TIMEOUT_SECONDS = 3.0


class CheckResult(BaseModel):
    """Outcome of one dependency probe."""

    name: CheckName
    status: CheckStatus
    detail: str | None = None
    #: Whether this check is required for the service to be considered ready.
    required: bool = True


class ReadinessReport(BaseModel):
    """Aggregate readiness. ``checks`` is always present so an operator sees *which* failed."""

    status: Literal["ready", "not_ready"]
    checks: list[CheckResult] = Field(default_factory=list)

    @property
    def is_ready(self) -> bool:
        return self.status == "ready"


class LivenessReport(BaseModel):
    """Liveness. Carries no dependency state by design."""

    status: Literal["ok"] = "ok"
    version: str
    service: str


CheckFunc = Callable[[], Awaitable[CheckResult]]


class ReadinessRegistry:
    """Collects dependency checks and evaluates them concurrently.

    Checks run with ``asyncio.gather`` rather than sequentially: with several dependencies, a
    sequential probe would add their timeouts together and make ``/readyz`` unusable exactly when
    something is wrong.
    """

    def __init__(self) -> None:
        self._checks: dict[str, tuple[CheckFunc, bool]] = {}

    def register(self, name: CheckName, check: CheckFunc, *, required: bool = True) -> None:
        if name in self._checks:
            # Re-registering silently would let a later import replace a real check with a stub.
            msg = f"readiness check {name!r} is already registered"
            raise ValueError(msg)
        self._checks[name] = (check, required)

    async def evaluate(self) -> ReadinessReport:
        if not self._checks:
            # No checks at all is a configuration error, not a healthy service.
            return ReadinessReport(status="not_ready", checks=[])

        results = await asyncio.gather(
            *(self._run(name, func, required) for name, (func, required) in self._checks.items()),
            return_exceptions=False,
        )
        ordered = sorted(results, key=lambda r: r.name)
        # Fail closed: a required check that is anything other than "ok" blocks readiness.
        # A non-required check may be not_configured without blocking (see build_default_registry).
        ready = all((result.status == "ok") or (not result.required) for result in ordered)
        return ReadinessReport(status="ready" if ready else "not_ready", checks=ordered)

    @staticmethod
    async def _run(name: str, check: CheckFunc, required: bool) -> CheckResult:
        try:
            result = await asyncio.wait_for(check(), timeout=PROBE_TIMEOUT_SECONDS)
        except TimeoutError:
            return CheckResult(
                name=name,  # type: ignore[arg-type]
                status="unavailable",
                detail=f"probe exceeded {PROBE_TIMEOUT_SECONDS}s",
                required=required,
            )
        except Exception as exc:
            # Report the exception type and message. The redaction processor strips any credential
            # that happens to be embedded in a connection string inside that message.
            return CheckResult(
                name=name,  # type: ignore[arg-type]
                status="unavailable",
                detail=f"{type(exc).__name__}: {exc}",
                required=required,
            )
        # Honour the registry's `required` rather than whatever the check function set, so the
        # policy lives in one place.
        return result.model_copy(update={"required": required})


async def check_database() -> CheckResult:
    """Verify the database is reachable and answering, with a real ``SELECT 1``.

    Returns ``not_configured`` when ``DATABASE_URL`` is unset, which ``ReadinessRegistry`` treats as
    *not ready* for a required check.
    """
    settings = get_settings()
    if not settings.database_url:
        return CheckResult(
            name="database", status="not_configured", detail="DATABASE_URL is not set"
        )

    # Bound to a local: DATABASE_URL was checked above, but mypy does not carry that narrowing into
    # the nested `_blocking` closure, and a probe must read one consistent value regardless.
    database_url: str = settings.database_url

    try:
        # Local import: sqlalchemy lives in the optional `db` extra, so this module must import and
        # report honestly in environments where it is absent (lint, docs builds, unit-test CI).
        from sqlalchemy import create_engine, text  # noqa: PLC0415
    except ImportError:
        # The `db` extra is not installed. Report honestly rather than claiming success — a probe
        # that passes because a driver is missing is worse than no probe.
        return CheckResult(
            name="database",
            status="unavailable",
            detail="sqlalchemy is not installed; install the 'db' extra",
        )

    def _blocking() -> CheckResult:
        # DATABASE_URL uses the synchronous psycopg driver in v1. The probe runs off the event loop
        # so a slow or hung database cannot stall /readyz for every other caller.
        #
        # create_engine is INSIDE the try: it imports the DBAPI driver eagerly, so a missing
        # `psycopg` would otherwise raise out of the probe and take /readyz down with it. A
        # readiness endpoint that crashes is worse than one that reports "unavailable".
        engine = None
        try:
            engine = create_engine(
                database_url,
                pool_pre_ping=True,
                pool_timeout=settings.db_pool_timeout_seconds,
                connect_args={"connect_timeout": max(1, int(settings.db_pool_timeout_seconds))},
            )
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return CheckResult(name="database", status="ok", detail="SELECT 1 succeeded")
        except ModuleNotFoundError as exc:
            # Distinct from "unreachable": this is a broken deployment image, not a down database.
            # Operators act on the two differently, so they are reported differently.
            return CheckResult(
                name="database",
                status="unavailable",
                detail=(
                    f"database driver is not installed ({exc.name}); install the 'db' extra "
                    "so the deployment image matches DATABASE_URL"
                ),
            )
        except Exception as exc:
            return CheckResult(
                name="database", status="unavailable", detail=f"{type(exc).__name__}: {exc}"
            )
        finally:
            if engine is not None:
                engine.dispose()

    return await asyncio.to_thread(_blocking)


async def check_redis() -> CheckResult:
    """Verify Redis answers ``PING`` using a raw RESP connection.

    Deliberately **dependency-free**: M1 configures Redis but does not yet use a client library (the
    Celery broker arrives in M7, and ADR-0022 keeps Redis holding nothing durable until then). A raw
    ``PING`` / ``+PONG`` exchange is a genuine reachability check rather than a placeholder, and it
    validates the URL's host, port, password and TLS parsing for real.
    """
    settings = get_settings()
    if not settings.redis_url:
        return CheckResult(name="redis", status="not_configured", detail="REDIS_URL is not set")

    try:
        parsed = urlparse(settings.redis_url)
    except ValueError as exc:
        return CheckResult(name="redis", status="not_configured", detail=f"unparsable URL: {exc}")

    if parsed.scheme not in {"redis", "rediss"}:
        return CheckResult(
            name="redis",
            status="not_configured",
            detail=f"unsupported scheme {parsed.scheme!r}; expected 'redis' or 'rediss'",
        )

    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    password = unquote(parsed.password) if parsed.password else None
    db_index = int(parsed.path.lstrip("/") or 0) if parsed.path else 0
    use_tls = parsed.scheme == "rediss"

    return await asyncio.to_thread(_redis_ping, host, port, password, db_index, use_tls)


def _redis_ping(
    host: str, port: int, password: str | None, db_index: int, use_tls: bool
) -> CheckResult:
    """Blocking RESP PING, run off the event loop by :func:`check_redis`."""
    context = ssl.create_default_context() if use_tls else None
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT_SECONDS) as raw:
            sock: socket.socket = raw
            if context is not None:
                sock = context.wrap_socket(raw, server_hostname=host)
            with sock.makefile("rwb") as channel:
                if password:
                    # Inline AUTH. The password is never logged: the redaction processor treats
                    # `redis_url` and `password` keys as sensitive, and nothing here logs the value.
                    channel.write(f"AUTH {password}\r\n".encode())
                    channel.flush()
                    auth_reply = _read_line(channel)
                    if not auth_reply.startswith("+"):
                        return CheckResult(
                            name="redis", status="unavailable", detail="AUTH was rejected"
                        )
                channel.write(b"PING\r\n")
                channel.flush()
                reply = _read_line(channel)
                if reply.strip() in ("+PONG", "PONG"):
                    return CheckResult(
                        name="redis", status="ok", detail=f"PING/PONG on db {db_index}"
                    )
                return CheckResult(
                    name="redis", status="unavailable", detail=f"unexpected reply: {reply[:80]!r}"
                )
    except OSError as exc:
        return CheckResult(
            name="redis", status="unavailable", detail=f"{type(exc).__name__}: {exc}"
        )


def _read_line(channel: Any, limit: int = 512) -> str:
    """Read one RESP line, bounded so a misbehaving server cannot exhaust memory."""
    data: bytes = channel.readline(limit)
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def build_default_registry() -> ReadinessRegistry:
    """Wire the checks M1 is responsible for.

    ``migrations`` and ``preflight`` are registered as **not required** in M1 and report honestly
    that they are not yet implemented. They are flipped to required in the milestone that delivers
    them — M2 for schema-head verification, M19/M20 for the encrypted-volume host preflight
    (ADR-0006 §5.4). Registering them now, reporting their real state, is deliberate: a check that
    appears only when it starts passing would hide the fact that it was missing before.
    """
    registry = ReadinessRegistry()
    registry.register("database", check_database, required=True)
    registry.register("redis", check_redis, required=True)

    async def _migrations_pending() -> CheckResult:
        return CheckResult(
            name="migrations",
            status="not_configured",
            detail=(
                "schema-head verification is delivered in M2; no domain schema exists yet in M1"
            ),
        )

    async def _preflight_pending() -> CheckResult:
        settings = get_settings()
        if not settings.preflight_required:
            return CheckResult(
                name="preflight",
                status="not_configured",
                detail="host preflight is not required outside production (ADR-0006 §5.4)",
            )
        return CheckResult(
            name="preflight",
            status="not_configured",
            detail=(
                "encrypted-volume verification runs at container entrypoint in M19/M20; "
                "infra/scripts/verify-encrypted-mount.sh is specified in BACKUP_RECOVERY.md §5.4 "
                "but not yet wired into the startup path"
            ),
        )

    registry.register("migrations", _migrations_pending, required=False)
    registry.register("preflight", _preflight_pending, required=False)
    return registry


__all__ = [
    "PROBE_TIMEOUT_SECONDS",
    "CheckFunc",
    "CheckName",
    "CheckResult",
    "CheckStatus",
    "LivenessReport",
    "ReadinessRegistry",
    "ReadinessReport",
    "build_default_registry",
    "check_database",
    "check_redis",
]
