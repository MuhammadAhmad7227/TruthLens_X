"""The database layer: identifiers, configuration refusals, the engine/session lifecycle, and the
schema-head readiness probe.

Most of this needs no server. ``build_engine`` does not connect, ``require_database_url`` only parses,
and :func:`app.db.uuid7.uuid7` is arithmetic — so the parts that decide *whether the application may
start* are tested everywhere, including in a CI job with no PostgreSQL. The parts that can only be
proven against a real server (that ``verify_schema_head`` reads the revision, that ``atomic()`` nests
through savepoints, that ``get_session`` leaves nothing behind) are marked and skip with a reason.

The layer's contract, which these tests hold it to: it provides sessions, not queries
(SYSTEM_ARCHITECTURE §4.1 rule 7); the request dependency never commits; and every failure to reach
the database is *reported*, never raised out of a probe.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, cast
from uuid import RFC_4122, UUID

import pytest
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool
from structlog.testing import capture_logs

from app.core.config import Settings, get_settings, reset_settings
from app.core.errors import DependencyUnavailableError
from app.db import (
    base as base_module,
    migrations as migrations_module,
    session as session_module,
    transaction as transaction_module,
    uuid7 as uuid7_module,
)
from app.db.base import NAMING_CONVENTION, SoftDeleteMixin, TimestampMixin
from app.db.session import (
    DatabaseNotConfiguredError,
    build_engine,
    create_session_factory,
    dispose_database,
    get_engine,
    get_session,
    get_session_factory,
    init_database,
    is_database_configured,
    require_database_url,
)
from app.db.transaction import atomic, session_scope
from app.db.uuid7 import uuid7
from app.models.identity import User
from tests.db.conftest import (
    alembic_downgrade,
    alembic_stamp,
    disposable_database,
    one,
    scalars,
)

#: A URL that parses and can never connect. Port 1 is reserved and nothing listens there, so an
#: engine built from it stays lazy and a probe against it fails fast and honestly.
UNREACHABLE_URL: Final = "postgresql+psycopg://tlx_probe:not-a-real-password@127.0.0.1:1/truthlens"

#: The revision at the tip of the graph, spelled out so a stale expectation fails loudly here rather
#: than being quietly inherited from whatever the scripts happen to contain.
HEAD_REVISION: Final = "0006"

#: The revision before it. A test that puts a database "one behind" has to name the revision it means:
#: stamping an older one changes how many revisions are pending, which is the number under assertion.
PREVIOUS_REVISION: Final = "0004"


@pytest.fixture(autouse=True)
def _isolated_engine_state() -> Iterator[None]:
    """The engine and session factory are process-wide singletons; a test must not inherit one.

    Reset on both sides: a leaked engine would make an idempotency test pass by accident, and would
    hold a connection pool open past the end of the session.
    """
    dispose_database()
    yield
    dispose_database()


@pytest.fixture
def unreachable_settings(dev_settings: Settings) -> Settings:
    """Settings pointing at a server that refuses connections."""
    return dev_settings.model_copy(update={"database_url": UNREACHABLE_URL})


@pytest.fixture
def unconfigured_settings(dev_settings: Settings) -> Settings:
    """Settings with no ``DATABASE_URL`` at all.

    ``dev_settings`` deliberately carries a canary connection string (the leak tests need one), so
    "unconfigured" has to be built rather than borrowed.
    """
    return dev_settings.model_copy(update={"database_url": None})


@contextmanager
def _configured(url: str | None) -> Iterator[None]:
    """Point the application's own settings at ``url`` for the duration of the block.

    ``migrations/env.py`` and ``get_engine()`` both resolve their connection string through
    ``app.core.config`` — Alembic has no second configuration system, and neither does this layer —
    so driving them from a test means driving them through the same settings object the API uses.
    """
    previous = os.environ.get("DATABASE_URL")
    if url is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = url
    reset_settings()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        reset_settings()
        dispose_database()


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# UUIDv7
# ══════════════════════════════════════════════════════════════════════════════════════════════════


class TestUuidV7:
    """ADR-0009: time-ordered identifiers for append-only tables.

    Python generates these for tests and for any code path that needs an identifier before insert;
    PostgreSQL generates them as column defaults. Both must produce the same shape, or a row written
    one way sorts differently from a row written the other.
    """

    def test_the_version_and_variant_nibbles_are_rfc_9562(self) -> None:
        identifier = uuid7()
        assert identifier.version == 7
        assert identifier.variant == RFC_4122

    def test_the_supplied_timestamp_is_what_gets_embedded(self) -> None:
        """The parameter exists so ordering can be asserted rather than hoped for."""
        millis = 1_700_000_000_123
        identifier = uuid7(timestamp_ms=millis)
        assert identifier.int >> 80 == millis

    def test_identifiers_order_by_time(self) -> None:
        earlier = uuid7(timestamp_ms=1_700_000_000_000)
        later = uuid7(timestamp_ms=1_700_000_000_001)
        assert earlier < later, "UUIDv7 must sort chronologically or a B-tree scan cannot use it"

    def test_identifiers_generated_together_are_distinct(self) -> None:
        """74 bits of CSPRNG output per identifier: a collision here would be a security event, not
        an inconvenience, because these keys are used as capability references."""
        generated = {uuid7() for _ in range(20_000)}
        assert len(generated) == 20_000

    def test_two_identifiers_for_the_same_millisecond_share_no_random_bits(self) -> None:
        """The random tail is what keeps same-millisecond identifiers unpredictable.

        The variant bits are constant by definition, so the comparison masks them off: what is left
        is ``rand_b``, and two calls must not produce the same value or consecutive values.
        """
        millis = 1_700_000_000_000
        first = uuid7(timestamp_ms=millis)
        second = uuid7(timestamp_ms=millis)
        random_bits = (1 << 62) - 1
        assert first != second
        assert (first.int & random_bits) != (second.int & random_bits)

    def test_the_python_and_server_generators_agree(self, scratch_engine: Engine) -> None:
        """Both generators must lay out the same fields, or a row keyed in Python sorts differently
        from one keyed by a column default — and a ledger that sorts inconsistently is unreadable."""
        with scratch_engine.connect() as connection:
            server_side = [
                UUID(str(value))
                for value in scalars(
                    connection.execute(
                        text("SELECT uuid_generate_v7() FROM generate_series(1, 16)")
                    )
                )
            ]
        client_side = uuid7()
        assert server_side, "the server produced no identifiers"
        for generated in [*server_side, client_side]:
            assert generated.version == 7
            assert generated.variant == RFC_4122
            # The embedded timestamp must be within a minute of now, on both sides.
            embedded_ms = generated.int >> 80
            assert abs(embedded_ms - datetime.now(UTC).timestamp() * 1000) < 60_000


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════════════════════════


class TestConfigurationRefusals:
    def test_a_missing_url_is_reported_as_unconfigured(
        self, unconfigured_settings: Settings
    ) -> None:
        assert is_database_configured(unconfigured_settings) is False
        with pytest.raises(DatabaseNotConfiguredError, match="DATABASE_URL is not set"):
            require_database_url(unconfigured_settings)

    def test_the_refusal_is_a_503_that_names_the_dependency_and_the_fix(
        self, unconfigured_settings: Settings
    ) -> None:
        """A missing database is a dependency problem, not a server bug: 500 would send an operator
        looking at the application instead of at the configuration."""
        with pytest.raises(DatabaseNotConfiguredError) as excinfo:
            require_database_url(unconfigured_settings)
        error = excinfo.value
        assert isinstance(error, DependencyUnavailableError)
        assert error.status == 503
        assert error.error_code == "DEPENDENCY_UNAVAILABLE"
        assert error.to_problem().status == 503
        assert "postgresql+psycopg" in str(error.remediation)

    @pytest.mark.parametrize(
        "scheme",
        ["sqlite", "mysql+pymysql", "mariadb", "mongodb", "postgresql-typo"],
    )
    def test_a_non_postgresql_scheme_is_refused_before_anything_connects(
        self, unconfigured_settings: Settings, scheme: str
    ) -> None:
        """§11 targets PostgreSQL 16, and the schema depends on it.

        Pointing at SQLite would not fail at connect time: it would fail at the first ``CREATE TYPE``,
        or appear to work until a JSONB query returned nothing. Refusing the scheme is cheaper than
        either outcome, and it happens before a pool is opened.
        """
        settings = unconfigured_settings.model_copy(
            update={"database_url": f"{scheme}://localhost/truthlens"}
        )
        with pytest.raises(DatabaseNotConfiguredError, match="not supported"):
            require_database_url(settings)

    @pytest.mark.parametrize(
        "url",
        [
            "postgresql+psycopg://tlx:pw@localhost:5432/truthlens",
            "postgresql://tlx:pw@localhost:5432/truthlens",
            "POSTGRESQL+PSYCOPG://tlx:pw@localhost:5432/truthlens",
        ],
    )
    def test_every_postgresql_spelling_is_accepted(
        self, unconfigured_settings: Settings, url: str
    ) -> None:
        settings = unconfigured_settings.model_copy(update={"database_url": url})
        assert is_database_configured(settings) is True
        assert require_database_url(settings) == url

    def test_the_url_is_read_from_the_application_configuration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No second configuration system: the same ``Settings`` object the API validates."""
        monkeypatch.setenv("DATABASE_URL", UNREACHABLE_URL)
        reset_settings()
        try:
            assert require_database_url() == UNREACHABLE_URL
            assert require_database_url(get_settings()) == UNREACHABLE_URL
        finally:
            reset_settings()


class TestEngineConstruction:
    def test_every_pool_parameter_comes_from_configuration(
        self, unreachable_settings: Settings
    ) -> None:
        settings = unreachable_settings.model_copy(
            update={
                "db_pool_size": 7,
                "db_max_overflow": 3,
                "db_pool_timeout_seconds": 11,
                "db_pool_recycle_seconds": 900,
                "db_echo": True,
            }
        )
        engine = build_engine(settings)
        try:
            pool = cast(QueuePool, engine.pool)
            assert engine.echo is True
            assert pool.size() == 7
            # QueuePool.timeout() is a method that reports current state; the configured values live
            # in underscore attributes with no public accessor. They are exactly the parameters an
            # operator tunes under load, so the test reaches in rather than trusting the call was made.
            assert pool._timeout == 11
            assert pool._max_overflow == 3
            assert pool._recycle == 900
        finally:
            engine.dispose()

    def test_the_statement_timeout_is_passed_to_libpq_for_every_connection(
        self, unreachable_settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """libpq's ``options``, not a per-query hint.

        A per-query setting protects the queries somebody remembered to protect. This protects the
        ones written later by somebody who has never heard of it — and a runaway query against a
        table holding evidence competes with ingest for the same connections and the same disk.
        """
        settings = unreachable_settings.model_copy(update={"db_statement_timeout_ms": 4242})
        calls = _record_engine_construction(monkeypatch)
        engine = build_engine(settings)
        engine.dispose()
        assert calls[0]["connect_args"]["options"] == "-c statement_timeout=4242"

    def test_the_timeout_is_what_the_server_applies(self, scratch_database: str) -> None:
        """The other half: that libpq accepts the option and the session ends up limited by it."""
        settings = get_settings().model_copy(
            update={"database_url": scratch_database, "db_statement_timeout_ms": 4242}
        )
        engine = build_engine(settings)
        try:
            with engine.connect() as connection:
                assert one(connection.execute(text("SHOW statement_timeout"))) == "4242ms"
        finally:
            engine.dispose()

    def test_the_connect_timeout_never_means_wait_forever(
        self, unreachable_settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """libpq reads 0 as "no timeout", so the floor is what keeps a black-holed host from hanging
        a worker for the kernel's default."""
        settings = unreachable_settings.model_copy(update={"db_pool_timeout_seconds": 0})
        calls = _record_engine_construction(monkeypatch)
        engine = build_engine(settings)
        engine.dispose()
        assert int(calls[0]["connect_args"]["connect_timeout"]) >= 1

    def test_connections_are_health_checked_before_use(
        self, unreachable_settings: Settings
    ) -> None:
        """``pool_pre_ping``: a connection the server closed during an idle period must not be handed
        to a request that then fails on its first statement."""
        engine = build_engine(unreachable_settings)
        try:
            assert cast(QueuePool, engine.pool)._pre_ping is True
        finally:
            engine.dispose()

    def test_a_missing_driver_is_a_deployment_defect_not_an_outage(
        self, unreachable_settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Different message, different operator action: rebuild the image with the ``db`` extra.

        Conflating it with "the database is down" sends somebody to restart PostgreSQL while the real
        fix is a build.
        """

        def refuse_without_the_driver(*args: Any, **kwargs: Any) -> Engine:
            raise ModuleNotFoundError("No module named 'psycopg'", name="psycopg")

        monkeypatch.setattr(session_module, "create_engine", refuse_without_the_driver)
        with pytest.raises(DependencyUnavailableError, match="driver is not installed") as excinfo:
            build_engine(unreachable_settings)
        error = excinfo.value
        assert not isinstance(error, DatabaseNotConfiguredError)
        assert isinstance(error.__cause__, ModuleNotFoundError)
        assert "'db' extra" in str(error.remediation)

    def test_the_session_factory_defaults_are_the_deliberate_ones(
        self, unreachable_settings: Settings
    ) -> None:
        engine = build_engine(unreachable_settings)
        try:
            factory = create_session_factory(engine)
            session = factory()
            try:
                assert session.expire_on_commit is False, (
                    "post-commit attribute reads must not re-SELECT an object graph that is already "
                    "correct in memory"
                )
                assert session.autoflush is True, (
                    "a uniqueness violation must surface at the statement that caused it, where the "
                    "code can still react, not at commit"
                )
                assert isinstance(session, Session)
            finally:
                session.close()
        finally:
            engine.dispose()


class TestEngineLifecycle:
    def test_initialising_twice_returns_the_same_engine(
        self, unreachable_settings: Settings
    ) -> None:
        """A second engine would be a second connection pool, and nothing would ever dispose it."""
        first = init_database(unreachable_settings)
        assert init_database(unreachable_settings) is first
        assert get_engine() is first
        assert get_session_factory().kw["bind"] is first

    def test_initialising_from_concurrent_requests_creates_one_engine(
        self, unreachable_settings: Settings
    ) -> None:
        """The first request may arrive on any thread; the lock is what makes the singleton safe."""
        threads_count = 8
        barrier = threading.Barrier(threads_count)
        engines: list[Engine] = []
        guard = threading.Lock()

        def initialise() -> None:
            barrier.wait(timeout=5)
            engine = init_database(unreachable_settings)
            with guard:
                engines.append(engine)

        workers = [threading.Thread(target=initialise) for _ in range(threads_count)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
        assert len(engines) == threads_count
        assert len({id(engine) for engine in engines}) == 1

    def test_disposal_clears_the_state_so_a_new_engine_can_be_built(
        self, unreachable_settings: Settings
    ) -> None:
        first = init_database(unreachable_settings)
        dispose_database()
        assert init_database(unreachable_settings) is not first

    def test_disposal_is_safe_when_nothing_was_initialised(self) -> None:
        """Shutdown runs whether or not startup ever reached the database."""
        dispose_database()
        dispose_database()

    def test_disposal_returns_the_pooled_connections(self, unreachable_settings: Settings) -> None:
        """Without it a worker that exits after a batch leaves the server holding idle connections
        until they time out — and PgBouncer in front makes that a shared-resource problem."""
        engine = init_database(unreachable_settings)
        pool = cast(QueuePool, engine.pool)
        dispose_database()
        # size() is the configured capacity and survives disposal by design; what must be zero is the
        # number of connections still held or still handed out.
        assert pool.checkedin() == 0
        assert pool.checkedout() == 0

    def test_the_factory_is_created_lazily_on_first_use(
        self, unreachable_settings: Settings
    ) -> None:
        """``get_session_factory`` must work in a worker that never called ``init_database``."""
        with _configured(unreachable_settings.database_url):
            factory = get_session_factory()
            assert isinstance(factory, sessionmaker)
            assert get_engine() is factory.kw["bind"]

    def test_an_unconfigured_application_refuses_rather_than_guessing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        reset_settings()
        try:
            with pytest.raises(DatabaseNotConfiguredError):
                get_session_factory()
        finally:
            reset_settings()


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# The request dependency
# ══════════════════════════════════════════════════════════════════════════════════════════════════


@pytest.mark.integration
class TestRequestSessionDependency:
    """``get_session`` is the boundary between a request and a transaction.

    The rule it implements: **the dependency never commits**. A service commits by calling
    :func:`app.db.transaction.atomic`; if a request ends with uncommitted work, that work is rolled
    back and says so out loud. The alternative — committing whatever happens to be pending when the
    handler returns — would make "did this write happen?" depend on the order in which a framework
    tears a request down.
    """

    def test_it_yields_a_session_that_can_read(self, scratch_database: str) -> None:
        with _configured(scratch_database):
            sessions = get_session()
            session = next(sessions)
            try:
                assert one(session.execute(text("SELECT count(*) FROM roles"))) == 6
            finally:
                _exhaust(sessions)

    def test_a_write_nobody_committed_does_not_survive_the_request(
        self, scratch_database: str
    ) -> None:
        with _configured(scratch_database):
            sessions = get_session()
            session = next(sessions)
            session.add(_user("never-committed@example.org"))
            _exhaust(sessions)

        assert _count_users(scratch_database, "never-committed@example.org") == 0, (
            "the dependency committed a write nobody asked it to"
        )

    def test_the_dropped_write_is_announced_with_enough_detail_to_find_it(
        self, scratch_database: str
    ) -> None:
        """Silently discarding a write is worse than raising: the caller believes it was stored."""
        with _configured(scratch_database), capture_logs() as logs:
            sessions = get_session()
            session = next(sessions)
            session.add(_user("announced@example.org"))
            _exhaust(sessions)

        warnings = [
            entry for entry in logs if entry.get("event") == "uncommitted_changes_at_request_end"
        ]
        assert len(warnings) == 1, f"expected exactly one warning, got {logs}"
        assert warnings[0]["log_level"] == "warning"
        assert warnings[0]["new"] == 1
        assert "atomic()" in str(warnings[0]["remediation"])

    def test_a_failing_request_is_rolled_back_before_the_error_reaches_the_handler(
        self, scratch_database: str
    ) -> None:
        """The exception handler that builds the problem detail must not run against a connection
        still holding locks or an aborted transaction — so the rollback happens first, and this test
        asserts the order rather than assuming it."""

        class HandlerFailedError(Exception):
            """Stands in for a handler raising halfway through a request."""

        order: list[str] = []
        with _configured(scratch_database):
            sessions = get_session()
            session = next(sessions)
            event.listen(
                session, "after_rollback", lambda _session: order.append("transaction_rolled_back")
            )
            session.add(_user("rolled-back@example.org"))
            try:
                sessions.throw(HandlerFailedError("the handler failed"))
            except HandlerFailedError:
                order.append("caller_saw_the_error")
            else:
                pytest.fail("the dependency swallowed the request's exception")
            assert session.in_transaction() is False

        assert order == ["transaction_rolled_back", "caller_saw_the_error"]

    def test_a_committed_write_survives_because_the_service_committed_it(
        self, scratch_database: str
    ) -> None:
        with _configured(scratch_database):
            sessions = get_session()
            session = next(sessions)
            with atomic(session):
                session.add(_user("committed-by-service@example.org"))
            _exhaust(sessions)

        assert _count_users(scratch_database, "committed-by-service@example.org") == 1

    def test_the_session_is_closed_whichever_way_the_request_ends(
        self, scratch_database: str
    ) -> None:
        """A session left open holds a pooled connection, and the pool is finite."""
        with _configured(scratch_database):
            sessions = get_session()
            session = next(sessions)
            _exhaust(sessions)
            assert session.in_transaction() is False
            assert session.get_transaction() is None


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# Transactions
# ══════════════════════════════════════════════════════════════════════════════════════════════════


@pytest.mark.integration
class TestTransactionHelpers:
    def test_atomic_commits_on_a_clean_exit(self, scratch_database: str) -> None:
        engine = create_engine(scratch_database)
        try:
            with session_scope(create_session_factory(engine)) as session, atomic(session):
                session.execute(
                    text("INSERT INTO organisations (slug, name) VALUES ('tx-probe', 'Probe')")
                )
            with engine.begin() as connection:
                assert _slug_count(connection, "tx-probe") == 1
                connection.execute(text("DELETE FROM organisations WHERE slug = 'tx-probe'"))
        finally:
            engine.dispose()

    def test_atomic_rolls_back_on_an_exception(self, scratch_database: str) -> None:
        engine = create_engine(scratch_database)
        try:
            with (
                pytest.raises(RuntimeError, match="aborted mid-write"),
                session_scope(create_session_factory(engine)) as session,
            ):
                _write_then_fail(session, "tx-abort")
            with engine.connect() as connection:
                assert _slug_count(connection, "tx-abort") == 0
        finally:
            engine.dispose()

    def test_nested_atomic_uses_savepoints_so_an_inner_failure_is_not_an_outer_one(
        self, scratch_database: str
    ) -> None:
        """The property that makes "try this, and if the database refuses it, continue" possible.

        Without nesting, an expected refusal — a duplicate, a CHECK that fires on one of several
        candidate rows — would abort the whole transaction and every write made before it.
        """
        engine = create_engine(scratch_database)
        try:
            with session_scope(create_session_factory(engine)) as session, atomic(session):
                session.execute(
                    text("INSERT INTO organisations (slug, name) VALUES ('tx-outer', 'Outer')")
                )
                with pytest.raises(SQLAlchemyError), atomic(session):
                    session.execute(
                        text("INSERT INTO organisations (slug, name) VALUES ('tx-outer', 'Dupe')")
                    )
                # The outer transaction is still usable after the inner failure.
                session.execute(
                    text("INSERT INTO organisations (slug, name) VALUES ('tx-after', 'After')")
                )
            with engine.begin() as connection:
                found = scalars(
                    connection.execute(
                        text(
                            "SELECT slug FROM organisations WHERE slug IN ('tx-outer', 'tx-after') ORDER BY slug"
                        )
                    )
                )
                assert list(found) == ["tx-after", "tx-outer"]
                connection.execute(text("DELETE FROM organisations WHERE slug LIKE 'tx-%'"))
        finally:
            engine.dispose()

    def test_session_scope_closes_the_session_even_when_the_body_fails(
        self, scratch_database: str
    ) -> None:
        engine = create_engine(scratch_database)
        try:
            factory = create_session_factory(engine)
            with pytest.raises(ValueError, match="body failed"), session_scope(factory) as session:
                raise ValueError("body failed")
            assert session.in_transaction() is False
        finally:
            engine.dispose()

    def test_session_scope_returns_a_usable_session(self, scratch_database: str) -> None:
        engine = create_engine(scratch_database)
        try:
            with session_scope(create_session_factory(engine)) as session:
                assert one(session.execute(text("SELECT count(*) FROM permissions"))) == 30
        finally:
            engine.dispose()

    def test_session_scope_without_a_factory_uses_the_process_wide_one(
        self, scratch_database: str
    ) -> None:
        """The path a worker script takes: no engine plumbing, just a transaction."""
        with _configured(scratch_database), session_scope() as session:
            assert one(session.execute(text("SELECT count(*) FROM roles"))) == 6


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# The schema-head readiness probe
# ══════════════════════════════════════════════════════════════════════════════════════════════════


class TestVerifySchemaHead:
    """§11: a server whose schema does not match its code must not serve traffic.

    ``verify_schema_head`` never raises — a readiness probe that can throw takes ``/readyz`` down with
    it, which is the one moment the probe is most needed. Every branch below is a way the database can
    be wrong, and each one has to come back as a status an operator can act on.
    """

    def test_it_reports_an_unconfigured_database(self, unconfigured_settings: Settings) -> None:
        status = migrations_module.verify_schema_head(unconfigured_settings)
        assert status.state == "not_configured"
        assert "DATABASE_URL" in status.detail

    def test_it_reports_an_unreachable_server_without_failing_the_probe(
        self, unreachable_settings: Settings
    ) -> None:
        status = migrations_module.verify_schema_head(unreachable_settings)
        assert status.state == "unreachable"
        assert status.head == HEAD_REVISION
        assert status.detail, "an operator needs the reason, not just the category"

    def test_it_reports_a_missing_migrations_directory(
        self, unreachable_settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wheel packages ``app``; ``migrations/`` reaches the image through a separate COPY.

        If that step is dropped, the honest answer is "I cannot tell", not "we are at head" — a
        container that reports ready while holding no migration scripts is a container that will
        serve queries against a schema it never checked.
        """

        def no_migrations_directory() -> None:
            return None

        monkeypatch.setattr(migrations_module, "find_script_directory", no_migrations_directory)
        status = migrations_module.verify_schema_head(unreachable_settings)
        assert status.state == "not_configured"
        assert "migrations" in status.detail

    def test_it_reports_a_branched_migration_graph_as_a_repository_defect(
        self, unreachable_settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two heads means two revisions authored in parallel and never merged.

        ``alembic upgrade head`` refuses to run against that graph, so a deployment would fail later
        and less clearly. Reporting it here puts the diagnosis in the readiness response.
        """
        scripts = _branched_migrations(tmp_path)
        monkeypatch.chdir(tmp_path)
        assert migrations_module.find_script_directory() == scripts
        status = migrations_module.verify_schema_head(unreachable_settings)
        assert status.state == "multiple_heads"
        assert "merge revision" in status.detail
        assert set((status.head or "").split(", ")) == {"aaaa1", "aaaa2"}

    def test_the_script_directory_is_found_from_the_repository(self) -> None:
        found = migrations_module.find_script_directory()
        assert found is not None
        assert (found / "env.py").is_file()
        assert (found / "versions" / "0001_initial_schema.py").is_file()


@pytest.mark.integration
class TestVerifySchemaHeadAgainstAServer:
    def test_a_migrated_database_is_current(self, scratch_database: str) -> None:
        with _configured(scratch_database):
            status = migrations_module.verify_schema_head()
        assert status.state == "current"
        assert status.applied == status.head == HEAD_REVISION
        assert HEAD_REVISION in status.detail

    def test_a_database_one_revision_behind_says_how_many_are_pending(
        self, scratch_database: str
    ) -> None:
        """The detail names the revisions and the command, because this is read during a deployment
        by somebody who needs the next action, not a category label."""
        alembic_stamp(scratch_database, PREVIOUS_REVISION)
        try:
            with _configured(scratch_database):
                status = migrations_module.verify_schema_head()
            assert status.state == "behind"
            assert status.applied == PREVIOUS_REVISION
            assert status.head == HEAD_REVISION
            assert "2 revision(s) to apply" in status.detail
            assert "alembic upgrade head" in status.detail
        finally:
            # Stamp back, do not upgrade: this test only ever touched the version table, and the
            # schema already holds every revision. Running `upgrade head` from a stamped-behind
            # state would re-apply a revision to a database that already has its tables, and fail
            # on a relation that already exists — a failure in the restore, not in the subject.
            alembic_stamp(scratch_database, HEAD_REVISION)

    def test_a_revision_this_build_does_not_know_is_divergence_not_progress(
        self, scratch_database: str
    ) -> None:
        """A database *ahead* of the code is not "up to date".

        It means a release was rolled back after its migration ran, or the database was built from
        another branch. Serving traffic from that state is how a column the code does not know about
        ends up holding data nobody reads.
        """
        engine = create_engine(scratch_database)
        try:
            with engine.begin() as connection:
                connection.execute(text("UPDATE alembic_version SET version_num = 'deadbeef'"))
            with _configured(scratch_database):
                status = migrations_module.verify_schema_head()
            assert status.state == "diverged"
            assert status.applied == "deadbeef"
            assert status.head == HEAD_REVISION
            assert "rolled back" in status.detail
        finally:
            engine.dispose()
            restore = create_engine(scratch_database)
            try:
                with restore.begin() as connection:
                    connection.execute(
                        text("UPDATE alembic_version SET version_num = :head"),
                        {"head": HEAD_REVISION},
                    )
            finally:
                restore.dispose()

    def test_a_schema_downgraded_to_base_reports_not_migrated(self, maintenance_url: URL) -> None:
        """The state ``alembic downgrade base`` leaves: the table exists and holds no rows.

        Indexing an empty result here would raise out of a function that promises never to — during
        the readiness probe of a server that has just been rolled back, which is the worst moment to
        discover it.
        """
        with disposable_database(maintenance_url) as url:
            alembic_downgrade(url, "base", x_args=("allow_data_loss=true",))
            with _configured(url):
                status = migrations_module.verify_schema_head()
        assert status.state == "not_migrated"
        assert "empty" in status.detail
        assert "alembic upgrade head" in status.detail

    def test_a_database_that_was_never_migrated_says_so(self, maintenance_url: URL) -> None:
        name = f"tlx_unmigrated_{uuid7().int % 10**10}"
        admin = create_engine(maintenance_url, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as connection:
                connection.execute(text(f'CREATE DATABASE "{name}"'))
            url = maintenance_url.set(database=name).render_as_string(hide_password=False)
            try:
                with _configured(url):
                    status = migrations_module.verify_schema_head()
                assert status.state == "not_migrated"
                assert "no alembic_version table" in status.detail
            finally:
                with admin.connect() as connection:
                    connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        finally:
            admin.dispose()


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# The declarative base
# ══════════════════════════════════════════════════════════════════════════════════════════════════


class TestDeclarativeBase:
    def test_the_naming_convention_covers_every_constraint_kind(self) -> None:
        """DB-7: deterministic names, so a migration can drop the constraint it means to drop.

        Without a convention SQLAlchemy derives names from a hash of the column expressions, so the
        same change can produce a different name on a different machine — and renaming a constraint
        later means dropping and recreating it on a table that holds evidence.
        """
        assert {"ix", "uq", "ck", "fk", "pk"} <= set(NAMING_CONVENTION)

    def test_the_mixins_supply_the_columns_they_claim(self) -> None:
        assert {"created_at", "updated_at"} <= set(TimestampMixin.__annotations__)
        assert {"deleted_at"} <= set(SoftDeleteMixin.__annotations__)

    def test_this_layer_does_not_import_the_models(self) -> None:
        """§4.1 rule 7: ``app.db`` provides sessions, not queries.

        Models import the declarative base from here, so this package importing them would be a cycle
        — and would put knowledge of what a case is into the one layer every other layer depends on.
        """
        for module in (
            base_module,
            session_module,
            transaction_module,
            migrations_module,
            uuid7_module,
        ):
            source_file = module.__file__
            assert source_file is not None, f"{module.__name__} has no file to read"
            path = Path(source_file)
            assert "app.models" not in path.read_text(encoding="utf-8"), (
                f"{path.name} imports the models"
            )


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# helpers
# ══════════════════════════════════════════════════════════════════════════════════════════════════


def _record_engine_construction(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture what :func:`build_engine` asks ``create_engine`` for, then do it for real.

    An ``Engine`` does not expose the ``connect_args`` it was built with, and the libpq arguments are
    the whole subject of these two tests — so the call is recorded rather than inferred.
    """
    calls: list[dict[str, Any]] = []

    def recording_create_engine(*args: Any, **kwargs: Any) -> Engine:
        calls.append(kwargs)
        # The name imported at the top of this module is the same function object app.db.session
        # imported, so calling it here calls the real one while the module's own binding is patched.
        return create_engine(*args, **kwargs)

    # By dotted path: app.db.session declares __all__, and create_engine is deliberately not in it —
    # an implementation detail this module imports, not part of the layer's public surface.
    monkeypatch.setattr("app.db.session.create_engine", recording_create_engine)
    return calls


def _user(email: str) -> User:
    """A user with every column that has no server default supplied."""
    return User(
        email=email,
        full_name="Test Investigator",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$notarealdigestvalue",
        password_changed_at=datetime.now(UTC),
    )


def _exhaust(sessions: Iterator[Session]) -> None:
    """Run the dependency's teardown, which is where its guarantees live."""
    with pytest.raises(StopIteration):
        next(sessions)


def _count_users(url: str, email: str) -> int:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return int(
                one(
                    connection.execute(
                        text("SELECT count(*) FROM users WHERE email = :email"), {"email": email}
                    )
                )
            )
    finally:
        engine.dispose()


def _write_then_fail(session: Session, slug: str) -> None:
    """Write inside ``atomic()`` and then fail, so the rollback has something to undo.

    A helper rather than two statements inside ``pytest.raises``: with the write and the raise in the
    same block, a test can pass because the *raise* propagated and never notice that the write was
    not rolled back.
    """
    with atomic(session):
        session.execute(
            text("INSERT INTO organisations (slug, name) VALUES (:slug, 'Abort')"), {"slug": slug}
        )
        raise RuntimeError("aborted mid-write")


def _slug_count(connection: Any, slug: str) -> int:
    return int(
        one(
            connection.execute(
                text("SELECT count(*) FROM organisations WHERE slug = :slug"), {"slug": slug}
            )
        )
    )


def _branched_migrations(root: Path) -> Path:
    """A minimal migration tree with two heads, for the branched-graph test."""
    scripts = root / "migrations"
    versions = scripts / "versions"
    versions.mkdir(parents=True)
    (scripts / "env.py").write_text(
        "# a stub env.py is all find_script_directory looks for\n", encoding="utf-8"
    )
    for revision in ("aaaa1", "aaaa2"):
        (versions / f"{revision}_branch.py").write_text(
            f'''"""Branch {revision} — exists only so the graph has two heads."""

revision = "{revision}"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Nothing to build."""


def downgrade() -> None:
    """Nothing to undo."""
''',
            encoding="utf-8",
        )
    return scripts
