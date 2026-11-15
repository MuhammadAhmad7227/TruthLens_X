"""Fixtures for the database suite.

Two kinds of test live in this directory and they are kept apart deliberately.

**Metadata tests** need no database at all. They import the models and inspect ``Base.metadata``:
primary keys, foreign keys, unique constraints, relationship directions, timestamp columns, the
absence of any column that could hold a plaintext password or an evidence binary. Those run
everywhere, always — including in an environment with no PostgreSQL — because a schema defect should
not be able to hide behind a missing service.

**Integration tests** need a real PostgreSQL. They prove what metadata cannot: that the migration
builds the schema from an empty database, that the CHECK constraints actually refuse a dishonest
finding, that the write-once trigger fires, that ``alembic check`` sees no drift, that a downgrade
refuses to destroy data. They are marked ``integration`` and **skip with a reason** when no database
is reachable. Skipping is not passing; the M2 report states plainly what was and was not executed.

Where the database comes from
-----------------------------
``TLX_TEST_DATABASE_URL``. Not ``DATABASE_URL``: the root ``conftest.py`` has an autouse
``hermetic_env`` fixture that deletes ``DATABASE_URL`` so no test can pick up a developer's ambient
configuration, and that is right. A test database is a different thing from an application database —
a test run must never point at one that holds real data — so it gets its own variable, which also
survives ``hermetic_env``.

The URL points at a *maintenance* database (any database on the target server). Each session creates
its own scratch database, migrates it, and drops it afterwards, so repeated or parallel runs cannot
collide and nothing is left behind. ``CREATE DATABASE`` needs the privilege; if the configured role
lacks it, the integration tests skip with that reason rather than failing.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, Result, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import reset_settings

#: tests/db/conftest.py -> db -> tests -> backend
BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

#: How long to wait for the server before declaring it unreachable. Short: this is a skip decision,
#: not a retry loop, and a CI job should not spend a minute discovering there is no database.
PROBE_TIMEOUT_SECONDS = 5

TEST_DATABASE_URL_ENV = "TLX_TEST_DATABASE_URL"


def configured_url() -> URL | None:
    """The configured test-database URL, or ``None`` when it is absent or unparsable."""
    raw = os.environ.get(TEST_DATABASE_URL_ENV, "").strip()
    if not raw:
        return None
    try:
        return make_url(raw)
    except (SQLAlchemyError, ValueError):
        return None


def unavailability_reason(url: URL | None) -> str | None:
    """Why the integration tests cannot run, or ``None`` when they can."""
    if url is None:
        return (
            f"{TEST_DATABASE_URL_ENV} is not set (or is not a valid SQLAlchemy URL), so there is no "
            "PostgreSQL to test against"
        )
    probe = create_engine(
        url, pool_pre_ping=False, connect_args={"connect_timeout": PROBE_TIMEOUT_SECONDS}
    )
    try:
        with probe.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # a probe reports; it does not propagate
        return f"PostgreSQL at {url.render_as_string(hide_password=True)} is not reachable: {exc}"
    finally:
        probe.dispose()
    return None


def one(result: Result[Any]) -> Any:
    """The first column of the single row of ``result``, asserting that there is exactly one.

    ``Result.scalar_one()`` carries a type parameter mypy cannot bind for a ``text()`` statement, so
    under ``--strict`` it demands an annotation at every call site — forty-odd times across these
    tests. Saying it once here keeps the call sites readable *and* keeps the "exactly one row" check
    that ``scalar_one()`` was providing.
    """
    rows = result.all()
    assert len(rows) == 1, f"expected exactly one row, got {len(rows)}"
    return rows[0][0]


def scalars(result: Result[Any]) -> list[Any]:
    """The first column of every row of ``result``, for the same reason as :func:`one`."""
    return [row[0] for row in result.all()]


@pytest.fixture(scope="session")
def maintenance_url() -> URL:
    """A reachable server's maintenance database, or a skip explaining why there is none."""
    url = configured_url()
    reason = unavailability_reason(url)
    if url is None or reason is not None:
        pytest.skip(reason or f"{TEST_DATABASE_URL_ENV} is not set")
    return url


@contextmanager
def _settings_pointing_at(url: str) -> Iterator[None]:
    """Point the application's own configuration at ``url`` for the duration of the block.

    ``migrations/env.py`` resolves the connection string from ``app.core.config`` — Alembic has no
    second configuration system — so driving a migration from a test means driving it through the
    same settings object the API uses. ``reset_settings()`` on both sides keeps the cached singleton
    from leaking one test's database into another.
    """
    previous = os.environ.get("DATABASE_URL")
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


def alembic_upgrade(url: str, target: str = "head") -> None:
    """Run ``alembic upgrade <target>`` against ``url``.

    The script location comes from ``alembic.ini`` (``%(here)s/migrations``), so this is independent
    of the working directory pytest was invoked from.
    """
    from alembic import command  # noqa: PLC0415 - alembic ships in the optional db extra
    from alembic.config import Config  # noqa: PLC0415

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    with _settings_pointing_at(url):
        command.upgrade(config, target)


def alembic_downgrade(url: str, target: str, *, x_args: tuple[str, ...] = ()) -> None:
    """Run ``alembic downgrade <target>``, optionally with ``-x key=value`` arguments.

    ``EnvironmentContext.get_x_argument()`` reads ``config.cmd_opts.x`` — the parsed argparse
    namespace — so a programmatic run has to supply that attribute itself. Passing the arguments
    this way exercises exactly the code path the migration reads, including
    ``-x allow_data_loss=true``.
    """
    from argparse import Namespace  # noqa: PLC0415

    from alembic import command  # noqa: PLC0415
    from alembic.config import Config  # noqa: PLC0415

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    if x_args:
        config.cmd_opts = Namespace(x=list(x_args))
    with _settings_pointing_at(url):
        command.downgrade(config, target)


def alembic_stamp(url: str, revision: str) -> None:
    """Set the recorded revision without running anything.

    Used to prove the seed revision is idempotent: stamping back to ``0001`` and upgrading again runs
    the seed inserts a second time against rows that already exist.
    """
    from alembic import command  # noqa: PLC0415
    from alembic.config import Config  # noqa: PLC0415

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    with _settings_pointing_at(url):
        command.stamp(config, revision)


def alembic_check(url: str) -> str | None:
    """Run ``alembic check``; return the drift report, or ``None`` when models and schema agree.

    This is the §11 gate in callable form: it asks Alembic to autogenerate against the *migrated*
    database and reports anything it would change. A non-empty result means the models and the
    migration have diverged — the schema in production would not be the schema the code expects.
    """
    from alembic import command  # noqa: PLC0415
    from alembic.config import Config  # noqa: PLC0415
    from alembic.util.exc import AutogenerateDiffsDetected  # noqa: PLC0415

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    with _settings_pointing_at(url):
        try:
            command.check(config)
        except AutogenerateDiffsDetected as exc:
            return "\n".join(str(diff) for diff in exc.diffs) or str(exc)
    return None


#: How long a migration subprocess may take. Generous: it runs three revisions against a server that
#: may be starting up, and a timeout that fires during a legitimate slow run reads as a failure of the
#: migration rather than of the machine.
ALEMBIC_SUBPROCESS_TIMEOUT_SECONDS = 300


def alembic_in_a_fresh_process(url: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the ``alembic`` CLI in a separate process, exactly as a deployment runs it.

    Not a convenience wrapper around :func:`alembic_upgrade`, and the difference is the whole point.
    SQLAlchemy memoises which enum types it has already emitted ``CREATE TYPE`` for *per process*, so
    applying a revision twice inside one interpreter can succeed where the same two invocations in two
    processes fail. Revision 0003 did exactly that: ``upgrade head`` from an empty database worked,
    while ``0002 -> head`` — the path every real deployment takes — died with
    ``type "integrity_status" already exists``. An in-process test of that path passed with the defect
    in place, which is why this helper exists.

    The URL travels as ``DATABASE_URL`` because ``migrations/env.py`` resolves it through
    ``app.core.config`` rather than reading a variable of its own; the subprocess gets a copy of the
    environment with that one key set, so the root ``conftest.py``'s hermetic-env fixture (which
    deletes ``DATABASE_URL`` in *this* process) is respected rather than fought.
    """
    environment = {**os.environ, "DATABASE_URL": url}
    return subprocess.run(  # noqa: S603 - a fixed interpreter and our own alembic.ini, no shell
        [sys.executable, "-m", "alembic", *arguments],
        cwd=str(BACKEND_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=ALEMBIC_SUBPROCESS_TIMEOUT_SECONDS,
        check=False,
    )


@contextmanager
def disposable_database(maintenance_url: URL) -> Iterator[str]:
    """Create a private database, migrate it to head, yield its URL, drop it again.

    The downgrade-lifecycle tests cannot share a session-scoped database: they tear the schema down,
    and a torn-down database is no use to whatever test runs next.
    """
    name = f"tlx_m2_test_{uuid4().hex[:12]}"
    scratch = maintenance_url.set(database=name)
    admin = create_engine(maintenance_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            try:
                connection.execute(text(f'CREATE DATABASE "{name}"'))
            except SQLAlchemyError as exc:
                pytest.skip(
                    f"cannot create a scratch database as {maintenance_url.username}: {exc}. The "
                    "integration tests need a role with CREATEDB."
                )
    finally:
        admin.dispose()

    url = scratch.render_as_string(hide_password=False)
    try:
        alembic_upgrade(url)
        yield url
    finally:
        teardown = create_engine(maintenance_url, isolation_level="AUTOCOMMIT")
        try:
            with teardown.connect() as connection:
                # WITH (FORCE) disconnects anything still holding the database — a leaked pooled
                # connection would otherwise make the DROP fail and leave scratch databases behind.
                connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        finally:
            teardown.dispose()


@pytest.fixture(scope="session")
def scratch_database(maintenance_url: URL) -> Iterator[str]:
    """A private database, migrated to head, dropped afterwards.

    One per session rather than one per test: building the schema takes about a second, and per-test
    isolation comes from the transaction rollback in :func:`db_session`, not from rebuilding
    twenty-two tables every time.
    """
    with disposable_database(maintenance_url) as url:
        yield url


@pytest.fixture(scope="session")
def scratch_engine(scratch_database: str) -> Iterator[Engine]:
    """A session-scoped engine on the scratch database (used by the migration-lifecycle tests)."""
    engine = create_engine(scratch_database)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_engine(scratch_database: str) -> Iterator[Engine]:
    """An engine on the scratch database, disposed after the test."""
    engine = create_engine(scratch_database)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """A session whose work is rolled back when the test ends.

    The session joins an outer transaction the fixture owns, with
    ``join_transaction_mode="create_savepoint"``. That is what makes it possible to test code which
    calls ``commit()`` — :func:`app.db.transaction.atomic` does, and so does the application — while
    leaving the database exactly as the migration left it. A commit inside the test releases a
    savepoint; the fixture's rollback undoes everything.

    Tests asserting that a constraint *refuses* a row use ``atomic()`` themselves, so a refusal costs
    only a savepoint and the rest of the test continues on the same session.
    """
    with db_engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()


@pytest.fixture
def seeded(db_session: Session) -> dict[str, object]:
    """The reference rows migration ``0002`` seeded, keyed for convenience."""
    roles: dict[str, UUID] = {}
    for code, identifier in db_session.execute(text("SELECT code::text, id FROM roles")).all():
        roles[str(code)] = UUID(str(identifier))
    permissions: dict[str, UUID] = {}
    for code, identifier in db_session.execute(text("SELECT code, id FROM permissions")).all():
        permissions[str(code)] = UUID(str(identifier))
    organisation = one(
        db_session.execute(text("SELECT id FROM organisations WHERE slug = 'org_default'"))
    )
    return {
        "roles": roles,
        "permissions": permissions,
        "organisation": UUID(str(organisation)),
    }
