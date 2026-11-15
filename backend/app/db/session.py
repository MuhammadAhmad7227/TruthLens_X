"""Engine construction, the session factory, and the FastAPI session dependency.

Who owns the transaction
------------------------
``SYSTEM_ARCHITECTURE.md`` §4.1(2) says services own transactions and authorization decisions. This
module follows that literally: :func:`get_session` hands a request a ``Session`` and guarantees it
is rolled back on error and closed afterwards, but it **never commits**. A commit here would mean
the request boundary decides when a unit of work is durable, and the same service could then not be
reused from a Celery worker or a maintenance script without inheriting an HTTP-shaped transaction.

Committing is explicit, in :mod:`app.db.transaction` (:func:`atomic`). The cost of that choice is
that forgetting it loses the write, so the dependency detects the mistake and logs it rather than
letting the request end in silence — see the ``else`` branch below.

Engine lifecycle
----------------
The engine is a process-wide singleton created lazily on first use and disposed at application
shutdown. Creating an engine does not open a connection, so an unreachable database does not stop
the API from starting: ``/healthz`` keeps answering, and ``/readyz`` reports the database as
unavailable, which is the state an operator needs to see rather than a container that will not come
up. ``config.py`` already refuses to start in a production-like environment with no
``DATABASE_URL``, so fail-soft here cannot mask a production misconfiguration.
"""

from __future__ import annotations

from collections.abc import Generator
from threading import Lock
from typing import Any

import structlog
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.errors import DependencyUnavailableError

__all__ = [
    "DatabaseNotConfiguredError",
    "build_engine",
    "create_session_factory",
    "dispose_database",
    "get_engine",
    "get_session",
    "get_session_factory",
    "init_database",
    "is_database_configured",
    "require_database_url",
]

_logger = structlog.get_logger(__name__)

#: The SQLAlchemy dialect names that address PostgreSQL. Anything else is refused before a pool is
#: opened — see :func:`require_database_url`.
_POSTGRESQL_DIALECTS: frozenset[str] = frozenset({"postgresql", "postgres"})


class DatabaseNotConfiguredError(DependencyUnavailableError):
    """``DATABASE_URL`` is missing, or names something that is not PostgreSQL.

    A subclass of the 503 ``DEPENDENCY_UNAVAILABLE`` error so the existing exception handlers and
    problem-detail mapping apply unchanged, while the type itself says which dependency and why.
    """


def is_database_configured(settings: Settings | None = None) -> bool:
    """True when a usable ``DATABASE_URL`` is present. Never raises."""
    return bool((settings or get_settings()).database_url)


def require_database_url(settings: Settings | None = None) -> str:
    """The configured ``DATABASE_URL``, or a specific 503 explaining what is wrong.

    Also refuses a non-PostgreSQL scheme. ``DATABASE_DESIGN.md`` §11 targets PostgreSQL 16: the
    schema uses native enums, ``JSONB``, partial and generated-column indexes, ``NULLS NOT
    DISTINCT`` and a PL/pgSQL UUIDv7 function. Pointing it at SQLite would not fail loudly at
    connect time — it would fail at the first ``CREATE TYPE``, or worse, appear to work until a
    JSONB query returned nothing. Refusing the scheme is cheaper than any of those outcomes.
    """
    resolved = settings or get_settings()
    url = resolved.database_url
    if not url:
        raise DatabaseNotConfiguredError(
            "DATABASE_URL is not set",
            remediation=(
                "Set DATABASE_URL to a PostgreSQL connection string, for example "
                "postgresql+psycopg://tlx_app:<password>@postgres:5432/truthlens"
            ),
        )
    scheme = url.split("://", 1)[0].lower()
    # The dialect is the part before any "+driver": postgresql, postgres, postgresql+psycopg and
    # postgresql+asyncpg all name PostgreSQL, while "postgresql-typo" merely starts with the word.
    # A prefix test would accept it and defer the failure to create_engine, where the message names
    # a module rather than the configuration mistake.
    dialect = scheme.split("+", 1)[0]
    if dialect not in _POSTGRESQL_DIALECTS:
        raise DatabaseNotConfiguredError(
            f"DATABASE_URL scheme {scheme!r} is not supported; this schema targets PostgreSQL 16",
            remediation="Use a postgresql+psycopg:// connection string (DATABASE_DESIGN.md §11).",
        )
    return url


def build_engine(settings: Settings | None = None) -> Engine:
    """Create an :class:`~sqlalchemy.engine.Engine` from the application settings.

    Every pool parameter comes from ``config.py`` (``DB_POOL_SIZE``, ``DB_MAX_OVERFLOW``,
    ``DB_POOL_TIMEOUT_SECONDS``, ``DB_POOL_RECYCLE_SECONDS``, ``DB_STATEMENT_TIMEOUT_MS``,
    ``DB_ECHO``) — this module reads configuration, it does not invent a second way to express it.

    ``statement_timeout`` is set through libpq's ``options`` parameter rather than per query, so it
    applies to every statement on every connection from this engine, including ones written later by
    someone who has never heard of it. A runaway query against a table holding evidence competes
    with ingest for the same connections and the same disk.
    """
    resolved = settings or get_settings()
    url = require_database_url(resolved)

    connect_args: dict[str, Any] = {
        # libpq's own connect timeout, so a black-holed host fails fast instead of hanging for the
        # kernel's default. Bounded below at 1 because libpq treats 0 as "wait forever".
        "connect_timeout": max(1, int(resolved.db_pool_timeout_seconds)),
        "options": f"-c statement_timeout={int(resolved.db_statement_timeout_ms)}",
    }

    try:
        return create_engine(
            url,
            echo=resolved.db_echo,
            pool_pre_ping=True,
            pool_size=resolved.db_pool_size,
            max_overflow=resolved.db_max_overflow,
            pool_timeout=resolved.db_pool_timeout_seconds,
            pool_recycle=resolved.db_pool_recycle_seconds,
            connect_args=connect_args,
        )
    except ModuleNotFoundError as exc:
        # Distinct from "the database is down": this is a deployment image that does not match its
        # own configuration, and the operator action is different (rebuild with the `db` extra).
        raise DependencyUnavailableError(
            f"database driver is not installed ({exc.name})",
            remediation="Install the backend 'db' extra so the image matches DATABASE_URL.",
        ) from exc


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """A ``sessionmaker`` with the defaults this application wants.

    ``expire_on_commit=False`` is deliberate. With the default ``True``, every attribute read after
    a commit re-issues a SELECT — and in a request that commits and then serialises a response, that
    is a round trip per attribute on an object graph that is already correct in memory. It also
    makes post-commit access raise outside a session, which turns "return the thing I just wrote"
    into a lazy-loading bug.

    ``autoflush`` is left at SQLAlchemy's default of ``True``, which is the less obvious choice and
    the safer one: pending changes are flushed before a query runs, so a uniqueness violation is
    raised at the statement that caused it, where the code can still react. With autoflush off, the
    same violation surfaces at commit time, when the only remaining option is to fail the whole
    request — and the traceback points at the commit rather than at the write.
    """
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


#: Process-wide state. Guarded by a lock because the first request may arrive on any thread and
#: because a double-created engine would leak a connection pool that nothing ever disposes.
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None
_lock = Lock()


def init_database(settings: Settings | None = None) -> Engine:
    """Create (once) the process-wide engine and session factory. Idempotent."""
    global _engine, _session_factory  # noqa: PLW0603 - module singletons are the point here
    resolved = settings or get_settings()
    with _lock:
        if _engine is None:
            engine = build_engine(resolved)
            _engine = engine
            _session_factory = create_session_factory(engine)
            # The URL is never logged. structlog's redaction processor would strip a credential,
            # but not logging it in the first place is the guarantee that does not depend on a
            # processor being correctly configured.
            _logger.info(
                "database_engine_initialised",
                pool_size=resolved.db_pool_size,
                max_overflow=resolved.db_max_overflow,
                pool_recycle_seconds=resolved.db_pool_recycle_seconds,
                statement_timeout_ms=resolved.db_statement_timeout_ms,
            )
        return _engine


def get_engine() -> Engine:
    """The process-wide engine, creating it on first use."""
    if _engine is None:
        return init_database()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """The process-wide session factory, creating the engine on first use."""
    with _lock:
        factory = _session_factory
    if factory is None:
        init_database()
        factory = _session_factory
    if factory is None:  # pragma: no cover - init_database always assigns it
        raise DatabaseNotConfiguredError("the session factory could not be created")
    return factory


def dispose_database() -> None:
    """Dispose the engine and drop the process-wide state.

    Called from the application lifespan on shutdown, and by tests that need a clean slate. Disposal
    closes pooled connections; without it a worker that exits after a batch leaves the server
    holding idle connections until they time out.
    """
    global _engine, _session_factory  # noqa: PLW0603
    with _lock:
        engine, _engine = _engine, None
        _session_factory = None
    if engine is not None:
        engine.dispose()
        _logger.info("database_engine_disposed")


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency: one ``Session`` per request.

    Guarantees, in order: a session is created; if the request raised, the transaction is rolled
    back; if the request finished holding uncommitted changes, they are rolled back **and logged**;
    the session is always closed. It never commits — see the module docstring.

    A generator dependency (not ``async def``) because the driver is synchronous: ``psycopg`` in
    sync mode must not be awaited, and running it in the event loop thread is exactly what a sync
    generator dependency does. M2 does not use ``AsyncSession``; nothing in the schema or the
    milestone plan requires it, and mixing the two would mean two ways to hold a transaction.
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    except Exception:
        # Roll back before the exception propagates: the handler that turns it into a problem detail
        # must not run while the connection still holds locks or an aborted transaction.
        session.rollback()
        raise
    else:
        pending = bool(session.new or session.dirty or session.deleted)
        if pending:
            # The request ended with work nobody committed. Rolling back is the only safe action,
            # but doing it silently would make the write vanish with nothing to diagnose it from —
            # so say so, with the counts that identify which object graph was dropped.
            _logger.warning(
                "uncommitted_changes_at_request_end",
                new=len(session.new),
                dirty=len(session.dirty),
                deleted=len(session.deleted),
                remediation="wrap the write in app.db.transaction.atomic()",
            )
            session.rollback()
    finally:
        session.close()
