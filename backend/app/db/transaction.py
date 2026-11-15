"""Explicit transaction handling — the only place this application commits.

``SYSTEM_ARCHITECTURE.md`` §4.1(2) gives transactions to the service layer, so the request-scoped
session dependency (:func:`app.db.session.get_session`) never commits. This module is what a service
uses instead, and it exists because "commit at the end of the request" and "commit at the end of the
unit of work" are different boundaries, and only the second one is reusable from a worker.

Nesting
-------
:func:`atomic` is re-entrant. The outermost call owns the real transaction and commits it; an inner
call opens a ``SAVEPOINT`` and releases it. That distinction is what lets one service call another
without either of them having to know: if the inner unit of work fails, its writes are undone and
the caller can catch the exception, keep its own work, and continue. With a flat ``commit()`` at
every level, the inner failure would roll back the *caller's* writes too — or the caller would have
to be written to expect that, which is how transaction boundaries end up documented in a wiki
instead of in code.

A ``SAVEPOINT`` is a database round trip, so nesting is not free. It is the correct default anyway:
the alternative — silently committing someone else's partial work — is a correctness bug that only
appears under failure, which is precisely when nobody is looking.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import structlog
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import get_session_factory

__all__ = ["atomic", "session_scope"]

_logger = structlog.get_logger(__name__)

#: Nesting depth, per session, in ``Session.info`` — the dictionary SQLAlchemy provides for exactly
#: this kind of per-session bookkeeping. Keyed here rather than in a global so that two sessions in
#: one thread (a request and a worker it spawned) cannot see each other's depth.
_DEPTH_KEY = "truthlens.atomic_depth"


@contextmanager
def atomic(session: Session) -> Iterator[Session]:
    """Run a block as one transaction: commit on clean exit, roll back on any exception.

    The exception is always re-raised. Swallowing it would leave the caller believing a write
    happened, and a silently lost write to an evidential record is the failure this module exists
    to prevent.
    """
    depth: int = session.info.get(_DEPTH_KEY, 0)
    session.info[_DEPTH_KEY] = depth + 1
    try:
        if depth == 0:
            # Adopt the session's autobegun transaction if there is one, so a service that read
            # something before writing still commits the whole unit of work — and so this helper
            # does not raise "a transaction is already begun" on a session that has been used.
            if not session.in_transaction():
                session.begin()
            try:
                yield session
            except Exception:
                session.rollback()
                raise
            else:
                session.commit()
        else:
            savepoint = session.begin_nested()
            try:
                yield session
            except Exception:
                savepoint.rollback()
                _logger.debug("atomic_savepoint_rolled_back", depth=depth)
                raise
            else:
                savepoint.commit()
    finally:
        session.info[_DEPTH_KEY] = depth


@contextmanager
def session_scope(factory: sessionmaker[Session] | None = None) -> Iterator[Session]:
    """Open a session, run one transaction, close it — for workers, scripts and tests.

    This is the non-HTTP counterpart of the request dependency: same guarantees, without FastAPI.
    Celery tasks (M7) and maintenance scripts use this so that a task's writes are one transaction
    rather than one-per-statement, and so that a crashed task rolls back instead of leaving a
    half-written custody ledger.
    """
    resolved = factory or get_session_factory()
    session = resolved()
    try:
        with atomic(session):
            yield session
    finally:
        session.close()
