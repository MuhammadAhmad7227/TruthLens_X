"""Alembic environment — the bridge between the migration scripts and the application's models.

Three decisions here are load-bearing.

**The URL comes from the application's settings.** ``require_database_url(get_settings())`` resolves
``DATABASE_URL`` through the same Pydantic Settings object the API uses, so a migration cannot run
against a database the application does not connect to. ``alembic.ini`` therefore contains no
``sqlalchemy.url``. To migrate as the ``tlx_migrator`` role rather than as ``tlx_app``
(``DATABASE_DESIGN.md`` §11, and the grants in ``infra/postgres/initdb``), export a
``DATABASE_URL`` naming that role for the duration of the command — see ``migrations/README.md``.

**No connection pool, and no statement timeout.** The application engine in ``app/db/session.py``
sets ``statement_timeout`` from ``DB_STATEMENT_TIMEOUT_MS`` (30s by default) because a runaway query
in a request path competes with ingest for connections. A migration is not in a request path: an
index build on a table holding years of evidence may legitimately take ten minutes, and killing it
at thirty seconds leaves a half-built index and a failed deploy. ``NullPool`` opens one connection
and closes it, because a migration is a short-lived process that has no business holding pooled
connections open.

**``compare_type=True``.** Without it ``alembic check`` — the drift gate §11 requires in CI — cannot
see a column whose type changed in a model but not in a migration, which is exactly the drift the
gate exists to catch. ``compare_server_default`` is left off, deliberately: PostgreSQL normalises a
stored default (``'investigator'::global_role``) into a form that rarely round-trips byte-for-byte
against the model's ``text("'investigator'")``, so enabling it produces phantom drift — and a gate
that cries phantom is a gate people learn to ignore.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import Engine, create_engine, pool

from app.core.config import get_settings
from app.db.session import require_database_url
from app.models import metadata as target_metadata

#: Alembic's own config, read from alembic.ini.
config = context.config

if config.config_file_name is not None:
    # Configures the `logging` module only. The application uses structlog; migrations run as a
    # deploy step, frequently with no API process alive, and must not depend on one for their output.
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting ("offline" mode).

    Useful for reviewing exactly what a deploy will execute, and for handing DDL to a DBA who runs
    it under a different role. ``literal_bindings=True`` renders parameters inline, because there is
    no DBAPI connection to bind them to.
    """
    url = require_database_url(get_settings())
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_bindings=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and apply the pending revisions ("online" mode — the normal path)."""
    url = require_database_url(get_settings())
    connectable: Engine = create_engine(url, poolclass=pool.NullPool)

    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        # NullPool holds nothing after the connection closes, but disposing makes the intent explicit
        # and keeps a leaked connection from surviving until interpreter exit. In `finally` because a
        # migration that fails — including one that refuses on purpose, the way these revisions
        # refuse to destroy data — must not leave a connection open on the server it just declined
        # to change.
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
