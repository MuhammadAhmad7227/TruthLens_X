"""Schema-head verification — the ``migrations`` readiness check (``DATABASE_DESIGN.md`` §11).

§11 makes "the database is at the revision this code expects" a deploy-time property, not a hope.
This module answers that question for ``/readyz``: it reads ``alembic_version`` from the database,
reads the head from the migration scripts on disk, and reports whether they agree.

Why the check cannot be "does the alembic_version table exist"
--------------------------------------------------------------
A database stamped at an older revision is the dangerous case. The application boots, the tables it
needs are mostly there, and the failure appears as a column that does not exist — raised from deep
inside a request, on the first code path that touches it. Reporting *behind* at readiness means the
deployment is stopped before traffic arrives, which is the whole point of a readiness probe being
distinct from a liveness probe.

The reverse case — a database *ahead* of the code, which happens when a release is rolled back
after its migration ran — is reported as ``diverged``, because it cannot honestly be told apart from
a database built from a different branch: the applied revision is not in this build's scripts, so
there is no history here to compare it against. §11's expand-and-contract rule is what makes that
state survivable (old code against a newer schema), and the detail says so, but deciding whether it
is safe belongs to whoever rolled the release back, not to a readiness probe.

Nothing here raises. A probe that throws takes ``/readyz`` down with it, and an endpoint that cannot
answer is worse than one that answers "unavailable".
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import structlog
from sqlalchemy import create_engine, inspect, text

from app.core.config import Settings, get_settings
from app.db.session import require_database_url

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["SchemaHeadState", "SchemaHeadStatus", "find_script_directory", "verify_schema_head"]

_logger = structlog.get_logger(__name__)

SchemaHeadState = Literal[
    "current",
    "behind",
    "diverged",
    "not_migrated",
    "multiple_heads",
    "unreachable",
    "not_configured",
]

#: Places the migration scripts may live, in order. The wheel packages only ``app``
#: (``[tool.hatch.build.targets.wheel] packages = ["app"]``), so in a container image the scripts
#: are *not* beside the installed package — they are in the copied source tree. Searching a small
#: ordered list of candidates covers the three layouts that actually occur: CI and local development
#: (CWD is ``backend/``), a container (CWD is the service root, scripts under ``backend/``), and an
#: editable install (scripts beside the package).
_CANDIDATE_RELATIVE_PATHS: tuple[tuple[str, ...], ...] = (
    ("migrations",),
    ("backend", "migrations"),
)


@dataclass(frozen=True, slots=True)
class SchemaHeadStatus:
    """The result of comparing the database's revision with the scripts' head.

    ``detail`` is written for an operator reading ``/readyz`` during a deployment, so it names the
    revisions and the command to run rather than describing a category.
    """

    state: SchemaHeadState
    detail: str
    applied: str | None = None
    head: str | None = None


def find_script_directory() -> Path | None:
    """Locate ``migrations/`` (the directory holding ``env.py`` and ``versions/``)."""
    roots: list[Path] = [Path.cwd()]
    here = Path(__file__).resolve()
    roots.extend(here.parents)

    for root in roots:
        for relative in _CANDIDATE_RELATIVE_PATHS:
            candidate = root.joinpath(*relative)
            if (candidate / "env.py").is_file() and (candidate / "versions").is_dir():
                return candidate
    return None


def _heads(script_directory: Path) -> tuple[str, ...]:
    """The revision identifiers at the tip of the migration graph."""
    # Local import: alembic ships in the optional `db` extra, and this module must import and report
    # honestly where it is absent — the same rule app/core/health.py follows for sqlalchemy.
    from alembic.script import ScriptDirectory  # noqa: PLC0415

    script = ScriptDirectory(str(script_directory))
    return tuple(script.get_heads())


def _history(script_directory: Path, head: str) -> list[str]:
    """Every revision from ``head`` down to the base, in reverse chronological order."""
    from alembic.script import ScriptDirectory  # noqa: PLC0415

    script = ScriptDirectory(str(script_directory))
    return [revision.revision for revision in script.walk_revisions(base="base", head=head)]


def _applied_revisions(url: str, settings: Settings) -> list[str] | None:
    """The rows in ``alembic_version``, or ``None`` when the table does not exist.

    Raises whatever the driver raises; :func:`verify_schema_head` catches it.
    """
    engine = None
    try:
        engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_timeout=settings.db_pool_timeout_seconds,
            connect_args={"connect_timeout": max(1, int(settings.db_pool_timeout_seconds))},
        )
        with engine.connect() as connection:
            if not inspect(connection).has_table("alembic_version"):
                return None
            rows: Sequence[Any] = (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
            )
            return [str(row) for row in rows]
    finally:
        if engine is not None:
            engine.dispose()


def verify_schema_head(  # noqa: PLR0911 - one return per state, and there are seven states
    settings: Settings | None = None,
) -> SchemaHeadStatus:
    """Compare the database's applied revision with the migration head. Never raises.

    The shape is a decision table rather than a nested branch: each guard names one way the database
    can be wrong and returns the status an operator can act on. Collapsing the returns to satisfy a
    count would nest the states inside each other, which is exactly what makes a probe like this hard
    to read when it reports something unexpected at 3am.
    """
    resolved = settings or get_settings()

    try:
        url = require_database_url(resolved)
    except Exception as exc:  # a probe reports; it does not propagate
        return SchemaHeadStatus(state="not_configured", detail=str(exc))

    script_directory = find_script_directory()
    if script_directory is None:
        return SchemaHeadStatus(
            state="not_configured",
            detail=(
                "no Alembic migrations directory was found; searched the working directory and the "
                "installed package path for migrations/env.py"
            ),
        )

    try:
        heads = _heads(script_directory)
    except Exception as exc:
        return SchemaHeadStatus(
            state="unreachable", detail=f"migration scripts could not be read: {exc}"
        )

    if not heads:
        return SchemaHeadStatus(
            state="not_configured",
            detail=f"no migration revisions exist under {script_directory}",
        )
    if len(heads) > 1:
        # A branched graph means two migrations were authored in parallel and never merged. It is a
        # repository defect, not a database defect, and `alembic upgrade head` refuses to run.
        return SchemaHeadStatus(
            state="multiple_heads",
            detail=f"migration graph has {len(heads)} heads ({', '.join(sorted(heads))}); "
            "create a merge revision",
            head=", ".join(sorted(heads)),
        )
    head = heads[0]

    try:
        applied_rows = _applied_revisions(url, resolved)
    except ModuleNotFoundError as exc:
        return SchemaHeadStatus(
            state="unreachable",
            detail=f"database driver is not installed ({exc.name}); install the 'db' extra",
            head=head,
        )
    except Exception as exc:
        return SchemaHeadStatus(
            state="unreachable",
            detail=f"{type(exc).__name__}: {exc}",
            head=head,
        )

    if not applied_rows:
        # Covers both "no alembic_version table" and "the table exists but is empty" — which is
        # exactly what `alembic downgrade base` leaves behind. Indexing an empty list here would
        # raise out of a function that promises never to, and would do it during the readiness probe
        # of a server that has just been rolled back.
        reason = (
            "database has no alembic_version table"
            if applied_rows is None
            else "alembic_version is empty — the schema has been downgraded to base"
        )
        return SchemaHeadStatus(
            state="not_migrated",
            detail=f"{reason}; run: alembic upgrade head ({head})",
            head=head,
        )
    if len(applied_rows) > 1:
        return SchemaHeadStatus(
            state="diverged",
            detail=(
                f"alembic_version holds {len(applied_rows)} rows "
                f"({', '.join(sorted(applied_rows))}) but the graph has one head; "
                "the database was stamped from a branched history"
            ),
            applied=", ".join(sorted(applied_rows)),
            head=head,
        )

    applied = applied_rows[0]
    if applied == head:
        return SchemaHeadStatus(
            state="current", detail=f"schema is at head {head}", applied=applied, head=head
        )

    try:
        history = _history(script_directory, head)
    except Exception as exc:
        return SchemaHeadStatus(
            state="diverged",
            detail=f"migration history could not be read: {exc}",
            applied=applied,
            head=head,
        )

    if applied in history:
        pending = len(history[: history.index(applied)])
        return SchemaHeadStatus(
            state="behind",
            detail=(
                f"schema is at {applied}, head is {head} ({pending} revision(s) to apply); "
                "run: alembic upgrade head"
            ),
            applied=applied,
            head=head,
        )

    return SchemaHeadStatus(
        state="diverged",
        detail=(
            f"schema is at {applied}, which this build does not know (its head is {head}); the "
            "database is either ahead of this code — a release rolled back after its migration ran "
            "— or was built from a different branch. §11's expand-and-contract rule makes the first "
            "case survivable; neither is a state to serve traffic from without a decision"
        ),
        applied=applied,
        head=head,
    )
