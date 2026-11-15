"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

Every revision in this directory is a reviewed artifact, not a generated one. ``DATABASE_DESIGN.md``
§11 requires one logical change per revision, human review of whatever autogenerate produced, and a
downgrade that does not silently destroy data — see ``migrations/README.md`` before editing this
file.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

#: One revision id, referenced by name so a rename cannot silently detach it from its file.
revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    """Apply the change.

    Expand first, contract later: a revision that stops writing to a column and a revision that
    drops it are two revisions, never one (§11). A single deploy must be reversible while the
    previous build is still running.
    """
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """Reverse the change, without silently destroying data.

    Dropping a table or column that holds evidence, custody history or audit records is not a
    downgrade — it is data loss wearing a downgrade's clothes. Where a reversal genuinely cannot
    preserve data, this function must raise and say what has to be done instead (§11, and
    ``migrations/README.md`` §"Downgrade strategy").
    """
    ${downgrades if downgrades else "pass"}
