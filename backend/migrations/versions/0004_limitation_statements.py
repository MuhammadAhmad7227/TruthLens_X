"""Create ``limitation_statements`` and seed the AR-4 disclaimer corpus.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-15

``DATABASE_DESIGN.md`` §5.3 is the last table M2 owes. ``analysis_results.limitations_code`` has been
``NOT NULL`` since revision ``0001`` — AR-4's rule that a finding which cannot state its limits is not
a finding — but until now the code named nothing. This revision builds the corpus it names.

What §5.3 asks for
------------------
Six columns, no surrogate key: ``(code, version)`` is the primary key, ``text_en`` is the exact
disclaimer the UI and the reports render, ``effective_from``/``effective_to`` are the window it was in
force, and ``approved_by`` records who signed the wording off. Nothing else is added. The versioning
is the point of the table: wording gets corrected, and a correction must be a new row rather than an
edit, so a report generated years after a result still prints the disclaimer that was in force when
the result was created. §5.3's heading calls that staying truthful retroactively, and an editable
single-row-per-code table could not do it.

Why the seed arrives in the same revision
-----------------------------------------
§11(1) says one logical change per revision, and §11(6) says reference data arrives as a versioned
data migration rather than an ad-hoc script. Both are satisfied by treating "the AR-4 corpus exists"
as the single change: the table has no purpose without its rows, and shipping it empty would leave
every environment with a ``limitations_code`` that resolves to nothing until somebody remembered to
run an insert. Revision ``0002`` split schema from seed because it was seeding tables revision
``0001`` had created; here the table and its corpus are written together for the first time.

What is seeded, and what deliberately is not
--------------------------------------------
**Seeded: the four statements whose wording the documentation ratifies.** ``MASTER_PRD.md`` AR-4
gives the ELA, deepfake, ALPR and ASR disclaimers verbatim, and §5.3 names exactly those codes first
in its list. Each is inserted at version 1 with the text transcribed character for character, so the
database holds the ratified wording rather than a paraphrase of it. ``tests/db/test_migrations.py``
asserts that against the document itself: a seeded statement whose text has drifted from AR-4 fails
the suite, which is the only way "fixed, versioned statement" can mean anything.

**Not seeded: ``DQT``, ``COPY_MOVE``, ``GEO_PLAUSIBILITY`` and the rest of §5.3's list.** The
ellipsis in §5.3 says the list is illustrative, and no document in ``docs/`` ratifies wording for
those three — the engines that need them (JPEG quantisation fingerprinting and copy-move detection in
M9, geographic plausibility in M8) do not exist yet, and a disclaimer is a statement about what a
specific engine cannot do. Writing one now would be inventing text nobody has reviewed and attaching
it to behaviour nobody has built. Each arrives with its engine, as its own data migration, which is
what §11(6) asks for. This is the same posture revision ``0002`` took with ``role_permissions``: the
vocabulary now, the content when the decision belongs to this milestone.

``approved_by`` is NULL on all four. No account exists when a fresh database is built, so there is
nobody to attribute them to; their approval of record is the ratified text of AR-4 itself. A later
revision that amends a statement names its approver, which is when attribution becomes meaningful.

``effective_from`` is the date of this revision rather than ``now()`` and rather than NULL. §13(6)
requires every environment to end up identical, and a seeded window that depends on the clock of the
machine running the migration is not identical anywhere; a NULL bound would install a corpus that
claims to have been in force before the platform existed.

Downgrading
-----------
Dropping the table removes the corpus, and the seeded rows come back on the next upgrade — so a
downgrade of a database holding nothing but the seed is a clean reversal and is allowed. Rows this
revision did not write are a different matter: they are wording an operator or a later migration
approved, with an effective window and an approver attached, and reports may already have printed
them. Those are refused unless the operator passes ``-x allow_data_loss=true``, the same flag
revisions ``0001`` and ``0003`` consult.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy import inspect
from sqlalchemy.engine import Connection

#: One revision id, referenced by name so a rename cannot silently detach it from its file.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The table this revision owns — its creation, its corpus, and its data-loss guard.
TABLE: str = "limitation_statements"

#: The date of this revision, used as the lower bound of every seeded window. A literal rather than
#: ``now()`` so that two environments built from the same migrations hold byte-identical corpora
#: (§13(6)); see the module docstring.
CORPUS_EFFECTIVE_FROM: datetime = datetime(2026, 11, 15, tzinfo=UTC)

#: The AR-4 corpus, transcribed verbatim from ``MASTER_PRD.md``. ``(code, version, text_en)``.
#:
#: A tuple of literals rather than something derived at run time: a revision is a snapshot of what was
#: true when it was written, and the wording here is the wording that was ratified. ``effective_to``
#: is absent because every seeded statement is still current — a superseded version is a row a later
#: revision closes, not one this revision predicts.
SEEDED_STATEMENTS: tuple[tuple[str, int, str], ...] = (
    (
        "ELA",
        1,
        "Error Level Analysis highlights recompression inconsistency. Legitimate operations "
        "(cropping, saving, platform re-encoding, screenshotting) produce the same signature. It "
        "does not establish manipulation.",
    ),
    (
        "DEEPFAKE",
        1,
        "No deepfake detector is reliable in the wild. Authentic media that has been compressed, "
        "resized, or transcoded by messaging platforms frequently produces these indicators, and "
        "high-quality synthetic media frequently does not. This output must not be used as the sole "
        "basis for any conclusion.",
    ),
    (
        "ALPR",
        1,
        "Character recognition degrades sharply with motion blur, low resolution, oblique angle, "
        "glare, and non-standard plate formats. Top-N candidates are shown; human confirmation is "
        "required.",
    ),
    (
        "ASR",
        1,
        "Transcription errors are common with noise, accents, overlapping speakers, and low-bitrate "
        "audio. Timestamps are approximate.",
    ),
)


def _data_loss_permitted() -> bool:
    """True only when the operator said so on the command line.

    ``alembic -x allow_data_loss=true downgrade <target>`` — the same flag revisions ``0001``,
    ``0002`` and ``0003`` consult. Duplicated rather than imported for the reason ``0002`` gives: a
    revision is a snapshot, and importing a helper from another revision would make this one's
    behaviour depend on code that may itself be edited later.
    """
    value = context.get_x_argument(as_dictionary=True).get("allow_data_loss", "")
    return value.strip().lower() == "true"


def _unseeded_statements(bind: Connection) -> list[str]:
    """The statement versions in the table that this revision did not write.

    ``EXISTS``-style short-circuit first: if the table is not there — a downgrade re-run against a
    database where a previous attempt already dropped it — there is nothing to protect and nothing to
    report. The rows are read whole rather than counted, because the refusal message has to name what
    would be lost for the message to be actionable.
    """
    if TABLE not in inspect(bind).get_table_names():
        return []
    seeded = {(code, version) for code, version, _ in SEEDED_STATEMENTS}
    rows = bind.execute(sa.text(f'SELECT code, version FROM "{TABLE}"')).all()
    return [f"{code} v{version}" for code, version in rows if (code, version) not in seeded]


def _refuse_data_loss(bind: Connection) -> None:
    """Raise unless this downgrade can proceed without destroying approved wording."""
    if _data_loss_permitted():
        return
    extra = _unseeded_statements(bind)
    if not extra:
        return
    preview = ", ".join(extra[:8]) + ("…" if len(extra) > 8 else "")
    raise RuntimeError(
        f"refusing to downgrade revision 0004: {TABLE} holds {len(extra)} statement version(s) this "
        f"revision did not seed ({preview}). Those are approved disclaimers with an effective window "
        "and an approver attached, and reports may already have printed them; dropping the table "
        "destroys the record of what readers were told, which DATABASE_DESIGN §5.3 exists to keep. "
        "Remove or re-home them first. For a deliberate, backed-up teardown re-run with: "
        "alembic -x allow_data_loss=true downgrade <target>"
    )


def upgrade() -> None:
    """Create the table and insert the corpus.

    Expand-only, like every other revision here: nothing existing is altered, so a deployment can run
    this while the previous build is still serving (§11(4)).
    """
    op.create_table(
        TABLE,
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("text_en", sa.Text(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        # §5.3 names no constraints. These four are what the columns need to do what §5.3 says they
        # do, and each is recorded in backend/migrations/README.md.
        sa.CheckConstraint(
            "btrim(code) <> ''", name=op.f("ck_limitation_statements_code_is_not_blank")
        ),
        sa.CheckConstraint(
            "version >= 1", name=op.f("ck_limitation_statements_version_is_at_least_one")
        ),
        sa.CheckConstraint(
            "btrim(text_en) <> ''",
            name=op.f("ck_limitation_statements_statement_text_is_not_blank"),
        ),
        sa.CheckConstraint(
            "effective_from IS NULL OR effective_to IS NULL OR effective_to >= effective_from",
            name=op.f("ck_limitation_statements_window_does_not_end_before_it_starts"),
        ),
        sa.ForeignKeyConstraint(
            ["approved_by"],
            ["users.id"],
            name=op.f("fk_limitation_statements_approved_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("code", "version", name=op.f("pk_limitation_statements")),
    )
    # No index beyond the primary key. The resolution query filters on ``code`` first, which the
    # ``(code, version)`` key already leads with, and the corpus is dozens of rows: an index here
    # would be maintenance with nothing to speed up.

    bind = op.get_bind()
    for code, version, text_en in SEEDED_STATEMENTS:
        # ON CONFLICT DO NOTHING, as in revision 0002: re-running the revision converges instead of
        # failing, and an operator who already inserted the corpus by hand is not overwritten.
        bind.execute(
            sa.text(
                f'INSERT INTO "{TABLE}" (code, version, text_en, effective_from, effective_to, '
                "approved_by) VALUES (:code, :version, :text_en, :effective_from, NULL, NULL) "
                "ON CONFLICT (code, version) DO NOTHING"
            ),
            {
                "code": code,
                "version": version,
                "text_en": text_en,
                "effective_from": CORPUS_EFFECTIVE_FROM,
            },
        )


def downgrade() -> None:
    """Drop the corpus, refusing first if it holds wording this revision did not seed.

    The check runs before the DROP, so a refusal leaves the schema exactly as it was rather than
    half-removed.
    """
    _refuse_data_loss(op.get_bind())
    op.drop_table(TABLE)
