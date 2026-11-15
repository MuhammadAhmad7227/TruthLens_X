"""What the migrations actually build — asserted against a real PostgreSQL server.

``tests/db/test_models.py`` proves the models describe a sound schema. This file proves something
different and not implied by it: that running ``alembic upgrade head`` on an empty database produces
*that* schema, that the constraints then refuse the rows they exist to refuse, that the seeded
reference data is there and is fail-closed, and that the whole thing can be taken apart and rebuilt.

That distinction is the reason §11 makes this a CI gate. A model is a description; a migration is a
set of statements PostgreSQL has to accept, in order, on a server that already contains something.
Generated columns have to be immutable, foreign keys have to point at unique targets that exist yet,
reserved words have to be avoided, and a CHECK constraint that reads correctly in Python may still be
vacuous in SQL. None of that is visible without a server, so these tests skip loudly when there is
none rather than quietly passing.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, Final, cast
from uuid import UUID

import pytest
from psycopg.errors import ForeignKeyViolation
from sqlalchemy import Enum as SAEnum, ForeignKeyConstraint, create_engine, inspect, text
from sqlalchemy.engine import URL, Engine
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.db.transaction import atomic
from app.models import metadata
from tests.db.conftest import (
    BACKEND_ROOT,
    alembic_check,
    alembic_downgrade,
    alembic_stamp,
    alembic_upgrade,
    disposable_database,
    one,
    scalars,
)

pytestmark = pytest.mark.integration

#: The revision the schema should be at after ``upgrade head``.
HEAD_REVISION: Final[str] = "0002"

#: §4.3's fourteen event types and SECURITY_ARCHITECTURE §4.1's six roles, spelled out here rather
#: than imported from the model: the point is to catch a model that has drifted from the document,
#: and a test importing the model cannot do that.
DOCUMENTED_ROLES: Final[tuple[str, ...]] = (
    "admin",
    "analyst",
    "auditor",
    "investigator",
    "lead_investigator",
    "reviewer",
)
DOCUMENTED_CAPABILITIES: Final[tuple[str, ...]] = (
    "view_case",
    "edit_case",
    "close_case",
    "reopen_case",
    "manage_members",
    "upload_evidence",
    "view_evidence",
    "view_evidence_content",
    "edit_evidence_metadata",
    "delete_evidence",
    "hard_delete_evidence",
    "analyze_evidence",
    "view_finding",
    "verify_finding",
    "create_comparison",
    "create_graph_edge",
    "verify_graph_edge",
    "create_timeline_event",
    "use_assistant",
    "export_reports",
    "generate_report",
    "approve_report",
    "read_audit",
    "verify_audit_chain",
    "manage_users",
    "manage_models",
    "manage_settings",
    "manage_queues",
    "break_glass",
    "enable_external_ai",
)
DOCUMENTED_CUSTODY_EVENTS: Final[tuple[str, ...]] = (
    "accessed",
    "analyzed",
    "custody_accepted",
    "custody_transferred",
    "downloaded",
    "exported",
    "hash_computed",
    "hash_verified",
    "ingested",
    "integrity_alert",
    "legal_hold",
    "quarantined",
    "released",
    "verification_set",
)

HEX: Final[str] = "0" * 64


# ── row builders ─────────────────────────────────────────────────────────────────────────────────
# Written as SQL rather than through the ORM on purpose: these tests assert what the *database*
# permits, and an ORM insert would quietly omit a column or apply a Python-side default that the
# server never sees.

INSERT_USER: Final[str] = """
INSERT INTO users (email, full_name, password_hash, password_changed_at)
VALUES (:email, 'Test Investigator',
        '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHR2YWx1ZQ$notarealdigestvalue', now())
RETURNING id
"""

INSERT_CASE: Final[str] = """
INSERT INTO cases (case_number, title, sensitivity, created_by)
VALUES (:case_number, :title, :sensitivity, :user_id)
RETURNING id
"""

INSERT_PHYSICAL_OBJECT: Final[str] = """
INSERT INTO physical_objects (sha256, size_bytes, storage_backend, storage_path,
                              detected_mime, encryption, written_at)
VALUES (:sha256, :size_bytes, 'filesystem', :storage_path, 'image/jpeg', :encryption, now())
RETURNING id
"""

INSERT_EVIDENCE: Final[str] = """
INSERT INTO evidence_items (case_id, physical_object_id, evidence_number, original_filename,
                            sanitized_filename, item_type, source_type, submitted_by)
VALUES (:case_id, :physical_object_id, :evidence_number, :original_filename,
        :sanitized_filename, 'image', 'upload', :user_id)
RETURNING id
"""

INSERT_JOB: Final[str] = """
INSERT INTO analysis_jobs (case_id, pipeline, pipeline_version, params_hash, status, started_at)
VALUES (:case_id, 'image_metadata', '1.4.0', :params_hash, :status, :started_at)
RETURNING id
"""

INSERT_RESULT: Final[str] = """
INSERT INTO analysis_results (job_id, case_id, pipeline, pipeline_version, result_kind, summary,
                              limitations_code, raw_output_schema_version, advisory_score,
                              score_confidence_low, score_confidence_high, confidence,
                              confidence_basis, verification_status, verified_by, verified_at,
                              verification_notes, requires_human_verification)
VALUES (:job_id, :case_id, 'image_metadata', '1.4.0', 'metadata',
        'Capture metadata is internally consistent.', 'NONE', '1.0.0', :advisory_score,
        :score_low, :score_high, :confidence, :confidence_basis, :verification_status,
        :verified_by, :verified_at, :verification_notes, :requires_human_verification)
RETURNING id
"""

INSERT_CUSTODY_EVENT: Final[str] = """
INSERT INTO custody_events (case_id, evidence_id, sequence, event_type, actor_id, system_actor,
                            acted_at, sha256_at_event, record_hash, purpose)
VALUES (:case_id, :evidence_id, :sequence, :event_type, :actor_id, :system_actor, now(),
        :sha256_at_event, :record_hash, :purpose)
RETURNING id
"""


def expect_refusal(
    session: Session, statement: str, params: dict[str, Any], constraint: str
) -> None:
    """Assert the database refuses this row, *and* that it refuses it for the stated reason.

    Checking the constraint name is what keeps this honest. A row rejected by some other rule — a
    NOT NULL, a foreign key, a different CHECK — would otherwise pass a test whose subject was never
    exercised, and the constraint under test could be broken or vacuous without anything noticing.
    """
    with pytest.raises(IntegrityError) as excinfo, atomic(session):
        session.execute(text(statement), params)
    refused_by = _refused_by(excinfo.value)
    assert refused_by == constraint, f"refused by {refused_by!r}, not {constraint!r}"


@pytest.fixture
def rows(db_session: Session) -> dict[str, Any]:
    """A minimal honest set of rows for the refusal tests to corrupt, one at a time."""
    user = one(db_session.execute(text(INSERT_USER), {"email": "investigator@example.org"}))
    case = one(
        db_session.execute(
            text(INSERT_CASE),
            {
                "case_number": "TLX-2026-000001",
                "title": "Financial irregularities, Q3",
                "sensitivity": "internal",
                "user_id": user,
            },
        )
    )
    physical_object = one(
        db_session.execute(
            text(INSERT_PHYSICAL_OBJECT),
            {
                "sha256": "a" * 64,
                "size_bytes": 204_800,
                "storage_path": "/var/lib/truthlens/evidence/aa/aaaa",
                "encryption": "none",
            },
        )
    )
    evidence = one(
        db_session.execute(
            text(INSERT_EVIDENCE),
            {
                "case_id": case,
                "physical_object_id": physical_object,
                "evidence_number": 1,
                "original_filename": "IMG_0001 (1).JPG",
                "sanitized_filename": "img-0001-1.jpg",
                "user_id": user,
            },
        )
    )
    job = one(
        db_session.execute(
            text(INSERT_JOB),
            {
                "case_id": case,
                "params_hash": "b" * 64,
                "status": "running",
                "started_at": datetime.now(UTC),
            },
        )
    )
    return {
        "user": user,
        "case": case,
        "physical_object": physical_object,
        "evidence": evidence,
        "job": job,
    }


def honest_result_params(rows: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """A result row that satisfies every honesty constraint, with individual fields overridable."""
    params: dict[str, Any] = {
        "job_id": rows["job"],
        "case_id": rows["case"],
        "advisory_score": "87.35",
        "score_low": "81.20",
        "score_high": "92.10",
        "confidence": "0.87",
        "confidence_basis": "internal-consistency",
        "verification_status": "unverified",
        "verified_by": None,
        "verified_at": None,
        "verification_notes": None,
        "requires_human_verification": True,
    }
    params.update(overrides)
    return params


def honest_event_params(rows: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """A custody event with a named actor and no content access, so no purpose is required."""
    params: dict[str, Any] = {
        "case_id": rows["case"],
        "evidence_id": rows["evidence"],
        "sequence": 1,
        "event_type": "ingested",
        "actor_id": rows["user"],
        "system_actor": None,
        "sha256_at_event": "a" * 64,
        "record_hash": "c" * 64,
        "purpose": None,
    }
    params.update(overrides)
    return params


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# The schema the migration builds
# ══════════════════════════════════════════════════════════════════════════════════════════════════


class TestSchemaIsBuilt:
    def test_every_modelled_table_exists_and_nothing_extra_does(
        self, scratch_engine: Engine
    ) -> None:
        with scratch_engine.connect() as connection:
            found = set(inspect(connection).get_table_names())
        assert found - {"alembic_version"} == set(metadata.tables), (
            f"missing {sorted(set(metadata.tables) - found)}, unexpected {sorted(found - set(metadata.tables) - {'alembic_version'})}"
        )

    def test_the_recorded_revision_is_the_head(self, scratch_engine: Engine) -> None:
        from alembic.config import Config  # noqa: PLC0415
        from alembic.script import ScriptDirectory  # noqa: PLC0415

        with scratch_engine.connect() as connection:
            applied = scalars(connection.execute(text("SELECT version_num FROM alembic_version")))
        assert applied == [HEAD_REVISION], f"alembic_version holds {applied}"

        script = ScriptDirectory.from_config(Config(str(BACKEND_ROOT / "alembic.ini")))
        assert script.get_current_head() == HEAD_REVISION, "HEAD_REVISION in this file is stale"

    def test_enums_are_native_types_carrying_the_documented_labels(
        self, scratch_engine: Engine
    ) -> None:
        """Native types, not CHECK constraints over text.

        A label that exists in the model but not in the type makes every seed row and every query
        comparison silently match nothing — a defect that surfaces as an empty result set during an
        investigation, which is the worst possible time to discover it.
        """
        with scratch_engine.connect() as connection:
            found = {
                row[0]: tuple(row[1])
                for row in connection.execute(
                    text("""
                        SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder)
                        FROM pg_type t
                        JOIN pg_enum e ON e.enumtypid = t.oid
                        JOIN pg_namespace n ON n.oid = t.typnamespace
                        WHERE n.nspname = 'public'
                        GROUP BY t.typname
                    """)
                ).all()
            }
        expected: dict[str, tuple[str, ...]] = {}
        for table_name in metadata.tables:
            for column in metadata.tables[table_name].columns:
                column_type = column.type
                if isinstance(column_type, SAEnum):
                    assert column_type.name is not None, (
                        f"{table_name}.{column.name} has no enum name"
                    )
                    expected[column_type.name] = tuple(column_type.enums)
        assert found == expected, (
            f"database enum types differ from the models:\n{found}\n{expected}"
        )

    def test_the_global_role_vocabulary_matches_the_security_architecture(
        self, scratch_engine: Engine
    ) -> None:
        with scratch_engine.connect() as connection:
            labels = scalars(
                connection.execute(
                    text("SELECT unnest(enum_range(NULL::global_role))::text ORDER BY 1")
                )
            )
        assert tuple(labels) == DOCUMENTED_ROLES

    def test_the_custody_event_vocabulary_is_complete(self, scratch_engine: Engine) -> None:
        """Fourteen event types. A missing one means an action that cannot be recorded — and an
        action that cannot be recorded is an action that will not appear in the chain of custody."""
        with scratch_engine.connect() as connection:
            labels = scalars(
                connection.execute(
                    text("SELECT unnest(enum_range(NULL::custody_event_type))::text ORDER BY 1")
                )
            )
        assert tuple(labels) == DOCUMENTED_CUSTODY_EVENTS

    def test_uuidv7_is_installed_and_orders_by_time(self, scratch_engine: Engine) -> None:
        """PostgreSQL 16 has no built-in v7, so the migration installs one.

        Ordering is asserted with a gap between the two calls: v7 sorts by millisecond, so two
        identifiers generated inside the same millisecond are ordered by their random tail and
        comparing them would be a coin toss dressed up as a test.
        """
        with scratch_engine.connect() as connection:
            versions = scalars(
                connection.execute(
                    text(
                        "SELECT get_byte(uuid_send(uuid_generate_v7()), 6) >> 4 FROM generate_series(1, 8)"
                    )
                )
            )
            earlier = one(connection.execute(text("SELECT uuid_generate_v7()")))
            time.sleep(0.01)
            later = one(connection.execute(text("SELECT uuid_generate_v7()")))
        assert set(versions) == {7}, (
            f"uuid_generate_v7 produced version nibbles {sorted(set(versions))}"
        )
        assert earlier < later, f"{earlier} is not ordered before {later}"

    def test_the_write_once_trigger_guards_the_object_ledger(self, scratch_engine: Engine) -> None:
        """``BEFORE UPDATE OR DELETE``, row-level, on ``physical_objects`` and nothing else.

        Decoded from ``tgtype``'s bitmap rather than compared as one number: a trigger that also fired
        on INSERT would reject every new object, and a statement-level trigger would see the old row
        as NULL — both defects a single opaque bitmask comparison would report as "fine".
        """
        bits = {"row": 1, "before": 2, "insert": 4, "delete": 8, "update": 16, "truncate": 32}
        with scratch_engine.connect() as connection:
            found = connection.execute(
                text("""
                    SELECT tgname, tgrelid::regclass::text, tgtype,
                           pg_get_triggerdef(oid) AS definition
                    FROM pg_trigger
                    WHERE NOT tgisinternal
                """)
            ).all()
        assert [row[0] for row in found] == ["tlx_physical_objects_write_once"]
        relation, tgtype, definition = found[0][1:]
        assert relation == "physical_objects"
        assert {flag for flag, bit in bits.items() if tgtype & bit} == {
            "row",
            "before",
            "update",
            "delete",
        }
        # pg_get_triggerdef prints the events in its own order, so the bitmap above is the
        # assertion that matters and this one only checks the trigger is where it belongs.
        assert "ON public.physical_objects FOR EACH ROW" in definition
        assert "EXECUTE FUNCTION tlx_enforce_write_once_physical_objects()" in definition

    def test_the_case_number_sequence_never_recycles(self, scratch_engine: Engine) -> None:
        """A recycled case number would put two investigations behind one identifier."""
        with scratch_engine.connect() as connection:
            cycles = one(
                connection.execute(
                    text(
                        "SELECT cycle FROM pg_sequences WHERE schemaname = 'public' AND sequencename = 'case_number_seq'"
                    )
                )
            )
            first = one(connection.execute(text("SELECT nextval('case_number_seq')")))
            second = one(connection.execute(text("SELECT nextval('case_number_seq')")))
        assert cycles is False
        assert second > first

    def test_the_generated_search_vector_is_populated_and_findable(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """§3.3's ``search_vector`` is generated, so it cannot fall out of step with the columns it
        summarises — a trigger-maintained vector can, and then search misses a case that exists."""
        db_session.execute(
            text("UPDATE cases SET title = 'Suspected invoice fraud, Q3' WHERE id = :case"),
            {"case": rows["case"]},
        )
        matched = scalars(
            db_session.execute(
                text("""
                SELECT id FROM cases
                WHERE search_vector @@ plainto_tsquery('english', :query)
            """),
                {"query": "invoice fraud"},
            )
        )
        assert rows["case"] in matched

        gin = one(
            db_session.execute(
                text("""
                SELECT indexdef FROM pg_indexes
                WHERE schemaname = 'public' AND indexname = 'ix_cases_search_vector_gin'
            """)
            )
        )
        assert "USING gin" in gin

    def test_every_case_scoped_table_has_an_index_leading_with_case_id(
        self, scratch_engine: Engine
    ) -> None:
        with scratch_engine.connect() as connection:
            indexed = {
                row[0]
                for row in connection.execute(
                    text("""
                        SELECT tablename, indexdef FROM pg_indexes WHERE schemaname = 'public'
                    """)
                ).all()
                if "(case_id" in row[1]
            }
        case_scoped = {
            name
            for name in metadata.tables
            if "case_id" in metadata.tables[name].columns and name != "cases"
        }
        missing = sorted(case_scoped - indexed)
        assert not missing, f"tables with a case_id and no index leading with it: {missing}"

    def test_foreign_key_delete_rules_are_what_the_models_declare(
        self, scratch_engine: Engine
    ) -> None:
        """``alembic check`` compares columns and types; delete behaviour is compared here.

        An ``ON DELETE CASCADE`` that should have been ``RESTRICT`` deletes custody history the first
        time a case is removed, and nothing else in the suite would notice.
        """
        codes = {
            "a": "NO ACTION",
            "r": "RESTRICT",
            "c": "CASCADE",
            "n": "SET NULL",
            "d": "SET DEFAULT",
        }
        with scratch_engine.connect() as connection:
            found = {
                row[0]: codes[row[1]]
                for row in connection.execute(
                    text("""
                        SELECT conname, confdeltype FROM pg_constraint
                        WHERE contype = 'f' AND connamespace = 'public'::regnamespace
                    """)
                ).all()
            }
        declared = {
            str(constraint.name): constraint.ondelete or "NO ACTION"
            for table_name in metadata.tables
            for constraint in metadata.tables[table_name].constraints
            if isinstance(constraint, ForeignKeyConstraint)
        }
        assert found == declared, (
            f"delete rules differ: only-in-db {sorted(set(found) - set(declared))}, "
            f"only-in-models {sorted(set(declared) - set(found))}, "
            f"mismatched {sorted(k for k in set(found) & set(declared) if found[k] != declared[k])}"
        )

    def test_the_migration_succeeds_without_the_application_roles(
        self, scratch_engine: Engine
    ) -> None:
        """The REVOKEs at the end of revision ``0001`` are conditional.

        A scratch database, a CI service container and any developer's local server have no
        ``tlx_app``/``tlx_worker``/``tlx_auditor`` roles. An unconditional REVOKE would abort the
        migration there, which would mean the schema can only be built on a server that was set up by
        hand — the opposite of reproducible.
        """
        with scratch_engine.connect() as connection:
            roles = scalars(
                connection.execute(
                    text("SELECT rolname FROM pg_roles WHERE rolname LIKE 'tlx\\_%'")
                )
            )
            tables = len(inspect(connection).get_table_names())
        assert roles == [], f"this server already has application roles: {roles}"
        assert tables == len(metadata.tables) + 1


class TestModelsAndMigrationAgree:
    def test_autogenerate_finds_no_drift(self, scratch_database: str) -> None:
        """§11's drift gate.

        This is the assertion that makes the migration trustworthy over time: if somebody edits a
        model and forgets the migration, or hand-edits a migration and forgets the model, the two
        disagree here — before the disagreement reaches a deployment where the running code queries
        a column that does not exist.
        """
        drift = alembic_check(scratch_database)
        assert drift is None, (
            f"alembic check found drift between the models and the schema:\n{drift}"
        )


class TestSeedData:
    def test_the_default_organisation_exists_and_is_active(self, scratch_engine: Engine) -> None:
        """``cases.organisation_id`` is NOT NULL *and* defaults to this row's identifier.

        So the row must be seeded by the same migration chain that creates the column: without it the
        first case insert in the platform fails, and the failure would look like a permissions bug.
        ADR-0010 keeps the table inert — no row-level security, no tenant column elsewhere — so this
        is a placeholder that a deployment may rename, not a feature.
        """
        from app.models.cases import DEFAULT_ORGANISATION_ID  # noqa: PLC0415

        with scratch_engine.connect() as connection:
            organisation = connection.execute(
                text("SELECT id, slug, status FROM organisations")
            ).one()
            defaulted = one(
                connection.execute(
                    text("""
                    SELECT pg_get_expr(adbin, adrelid) FROM pg_attrdef
                    WHERE adrelid = 'cases'::regclass
                      AND adnum = (SELECT attnum FROM pg_attribute
                                   WHERE attrelid = 'cases'::regclass AND attname = 'organisation_id')
                """)
                )
            )
        # The constant is the string the column default is built from; the driver returns a UUID.
        assert organisation[0] == UUID(DEFAULT_ORGANISATION_ID)
        assert organisation[1] == "org_default"
        assert organisation[2] == "active"
        assert str(DEFAULT_ORGANISATION_ID) in defaulted, (
            f"cases.organisation_id does not default to the seeded organisation: {defaulted}"
        )

    def test_the_six_roles_are_seeded(self, scratch_engine: Engine) -> None:
        with scratch_engine.connect() as connection:
            codes = scalars(connection.execute(text("SELECT code::text FROM roles ORDER BY 1")))
        assert tuple(codes) == DOCUMENTED_ROLES

    def test_every_documented_capability_is_seeded(self, scratch_engine: Engine) -> None:
        """SECURITY_ARCHITECTURE §4.2's canonical vocabulary, arriving as rows.

        A capability the code checks for but the database does not define can never be granted, so
        the feature it guards is unreachable — and the failure looks like a permissions bug rather
        than a missing seed. Transcribed here rather than imported from the migration: a test that
        reads the same constant the seed does can only ever agree with itself.
        """
        with scratch_engine.connect() as connection:
            found = scalars(connection.execute(text("SELECT code FROM permissions ORDER BY 1")))
        assert tuple(found) == tuple(sorted(DOCUMENTED_CAPABILITIES))
        assert len(found) == len(DOCUMENTED_CAPABILITIES) == 30

    def test_every_capability_names_a_resource_group(self, scratch_engine: Engine) -> None:
        """The group is a label for an administration UI. Blank or NULL there means a screen with an
        unlabelled section — cosmetic, but it is the kind of thing a seed forgets."""
        with scratch_engine.connect() as connection:
            blank = scalars(
                connection.execute(
                    text(
                        "SELECT code FROM permissions WHERE resource IS NULL OR btrim(resource) = ''"
                    )
                )
            )
        assert blank == []

    def test_no_capability_is_granted_before_the_authorization_matrix_exists(
        self, scratch_engine: Engine
    ) -> None:
        """Deliberately empty, and fail-closed.

        Deciding which role holds which capability *is* the authorization design, and that is M3.
        Seeding a guess here would make a plausible-looking matrix that nobody ratified; leaving it
        empty means every request is denied until M3 writes the matrix down and a test asserts it.
        """
        with scratch_engine.connect() as connection:
            grants = one(connection.execute(text("SELECT count(*) FROM role_permissions")))
        assert grants == 0

    def test_seeding_is_idempotent(self, scratch_database: str, scratch_engine: Engine) -> None:
        """Stamping back and re-upgrading must not duplicate, delete or re-key anything.

        A migration that can only be run exactly once is a migration that cannot be retried after a
        partial failure — and a half-applied seed on a production server is recovered by running it
        again, which is precisely what this proves is safe.
        """
        with scratch_engine.connect() as connection:
            before = connection.execute(
                text("SELECT id, code FROM permissions ORDER BY code")
            ).all()

        alembic_stamp(scratch_database, "0001")
        alembic_upgrade(scratch_database)

        with scratch_engine.connect() as connection:
            after = connection.execute(text("SELECT id, code FROM permissions ORDER BY code")).all()
            version = one(connection.execute(text("SELECT version_num FROM alembic_version")))
            organisations = one(connection.execute(text("SELECT count(*) FROM organisations")))
            roles = one(connection.execute(text("SELECT count(*) FROM roles")))
        assert after == before, "re-seeding changed the reference rows"
        assert version == HEAD_REVISION
        assert (organisations, roles) == (1, 6)


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# What the database refuses
# ══════════════════════════════════════════════════════════════════════════════════════════════════


class TestHonestyConstraints:
    """§5.2: findings are indicators, not verdicts — enforced in the schema, not only in prose.

    Every test here starts from a row the database accepts and changes one thing. That structure
    matters: a refusal test whose row was rejected for some unrelated reason would pass while proving
    nothing, which is why :func:`expect_refusal` names the constraint it expects.
    """

    def test_the_honest_baseline_is_accepted(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        with atomic(db_session):
            identifier = one(db_session.execute(text(INSERT_RESULT), honest_result_params(rows)))
        assert identifier is not None

    def test_a_score_without_an_interval_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """A number with no interval is a verdict wearing a decimal point (ADR-0023)."""
        expect_refusal(
            db_session,
            INSERT_RESULT,
            honest_result_params(rows, score_low=None, score_high=None),
            "ck_analysis_results_score_requires_confidence_interval",
        )

    def test_an_inverted_interval_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_RESULT,
            honest_result_params(rows, score_low="95.00", score_high="10.00"),
            "ck_analysis_results_confidence_interval_is_ordered",
        )

    def test_a_score_outside_the_scale_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_RESULT,
            honest_result_params(
                rows, advisory_score="140.00", score_low="100.00", score_high="140.00"
            ),
            "ck_analysis_results_score_in_range",
        )

    def test_confidence_without_a_basis_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """Confidence is only meaningful relative to what produced it."""
        expect_refusal(
            db_session,
            INSERT_RESULT,
            honest_result_params(rows, confidence_basis=None),
            "ck_analysis_results_confidence_requires_basis",
        )

    def test_a_verdict_without_notes_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """A human confirming or rejecting a finding must say why — that sentence is the review."""
        expect_refusal(
            db_session,
            INSERT_RESULT,
            honest_result_params(
                rows,
                verification_status="confirmed",
                verified_by=rows["user"],
                verified_at=datetime.now(UTC),
                verification_notes=None,
                requires_human_verification=False,
            ),
            "ck_analysis_results_verdict_requires_notes",
        )

    def test_an_unverified_row_cannot_name_a_verifier(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """Otherwise "unverified" and "verified by nobody in particular" become the same claim."""
        expect_refusal(
            db_session,
            INSERT_RESULT,
            honest_result_params(rows, verified_by=rows["user"], verified_at=datetime.now(UTC)),
            "ck_analysis_results_unverified_has_no_verifier",
        )

    def test_a_verdict_without_a_timestamp_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_RESULT,
            honest_result_params(
                rows,
                verification_status="rejected",
                verified_by=rows["user"],
                verification_notes="Source metadata is inconsistent with the claimed capture device.",
                requires_human_verification=False,
            ),
            "ck_analysis_results_verdict_has_timestamp",
        )

    def test_indicators_must_be_an_array(self, db_session: Session, rows: dict[str, Any]) -> None:
        """A renderer iterating an object gets keys instead of findings — silently, and wrong."""
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text("""
                        INSERT INTO analysis_results (job_id, case_id, pipeline, pipeline_version,
                            result_kind, summary, limitations_code, raw_output_schema_version,
                            indicators, requires_human_verification)
                        VALUES (:job_id, :case_id, 'image_metadata', '1.4.0', 'metadata',
                            'Indicators as an object.', 'NONE', '1.0.0',
                            '{"tampering": true}'::jsonb, true)
                    """),
                {"job_id": rows["job"], "case_id": rows["case"]},
            )
        assert _refused_by(excinfo.value) == "ck_analysis_results_indicators_is_array"

    def test_a_reviewed_result_still_defaults_to_requiring_verification(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """ADR-0023's default is the safety property: forgetting the column yields the safe value."""
        with atomic(db_session):
            stored = db_session.execute(
                text("""
                    INSERT INTO analysis_results (job_id, case_id, pipeline, pipeline_version,
                        result_kind, summary, limitations_code, raw_output_schema_version)
                    VALUES (:job_id, :case_id, 'image_metadata', '1.4.0', 'metadata',
                        'Minimal honest row.', 'NONE', '1.0.0')
                    RETURNING requires_human_verification, verification_status::text, advisory_score
                """),
                {"job_id": rows["job"], "case_id": rows["case"]},
            ).one()
        assert stored[0] is True
        assert stored[1] == "unverified"
        assert stored[2] is None


class TestCustodyRules:
    def test_an_event_naming_neither_actor_nor_process_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_CUSTODY_EVENT,
            honest_event_params(rows, actor_id=None),
            "ck_custody_events_names_exactly_one_actor",
        )

    def test_an_event_naming_both_a_person_and_a_process_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """§4.3 says ``actor_id`` is NULL *only* for system jobs — so it is an exclusive or.

        An event naming both cannot answer "who did this", which is the only question a custody
        record exists to answer.
        """
        expect_refusal(
            db_session,
            INSERT_CUSTODY_EVENT,
            honest_event_params(rows, system_actor="worker-cpu-01"),
            "ck_custody_events_names_exactly_one_actor",
        )

    def test_a_blank_process_name_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_CUSTODY_EVENT,
            honest_event_params(rows, actor_id=None, system_actor="   "),
            "ck_custody_events_system_actor_is_not_blank",
        )

    def test_a_system_event_is_accepted(self, db_session: Session, rows: dict[str, Any]) -> None:
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_CUSTODY_EVENT),
                    honest_event_params(
                        rows, actor_id=None, system_actor="worker-cpu-01", sequence=2
                    ),
                )
            )
        assert identifier is not None

    def test_content_access_without_a_purpose_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """§4.3: "who looked at the original, and why" — the why is not optional."""
        for event_type in ("accessed", "downloaded", "exported"):
            expect_refusal(
                db_session,
                INSERT_CUSTODY_EVENT,
                honest_event_params(rows, event_type=event_type, sequence=3),
                "ck_custody_events_content_access_states_purpose",
            )

    def test_content_access_with_a_purpose_is_accepted(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_CUSTODY_EVENT),
                    honest_event_params(
                        rows,
                        event_type="downloaded",
                        sequence=4,
                        purpose="Preparation of exhibit list",
                    ),
                )
            )
        assert identifier is not None

    def test_the_sequence_cannot_repeat_or_go_backwards(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """A gap-tolerant but duplicate-intolerant sequence: the chain is ordered, and two events
        claiming the same position would make "between which two events did the bytes change"
        unanswerable. Uniqueness is scoped per case, so a second case may reuse the number."""
        with atomic(db_session):
            db_session.execute(text(INSERT_CUSTODY_EVENT), honest_event_params(rows, sequence=1))
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(text(INSERT_CUSTODY_EVENT), honest_event_params(rows, sequence=1))
        assert _refused_by(excinfo.value) == "uq_custody_events_case_sequence"

        expect_refusal(
            db_session,
            INSERT_CUSTODY_EVENT,
            honest_event_params(rows, sequence=0),
            "ck_custody_events_sequence_is_positive",
        )

    def test_the_genesis_event_starts_the_chain_at_zero(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """``prev_hash`` defaults to 64 zeros, so the first link is well defined and a verifier has
        nothing special to remember about the start of a chain.

        The chaining algorithm itself is M6; the shape arrives now because adding these columns to a
        populated ledger later would mean rewriting history that must never be rewritten.
        """
        with atomic(db_session):
            identifier = one(
                db_session.execute(text(INSERT_CUSTODY_EVENT), honest_event_params(rows))
            )
        stored = db_session.execute(
            text("SELECT prev_hash, record_hash FROM custody_events WHERE id = :id"),
            {"id": identifier},
        ).one()
        assert stored[0] == HEX
        assert stored[1] == "c" * 64

    def test_a_non_hex_chain_hash_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """The columns are fixed-width hex, so a malformed link is rejected at the door rather than
        stored and discovered by a verifier that then cannot say which record is wrong."""
        expect_refusal(
            db_session,
            INSERT_CUSTODY_EVENT,
            honest_event_params(rows, record_hash="not-a-digest"),
            "ck_custody_events_record_hash_is_lowercase_hex",
        )


class TestJobRules:
    def test_a_running_job_without_a_start_time_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """Without it, "how long has this been running" has no answer — and a stuck worker is
        invisible until somebody notices the queue."""
        expect_refusal(
            db_session,
            INSERT_JOB,
            {
                "case_id": rows["case"],
                "params_hash": "d" * 64,
                "status": "running",
                "started_at": None,
            },
            "ck_analysis_jobs_running_has_started_at",
        )

    def test_a_finished_job_without_a_finish_time_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_JOB,
            {
                "case_id": rows["case"],
                "params_hash": "e" * 64,
                "status": "succeeded",
                "started_at": datetime.now(UTC),
            },
            "ck_analysis_jobs_terminal_has_finished_at",
        )

    def test_an_error_on_a_successful_job_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """A stored error class on a succeeded job is a lie that will be believed during triage."""
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text("""
                        INSERT INTO analysis_jobs (case_id, pipeline, pipeline_version, params_hash,
                                                   status, error_class)
                        VALUES (:case_id, 'image_metadata', '1.4.0', :params_hash, 'succeeded',
                                'EngineTimeout')
                    """),
                {"case_id": rows["case"], "params_hash": "f" * 64},
            )
        assert _refused_by(excinfo.value) == "ck_analysis_jobs_error_only_on_failing_states"

    def test_the_idempotency_key_blocks_a_duplicate_submission(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """A retried upload must not enqueue the same analysis twice."""
        key = "1f0c9a7e-2b6d-4c31-9a55-7d2e4b8c6a10"
        statement = text("""
            INSERT INTO analysis_jobs (case_id, pipeline, pipeline_version, params_hash,
                                       idempotency_key)
            VALUES (:case_id, 'image_metadata', '1.4.0', :params_hash, :key)
        """)
        with atomic(db_session):
            db_session.execute(
                statement, {"case_id": rows["case"], "params_hash": "0" * 64, "key": key}
            )
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                statement, {"case_id": rows["case"], "params_hash": "0" * 64, "key": key}
            )
        assert _refused_by(excinfo.value) == "uq_analysis_jobs_idempotency_key"


class TestIntegrityRules:
    def test_an_encrypted_object_without_its_wrapped_key_is_refused(
        self, db_session: Session
    ) -> None:
        """§4.1: ciphertext nobody can decrypt is indistinguishable from deleted evidence.

        Refusing the row is what keeps "encrypted" from ever meaning "lost".
        """
        expect_refusal(
            db_session,
            INSERT_PHYSICAL_OBJECT,
            {
                "sha256": "1" * 64,
                "size_bytes": 1024,
                "storage_path": "/var/lib/truthlens/evidence/11/1111",
                "encryption": "aes256gcm_envelope",
            },
            "ck_physical_objects_encrypted_requires_wrapped_key",
        )

    def test_a_malformed_digest_is_refused(self, db_session: Session) -> None:
        for sha256 in ("A" * 64, "z" * 64, "a" * 63, ""):
            expect_refusal(
                db_session,
                INSERT_PHYSICAL_OBJECT,
                {
                    "sha256": sha256,
                    "size_bytes": 1024,
                    "storage_path": f"/var/lib/truthlens/evidence/bad/{sha256[:8] or 'empty'}",
                    "encryption": "none",
                },
                "ck_physical_objects_sha256_is_lowercase_hex",
            )

    def test_the_same_bytes_cannot_be_registered_twice(self, db_session: Session) -> None:
        """Deduplication is what makes ``reference_count`` meaningful: one object, many items."""
        params = {
            "sha256": "2" * 64,
            "size_bytes": 1024,
            "storage_path": "/var/lib/truthlens/evidence/22/2222",
            "encryption": "none",
        }
        with atomic(db_session):
            db_session.execute(text(INSERT_PHYSICAL_OBJECT), params)
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_PHYSICAL_OBJECT), {**params, "storage_path": "/somewhere/else"}
            )
        assert _refused_by(excinfo.value) == "uq_physical_objects_sha256"

    def test_a_case_number_outside_the_format_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        for case_number in ("TLX-26-000002", "tlx-2026-000002", "CASE-2026-000002", "TLX-2026-02"):
            expect_refusal(
                db_session,
                INSERT_CASE,
                {
                    "case_number": case_number,
                    "title": "Format probe",
                    "sensitivity": "internal",
                    "user_id": rows["user"],
                },
                "ck_cases_case_number_has_required_format",
            )

    def test_two_cases_cannot_share_a_number(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_CASE,
            {
                "case_number": "TLX-2026-000001",
                "title": "A second case with the same number",
                "sensitivity": "internal",
                "user_id": rows["user"],
            },
            "uq_cases_case_number",
        )

    def test_evidence_in_one_case_cannot_be_referenced_from_another(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """ADR-0004's boundary, made unrepresentable rather than merely forbidden.

        The composite foreign key means a note in case B about evidence belonging to case A cannot be
        stored at all — so no service has to remember to check, and no future code path can forget.
        """
        other_case = one(
            db_session.execute(
                text(INSERT_CASE),
                {
                    "case_number": "TLX-2026-000002",
                    "title": "Unrelated matter",
                    "sensitivity": "internal",
                    "user_id": rows["user"],
                },
            )
        )
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text("""
                        INSERT INTO case_notes (case_id, evidence_id, author_id, body)
                        VALUES (:case_id, :evidence_id, :author_id, 'A note about another case''s item.')
                    """),
                {"case_id": other_case, "evidence_id": rows["evidence"], "author_id": rows["user"]},
            )
        assert isinstance(excinfo.value.orig, ForeignKeyViolation)

    def test_a_soft_delete_without_an_actor_and_a_reason_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """§12: destruction is attributable or it does not happen."""
        expect_refusal(
            db_session,
            "UPDATE evidence_items SET deleted_at = now() WHERE id = :evidence",
            {"evidence": rows["evidence"]},
            "ck_evidence_items_soft_delete_requires_actor_and_reason",
        )

    def test_a_soft_delete_naming_an_actor_but_no_reason_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            "UPDATE evidence_items SET deleted_at = now(), deleted_by = :user WHERE id = :evidence",
            {"evidence": rows["evidence"], "user": rows["user"]},
            "ck_evidence_items_soft_delete_requires_actor_and_reason",
        )

    def test_a_complete_soft_delete_is_accepted(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        with atomic(db_session):
            deleted_at = one(
                db_session.execute(
                    text("""
                    UPDATE evidence_items
                    SET deleted_at = now(), deleted_by = :user,
                        deletion_justification = 'Duplicate upload of exhibit 1, withdrawn by submitter.'
                    WHERE id = :evidence
                    RETURNING deleted_at
                """),
                    {"evidence": rows["evidence"], "user": rows["user"]},
                )
            )
        assert deleted_at is not None


class TestWriteOnceObjectLedger:
    """The trigger, exercised. A write-once ledger is only write-once if the database says so.

    The trigger raises with ``ERRCODE = 'insufficient_privilege'``, which reaches Python as a
    ``DBAPIError`` rather than an ``IntegrityError`` — the refusal is a privilege decision, not a
    constraint violation, and the distinction is deliberate: it is what lets ``pgbouncer`` and the
    application distinguish "this write is not allowed" from "this data does not fit".
    """

    def _object_id(self, db_session: Session) -> UUID:
        inserted = one(
            db_session.execute(
                text(INSERT_PHYSICAL_OBJECT),
                {
                    "sha256": "3" * 64,
                    "size_bytes": 4096,
                    "storage_path": "/var/lib/truthlens/evidence/33/3333",
                    "encryption": "none",
                },
            )
        )
        return cast(UUID, inserted)

    def test_the_digest_cannot_be_rewritten(self, db_session: Session) -> None:
        identifier = self._object_id(db_session)
        with pytest.raises(DBAPIError) as excinfo, atomic(db_session):
            db_session.execute(
                text("UPDATE physical_objects SET sha256 = :sha WHERE id = :id"),
                {"sha": "4" * 64, "id": identifier},
            )
        assert "write-once" in str(excinfo.value.orig).lower()

    def test_the_write_time_cannot_be_backdated(self, db_session: Session) -> None:
        identifier = self._object_id(db_session)
        with pytest.raises(DBAPIError), atomic(db_session):
            db_session.execute(
                text(
                    "UPDATE physical_objects SET written_at = now() - interval '30 days' WHERE id = :id"
                ),
                {"id": identifier},
            )

    def test_the_row_cannot_be_deleted(self, db_session: Session) -> None:
        identifier = self._object_id(db_session)
        with pytest.raises(DBAPIError), atomic(db_session):
            db_session.execute(
                text("DELETE FROM physical_objects WHERE id = :id"), {"id": identifier}
            )

    def test_bookkeeping_columns_still_update(self, db_session: Session) -> None:
        """Reference counting and AV rescans are the legitimate mutations. Blocking them would make
        the rule unenforceable in practice — and an unenforceable rule gets switched off."""
        identifier = self._object_id(db_session)
        with atomic(db_session):
            db_session.execute(
                text("""
                    UPDATE physical_objects
                    SET reference_count = reference_count + 1, av_scan_status = 'clean'
                    WHERE id = :id
                """),
                {"id": identifier},
            )
        stored = db_session.execute(
            text("SELECT reference_count, av_scan_status FROM physical_objects WHERE id = :id"),
            {"id": identifier},
        ).one()
        assert stored[0] == 1
        assert stored[1] == "clean"

    def test_a_maintenance_session_may_correct_a_mistake(self, db_session: Session) -> None:
        """The escape hatch, and its price.

        A mistyped path or a failed AV integration must be correctable, so the trigger yields to
        ``SET LOCAL app.maintenance = 'on'`` — a setting only a role holding it can turn on, which is
        why ``infra/postgres/initdb`` never grants it to the application role. The audit obligation
        that comes with using it is documented in ``migrations/README.md``.
        """
        identifier = self._object_id(db_session)
        with atomic(db_session):
            db_session.execute(text("SET LOCAL app.maintenance = 'on'"))
            db_session.execute(
                text("UPDATE physical_objects SET storage_path = :path WHERE id = :id"),
                {"path": "/var/lib/truthlens/evidence/33/corrected", "id": identifier},
            )
        assert one(
            db_session.execute(
                text("SELECT storage_path FROM physical_objects WHERE id = :id"), {"id": identifier}
            )
        ).endswith("corrected")

    def test_the_maintenance_switch_does_not_outlive_its_transaction(
        self, db_engine: Engine
    ) -> None:
        """``SET LOCAL`` is what makes the escape hatch survivable: a leaked setting would leave the
        ledger writable for the rest of the connection's life.

        Two real transactions on one connection, not the savepoint-wrapped session fixture. Releasing
        a savepoint does not end the transaction containing it, so ``SET LOCAL`` inside
        :func:`app.db.transaction.atomic` under that fixture would still be in force afterwards —
        asserting the boundary there would measure the fixture, not the database.
        """
        maintenance = {
            "sha256": "9" * 64,
            "size_bytes": 64,
            "storage_path": "/var/lib/truthlens/evidence/99/9999",
            "encryption": "none",
        }
        guarded = {
            **maintenance,
            "sha256": "8" * 64,
            "storage_path": "/var/lib/truthlens/evidence/88/8888",
        }

        with db_engine.connect() as connection, connection.begin():
            connection.execute(text(INSERT_PHYSICAL_OBJECT), maintenance)
            connection.execute(text("SET LOCAL app.maintenance = 'on'"))
            connection.execute(
                text("DELETE FROM physical_objects WHERE sha256 = :sha256"), maintenance
            )

        with db_engine.connect() as connection:
            with pytest.raises(DBAPIError), connection.begin():
                _insert_then_delete(connection, guarded)

            setting = one(
                connection.execute(text("SELECT current_setting('app.maintenance', true)"))
            )
        assert not setting or setting == "off", (
            f"app.maintenance leaked into a later transaction: {setting!r}"
        )


class TestValueFidelity:
    def test_a_decimal_score_survives_the_round_trip_exactly(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """``numeric``, not ``double precision``: 87.35 must come back as 87.35.

        A score displayed in a report that differs in its last digit from the score that was reviewed
        is a discrepancy a defence expert will find.
        """
        with atomic(db_session):
            db_session.execute(text(INSERT_RESULT), honest_result_params(rows))
        stored = db_session.execute(
            text(
                "SELECT advisory_score, score_confidence_low FROM analysis_results WHERE job_id = :job"
            ),
            {"job": rows["job"]},
        ).one()
        assert str(stored[0]) == "87.35"
        assert str(stored[1]) == "81.20"

    def test_an_ip_address_round_trips_as_inet(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """§10: ``inet`` rather than text, so a range query or a subnet mask is possible at all.

        ``203.0.113.0/24`` is TEST-NET-3 (RFC 5737) — documentation address space, so this fixture
        can never name a real host.
        """
        with atomic(db_session):
            db_session.execute(
                text("""
                    INSERT INTO custody_events (case_id, evidence_id, sequence, event_type, actor_id,
                                                acted_at, sha256_at_event, record_hash, purpose, ip)
                    VALUES (:case_id, :evidence_id, 1, 'accessed', :actor_id, now(), :sha256_at_event,
                            :record_hash, 'Review for exhibit list', '203.0.113.42')
                """),
                {
                    "case_id": rows["case"],
                    "evidence_id": rows["evidence"],
                    "actor_id": rows["user"],
                    "sha256_at_event": "a" * 64,
                    "record_hash": "c" * 64,
                },
            )
        stored = db_session.execute(
            text("""
                SELECT host(ip), pg_typeof(ip)::text, ip << '203.0.113.0/24'::inet
                FROM custody_events WHERE case_id = :case
            """),
            {"case": rows["case"]},
        ).one()
        assert stored[0] == "203.0.113.42"
        assert stored[1] == "inet"
        assert stored[2] is True, "subnet containment is not computable — the column is not inet"

    def test_timestamps_come_back_timezone_aware(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """DB-6. A naive datetime read back from ``timestamptz`` is a local-time guess about an
        instant, and two systems guessing differently is how a timeline acquires a six-hour gap."""
        stored = one(
            db_session.execute(
                text("SELECT created_at FROM cases WHERE id = :case"), {"case": rows["case"]}
            )
        )
        assert stored.tzinfo is not None
        assert stored.utcoffset().total_seconds() == 0


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# Taking it apart and putting it back
# ══════════════════════════════════════════════════════════════════════════════════════════════════


class TestDowngradeLifecycle:
    """These get their own database: a teardown leaves nothing for the next test to use."""

    @pytest.fixture
    def lifecycle_database(self, maintenance_url: URL) -> Iterator[str]:
        with disposable_database(maintenance_url) as url:
            yield url

    def test_a_downgrade_refuses_while_cases_exist(self, lifecycle_database: str) -> None:
        """The refusal is the feature.

        Silently deleting an organisation that cases point at, or a role that accounts hold, would
        either fail halfway with a raw foreign-key error or quietly strip somebody's access. Explaining
        what has to be removed first is what makes the message actionable.
        """
        engine = create_engine(lifecycle_database)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text("""
                        INSERT INTO users (email, full_name, password_hash, password_changed_at)
                        VALUES ('lifecycle@example.org', 'Lifecycle Probe', 'hash', now())
                    """)
                )
                connection.execute(
                    text("""
                        INSERT INTO cases (case_number, title, sensitivity, created_by)
                        SELECT 'TLX-2026-000099', 'Lifecycle probe', 'internal', id FROM users
                        WHERE email = 'lifecycle@example.org'
                    """)
                )
            with pytest.raises(RuntimeError, match="cases"):
                alembic_downgrade(lifecycle_database, "base")
        finally:
            engine.dispose()

    def test_a_downgrade_refuses_while_a_role_is_assigned(self, lifecycle_database: str) -> None:
        engine = create_engine(lifecycle_database)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text("""
                        INSERT INTO users (email, full_name, password_hash, password_changed_at)
                        VALUES ('assigned@example.org', 'Assigned Probe', 'hash', now())
                    """)
                )
                connection.execute(
                    text("""
                        INSERT INTO user_roles (id, user_id, role_id, is_primary, granted_by)
                        SELECT gen_random_uuid(), u.id, r.id, true, u.id
                        FROM users u, roles r
                        WHERE u.email = 'assigned@example.org' AND r.code = 'admin'
                    """)
                )
            with pytest.raises(RuntimeError, match="user_roles"):
                alembic_downgrade(lifecycle_database, "0001")
        finally:
            engine.dispose()

    def test_a_deliberate_teardown_leaves_nothing_behind(self, lifecycle_database: str) -> None:
        """``-x allow_data_loss=true`` means it, all the way to ``base``.

        Enum types, functions, sequences and triggers are the parts a table-by-table drop forgets.
        Left behind, the next ``upgrade head`` fails on a type that already exists — and the error
        says nothing about which migration left it.
        """
        engine = create_engine(lifecycle_database)
        try:
            alembic_downgrade(lifecycle_database, "base", x_args=("allow_data_loss=true",))
            with engine.connect() as connection:
                assert inspect(connection).get_table_names() == ["alembic_version"]
                assert (
                    _count(
                        connection,
                        """
                    SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                    WHERE n.nspname = 'public' AND t.typtype = 'e'
                """,
                    )
                    == 0
                ), "enum types survived the teardown"
                assert (
                    _count(
                        connection,
                        """
                    SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public'
                """,
                    )
                    == 0
                ), "functions survived the teardown"
                assert (
                    _count(
                        connection, "SELECT count(*) FROM pg_sequences WHERE schemaname = 'public'"
                    )
                    == 0
                )
                assert (
                    _count(connection, "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal")
                    == 0
                )
        finally:
            engine.dispose()

    def test_the_schema_can_be_rebuilt_from_nothing(self, lifecycle_database: str) -> None:
        """Down and up again, ending in the same place — the property a rollback plan depends on."""
        engine = create_engine(lifecycle_database)
        try:
            alembic_downgrade(lifecycle_database, "base", x_args=("allow_data_loss=true",))
            alembic_upgrade(lifecycle_database)
            with engine.connect() as connection:
                assert len(inspect(connection).get_table_names()) == len(metadata.tables) + 1
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == HEAD_REVISION
                )
                assert _count(connection, "SELECT count(*) FROM roles") == 6
                assert _count(connection, "SELECT count(*) FROM permissions") == 30
            assert alembic_check(lifecycle_database) is None, (
                "the rebuilt schema drifted from the models"
            )
        finally:
            engine.dispose()


def _refused_by(error: IntegrityError) -> str | None:
    """The name of the constraint that refused the statement, from the driver's own diagnosis.

    ``DBAPIError.orig`` is typed as an optional plain ``Exception`` — SQLAlchemy cannot know which
    driver is underneath — and ``diag`` is psycopg's. Going through ``getattr`` keeps that honest:
    a driver that does not report a constraint name fails the test with a message saying so, rather
    than passing an assertion about ``None``.
    """
    original = error.orig
    assert original is not None, "IntegrityError arrived with no driver error attached"
    diag = getattr(original, "diag", None)
    assert diag is not None, (
        f"{type(original).__name__} carries no PostgreSQL diagnosis: {original}"
    )
    name = diag.constraint_name
    return str(name) if name is not None else None


def _insert_then_delete(connection: Any, params: dict[str, Any]) -> None:
    """Write an object and then try to delete it — the second statement must be refused.

    A helper rather than two statements inside ``pytest.raises``: a refusal test whose block holds
    more than the write under test can pass because of the wrong statement.
    """
    connection.execute(text(INSERT_PHYSICAL_OBJECT), params)
    connection.execute(text("DELETE FROM physical_objects WHERE sha256 = :sha256"), params)


def _count(connection: Any, statement: str) -> int:
    return int(one(connection.execute(text(statement))))
