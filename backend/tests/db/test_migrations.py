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

import importlib.util
import re
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast
from uuid import UUID, uuid4

import pytest
from psycopg.errors import ForeignKeyViolation
from sqlalchemy import Enum as SAEnum, ForeignKeyConstraint, create_engine, inspect, text
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.db.transaction import atomic
from app.models import metadata
from tests.db.conftest import (
    BACKEND_ROOT,
    _settings_pointing_at,
    alembic_check,
    alembic_downgrade,
    alembic_in_a_fresh_process,
    alembic_stamp,
    alembic_upgrade,
    disposable_database,
    one,
    scalars,
)

pytestmark = pytest.mark.integration

#: The revision the schema should be at after ``upgrade head``.
HEAD_REVISION: Final[str] = "0006"

#: The revision 0004 replaced. Named separately because the re-application test needs the pair: the
#: path a deployment takes is "already at the previous revision, apply the next one", not "build
#: everything from nothing", and those two executions are not the same.
PREVIOUS_REVISION: Final[str] = "0005"

#: The revision that seeds the role and capability reference data. Named because the idempotence test
#: re-runs exactly that one and no further: upgrading to head from a stamped-behind state would
#: re-apply 0003 and 0004 to a database that already holds their tables. (Revision 0004 seeds too —
#: the AR-4 corpus — and its idempotence is asserted where its content is, in TestLimitationStatement
#: Rules.)
SEED_REVISION: Final[str] = "0002"

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

    def test_m4_case_capability_matrix_is_seeded(self, scratch_engine: Engine) -> None:
        """M4 seeds only the ratified case-management capability cells."""
        expected = {
            "view_case": 6,
            "edit_case": 2,
            "close_case": 2,
            "reopen_case": 1,
            "manage_members": 2,
        }
        with scratch_engine.connect() as connection:
            for code, expected_count in expected.items():
                count = one(
                    connection.execute(
                        text(
                            "SELECT count(*) FROM role_permissions rp "
                            "JOIN permissions p ON p.id = rp.permission_id "
                            "WHERE p.code = :code"
                        ),
                        {"code": code},
                    )
                )
                assert count == expected_count
            total = one(connection.execute(text("SELECT count(*) FROM role_permissions")))
        assert total == 33

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

        # Stamp back past the seed and re-apply *only* the seed revision. Upgrading to head instead
        # would re-run 0003 and 0004 against a database that already has their tables, and the
        # failure would be about a relation that exists rather than about whether seeding repeats.
        alembic_stamp(scratch_database, "0001")
        try:
            alembic_upgrade(scratch_database, SEED_REVISION)

            with scratch_engine.connect() as connection:
                after = connection.execute(
                    text("SELECT id, code FROM permissions ORDER BY code")
                ).all()
                version = one(connection.execute(text("SELECT version_num FROM alembic_version")))
                organisations = one(connection.execute(text("SELECT count(*) FROM organisations")))
                roles = one(connection.execute(text("SELECT count(*) FROM roles")))
        finally:
            # Restore the version table only: nothing but it was changed.
            alembic_stamp(scratch_database, HEAD_REVISION)
        assert after == before, "re-seeding changed the reference rows"
        assert version == SEED_REVISION
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


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# Revision 0003: sessions, the assistant record, integrity sweeps, platform administration
# ══════════════════════════════════════════════════════════════════════════════════════════════════

INSERT_SESSION: Final[str] = """
INSERT INTO user_sessions (user_id, refresh_token_hash, family_id, issued_at, expires_at, ip,
                           user_agent, revoked_at)
VALUES (:user_id, :refresh_token_hash, :family_id, :issued_at, :expires_at, :ip, :user_agent,
        :revoked_at)
RETURNING id
"""

INSERT_CONVERSATION: Final[str] = """
INSERT INTO ai_conversations (case_id, created_by, title, provider, model_id, status)
VALUES (:case_id, :created_by, :title, :provider, :model_id, :status)
RETURNING id
"""

INSERT_MESSAGE: Final[str] = """
INSERT INTO ai_messages (conversation_id, role, content, citations, unsupported, retrieval_context,
                         prompt_tokens, completion_tokens, model_name, model_version, temperature,
                         top_p, seed, guardrail_version, prompt_template_version, latency_ms, status)
VALUES (:conversation_id, :role, :content, CAST(:citations AS jsonb), :unsupported,
        CAST(:retrieval_context AS jsonb), :prompt_tokens, :completion_tokens, :model_name,
        :model_version, :temperature, :top_p, :seed, :guardrail_version, :prompt_template_version,
        :latency_ms, :status)
RETURNING id
"""

#: The same insert with every optional column omitted, so what comes back is what the *database*
#: supplied rather than what a test chose.
INSERT_BARE_MESSAGE: Final[str] = """
INSERT INTO ai_messages (conversation_id, role, content, guardrail_version,
                         prompt_template_version, status)
VALUES (:conversation_id, :role, :content, :guardrail_version, :prompt_template_version, :status)
RETURNING id, citations, unsupported, retrieval_context
"""

INSERT_INTEGRITY_CHECK: Final[str] = """
INSERT INTO integrity_checks (physical_object_id, checked_at, expected_sha256, actual_sha256,
                              result, job_id)
VALUES (:physical_object_id, :checked_at, :expected_sha256, :actual_sha256, :result, :job_id)
RETURNING id
"""

INSERT_SYSTEM_SETTING: Final[str] = """
INSERT INTO system_settings (key, updated_by)
VALUES (:key, :updated_by)
RETURNING id, value, "schema", previous_value
"""

INSERT_FEATURE_FLAG: Final[str] = """
INSERT INTO feature_flags (key, reason, updated_by)
VALUES (:key, :reason, :updated_by)
RETURNING id, enabled
"""

INSERT_RETENTION_POLICY: Final[str] = """
INSERT INTO retention_policies (scope, evidence_type, keep_until_event, keep_duration, action,
                                approved_by)
VALUES (:scope, :evidence_type, :keep_until_event, CAST(:keep_duration AS interval), :action,
        :approved_by)
RETURNING id, action
"""

INSERT_PHYSICAL_OBJECT_FOR_SWEEP: Final[str] = """
INSERT INTO physical_objects (sha256, size_bytes, storage_backend, storage_path, detected_mime,
                              encryption, written_at)
VALUES (:sha256, 1024, 'filesystem', :storage_path, 'image/jpeg', 'none', now())
RETURNING id
"""


def honest_session_params(rows: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """A session row that satisfies every constraint, with individual fields overridable."""
    issued = datetime.now(UTC)
    params: dict[str, Any] = {
        "user_id": rows["user"],
        "refresh_token_hash": "d" * 64,
        "family_id": uuid4(),
        "issued_at": issued,
        "expires_at": issued + timedelta(days=30),
        "ip": "203.0.113.7",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "revoked_at": None,
    }
    params.update(overrides)
    return params


def honest_message_params(rows: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """An assistant turn that cites what it used, so a single field can be corrupted at a time."""
    params: dict[str, Any] = {
        "conversation_id": rows["conversation"],
        "role": "assistant",
        "content": "Two objects in this case share a capture timestamp.",
        "citations": f'[{{"evidence_id": "{rows["evidence"]}", "kind": "metadata"}}]',
        "unsupported": False,
        "retrieval_context": "[]",
        "prompt_tokens": 412,
        "completion_tokens": 87,
        "model_name": "local-llm",
        "model_version": "8b-instruct-1.2.0",
        "temperature": "0.2",
        "top_p": "0.9",
        "seed": 20260101,
        "guardrail_version": "guardrails-2.1.0",
        "prompt_template_version": "assistant-v1.4",
        "latency_ms": 1830,
        "status": "succeeded",
    }
    params.update(overrides)
    return params


def honest_check_params(rows: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """A sweep that read the bytes and found them unchanged."""
    params: dict[str, Any] = {
        "physical_object_id": rows["physical_object"],
        "checked_at": datetime.now(UTC),
        "expected_sha256": "a" * 64,
        "actual_sha256": "a" * 64,
        "result": "verified",
        "job_id": None,
    }
    params.update(overrides)
    return params


def retention_params(**overrides: Any) -> dict[str, Any]:
    """A retention policy that deletes nothing, with individual fields overridable."""
    params: dict[str, Any] = {
        "scope": "original",
        "evidence_type": None,
        "keep_until_event": None,
        "keep_duration": None,
        "action": "retain",
        "approved_by": None,
    }
    params.update(overrides)
    return params


@pytest.fixture
def assistant_rows(db_session: Session, rows: dict[str, Any]) -> dict[str, Any]:
    """``rows`` plus a conversation, so the assistant tests have a thread to write into."""
    with atomic(db_session):
        conversation = one(
            db_session.execute(
                text(INSERT_CONVERSATION),
                {
                    "case_id": rows["case"],
                    "created_by": rows["user"],
                    "title": "What does the metadata say?",
                    "provider": "local",
                    "model_id": None,
                    "status": "active",
                },
            )
        )
    return {**rows, "conversation": conversation}


class TestSessionRules:
    """§3.2's refresh-token table, against the server."""

    @pytest.mark.parametrize("token_hash", ["D" * 64, "z" * 64, "d" * 63])
    def test_a_token_hash_outside_the_alphabet_is_refused(
        self, db_session: Session, rows: dict[str, Any], token_hash: str
    ) -> None:
        """Uppercase, a non-hex character and a truncated digest are all refused by name.

        The width is already fixed by ``char(64)``; the alphabet is not, and a digest stored uppercase
        would never match the same token hashed again at presentation — which surfaces as "session
        expired" for a user whose session is valid.
        """
        expect_refusal(
            db_session,
            INSERT_SESSION,
            honest_session_params(rows, refresh_token_hash=token_hash),
            "ck_user_sessions_refresh_token_hash_is_lowercase_hex",
        )

    def test_the_same_token_cannot_be_presented_by_two_sessions(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """Rotation presents a token and expects exactly one row back.

        Two rows would mean two live sessions for one credential, and reuse detection — which decides
        whether to revoke a whole family — could not tell which one was replayed.
        """
        params = honest_session_params(rows)
        with atomic(db_session):
            db_session.execute(text(INSERT_SESSION), params)
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_SESSION), {**params, "family_id": uuid4(), "ip": "198.51.100.4"}
            )
        assert _refused_by(excinfo.value) == "uq_user_sessions_refresh_token_hash"

    @pytest.mark.parametrize(
        ("field", "constraint"),
        [
            ("expires_at", "ck_user_sessions_expiry_after_issue"),
            ("revoked_at", "ck_user_sessions_revocation_after_issue"),
        ],
    )
    def test_a_session_cannot_end_before_it_began(
        self, db_session: Session, rows: dict[str, Any], field: str, constraint: str
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_SESSION,
            honest_session_params(
                rows,
                issued_at=datetime(2026, 3, 1, 12, tzinfo=UTC),
                **{field: datetime(2026, 3, 1, 11, tzinfo=UTC)},
            ),
            constraint,
        )

    def test_a_revoked_session_may_still_be_expired(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """The constraint that must NOT exist, checked by writing the row it would have refused.

        Revoking an already-expired session is normal housekeeping — reuse detection sweeps families
        whose tokens have lapsed — so a ``revoked_at <= expires_at`` rule would block it. Asserting
        that the row is accepted is the only way to prove the rule is absent rather than unseen.
        """
        issued = datetime(2026, 3, 1, 12, tzinfo=UTC)
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_SESSION),
                    honest_session_params(
                        rows,
                        issued_at=issued,
                        expires_at=issued + timedelta(days=30),
                        revoked_at=issued + timedelta(days=45),
                    ),
                )
            )
        assert isinstance(identifier, UUID)

    def test_a_user_cannot_be_deleted_while_a_session_records_them(
        self, db_session: Session
    ) -> None:
        """§3.2's ``RESTRICT``, exercised: the login history outlives the account it belongs to.

        A deletion that took the sessions with it would remove the evidence that an account
        authenticated from a given address with a given client — the first thing an incident review
        asks for.
        """
        # A user of its own rather than `rows["user"]`: that one created a case, so deleting them is
        # refused by `fk_cases_created_by_users` first and the session constraint is never reached.
        # Which foreign key answers is not a detail — the point is that the session record survives.
        with atomic(db_session):
            holder = one(
                db_session.execute(text(INSERT_USER), {"email": "session-holder@example.org"})
            )
            db_session.execute(text(INSERT_SESSION), honest_session_params({"user": holder}))
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(text("DELETE FROM users WHERE id = :user_id"), {"user_id": holder})
        assert _refused_by(excinfo.value) == "fk_user_sessions_user_id_users"

    def test_session_identifiers_are_time_ordered(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """ADR-0009, observed on the server rather than asserted about a Python default.

        ``uuid_generate_v7()`` is a function the migration installs, so "the column defaults to v7"
        says nothing about whether it works. The gap between the two inserts matters: v7 orders by
        millisecond, and two identifiers from the same one are ordered by their random tail.
        """
        with atomic(db_session):
            first = one(db_session.execute(text(INSERT_SESSION), honest_session_params(rows)))
        time.sleep(0.01)
        with atomic(db_session):
            second = one(
                db_session.execute(
                    text(INSERT_SESSION), honest_session_params(rows, refresh_token_hash="e" * 64)
                )
            )
        assert first < second, f"{first} is not ordered before {second}"


class TestAssistantRecordRules:
    """§8.2 and AI-02, against the server: the honesty constraint has to actually refuse a row."""

    def test_an_assistant_claim_with_no_citation_and_no_declaration_is_refused(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """The single most important constraint revision 0003 adds.

        The guardrail prompt asks the model to cite; a CHECK makes it unable to persist an uncited
        claim. Without it the platform's central promise — every assistant statement traceable to case
        data, or explicitly marked as not traceable — rests on a model obeying an instruction.
        """
        expect_refusal(
            db_session,
            INSERT_MESSAGE,
            honest_message_params(assistant_rows, citations="[]", unsupported=False),
            "ck_ai_messages_assistant_cites_or_declares_unsupported",
        )

    def test_an_assistant_turn_may_say_the_case_does_not_support_it(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """``unsupported = true`` is the honest exit, and it has to be reachable.

        A constraint that refused every uncited turn would push the model towards inventing a citation,
        which is worse than admitting there is none.
        """
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_MESSAGE),
                    honest_message_params(
                        assistant_rows,
                        citations="[]",
                        unsupported=True,
                        content="The case data does not establish who sent this message.",
                    ),
                )
            )
        assert isinstance(identifier, UUID)

    @pytest.mark.parametrize("role", ["user", "system", "tool"])
    def test_the_citation_rule_binds_assistant_turns_only(
        self, db_session: Session, assistant_rows: dict[str, Any], role: str
    ) -> None:
        """A user's own words are not a claim the platform makes, and a tool result is not prose.

        Applying AI-02 to every role would refuse an ordinary question, which is how a well-intentioned
        constraint ends up disabled.
        """
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_MESSAGE),
                    honest_message_params(
                        assistant_rows,
                        role=role,
                        citations="[]",
                        unsupported=False,
                        content="What does the capture metadata show?",
                    ),
                )
            )
        assert isinstance(identifier, UUID)

    def test_citations_that_are_not_an_array_are_refused_by_their_own_constraint(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """``jsonb_array_length`` raises an internal error on a non-array.

        The sibling ``jsonb_typeof`` CHECK exists so the row is refused with a *name* attached. Both
        reject ``{}``; only one tells an operator which rule they broke. Asserted with a non-assistant
        role so the citation rule cannot fire first and take the credit.
        """
        expect_refusal(
            db_session,
            INSERT_MESSAGE,
            honest_message_params(assistant_rows, role="user", citations="{}"),
            "ck_ai_messages_citations_is_a_json_array",
        )

    def test_the_documented_cardinality_spelling_cannot_be_what_refuses_the_row(
        self, db_session: Session
    ) -> None:
        """§8.2 writes ``cardinality(citations)``; PostgreSQL has no such function for jsonb.

        Probed rather than assumed, because the deviation is only defensible if the documented spelling
        genuinely does not work: the migration would fail outright, not merely differ. The second half
        is that the substitute does.
        """
        with pytest.raises(DBAPIError) as excinfo, atomic(db_session):
            db_session.execute(text("SELECT cardinality(CAST('[]' AS jsonb))"))
        assert "cardinality" in str(excinfo.value.orig).lower()
        with atomic(db_session):
            length = one(db_session.execute(text("SELECT jsonb_array_length(CAST('[]' AS jsonb))")))
        assert length == 0

    def test_a_succeeded_turn_without_a_model_is_refused(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """AI-04 makes model and version mandatory for every interaction, and a turn that succeeded by
        definition reached a model."""
        expect_refusal(
            db_session,
            INSERT_MESSAGE,
            honest_message_params(assistant_rows, model_name=None),
            "ck_ai_messages_a_succeeded_turn_names_its_model",
        )

    def test_a_refused_turn_needs_no_model(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """A guardrail refusal never reached a model, so demanding one would force the platform to
        record a model it did not use — a fabricated provenance entry."""
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_MESSAGE),
                    honest_message_params(
                        assistant_rows,
                        citations="[]",
                        unsupported=True,
                        status="refused",
                        model_name=None,
                        model_version=None,
                        content="Refused by the guardrail.",
                    ),
                )
            )
        assert isinstance(identifier, UUID)

    @pytest.mark.parametrize("top_p", ["1.5", "-0.1"])
    def test_top_p_outside_the_probability_range_is_refused(
        self, db_session: Session, assistant_rows: dict[str, Any], top_p: str
    ) -> None:
        """Not an invented bound: ``top_p`` is a cumulative probability by definition."""
        expect_refusal(
            db_session,
            INSERT_MESSAGE,
            honest_message_params(assistant_rows, top_p=top_p),
            "ck_ai_messages_top_p_is_a_probability",
        )

    def test_a_negative_temperature_is_refused(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        expect_refusal(
            db_session,
            INSERT_MESSAGE,
            honest_message_params(assistant_rows, temperature="-0.1"),
            "ck_ai_messages_temperature_not_negative",
        )

    def test_a_large_temperature_is_accepted(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """The upper bound is deliberately absent, and this is what proves it.

        Providers disagree about the ceiling, so a scale invented here would silently refuse a
        legitimate provider setting — and the failure would look like a bug in the assistant rather
        than a bound nobody ratified.

        A separate test from the refusal above rather than its second half: ``expect_refusal`` rolls
        back the session's transaction, which is where the fixture's rows live, so a test that refuses
        first and inserts afterwards would fail on a missing conversation. Splitting them removes the
        ordering hazard instead of relying on which fixture happened to commit.
        """
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_MESSAGE), honest_message_params(assistant_rows, temperature="4.0")
                )
            )
        assert isinstance(identifier, UUID)

    @pytest.mark.parametrize(
        ("column", "constraint"),
        [
            ("prompt_tokens", "ck_ai_messages_prompt_tokens_not_negative"),
            ("completion_tokens", "ck_ai_messages_completion_tokens_not_negative"),
            ("latency_ms", "ck_ai_messages_latency_not_negative"),
            ("seed", "ck_ai_messages_seed_not_negative"),
        ],
    )
    def test_a_measurement_cannot_be_negative(
        self, db_session: Session, assistant_rows: dict[str, Any], column: str, constraint: str
    ) -> None:
        """AI-08's regenerate and AI-04's token accounting both read these as facts about a turn."""
        expect_refusal(
            db_session,
            INSERT_MESSAGE,
            honest_message_params(assistant_rows, **{column: -1}),
            constraint,
        )

    def test_the_defaults_record_an_empty_retrieval_not_an_unknown_one(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """``[]`` means "nothing was retrieved"; NULL would mean "we did not record it".

        The difference is what AI-01 turns on: an assistant answer with no retrieval context is a
        statement made without the case, and that has to be visible in the row rather than inferred
        from a column nobody filled in.
        """
        with atomic(db_session):
            row = db_session.execute(
                text(INSERT_BARE_MESSAGE),
                {
                    "conversation_id": assistant_rows["conversation"],
                    "role": "user",
                    "content": "Summarise this case.",
                    "guardrail_version": "guardrails-2.1.0",
                    "prompt_template_version": "assistant-v1.4",
                    "status": "succeeded",
                },
            ).one()
        assert row.citations == []
        assert row.retrieval_context == []
        assert row.unsupported is False

    def test_the_chat_vocabulary_is_the_one_the_documents_spell(
        self, scratch_engine: Engine
    ) -> None:
        """§9's ``chat_role`` and §8.2's three outcomes, read back from the server.

        A label the type does not carry makes every comparison match nothing, and the failure surfaces
        as an empty transcript during a review.
        """
        with scratch_engine.connect() as connection:
            roles = scalars(
                connection.execute(text("SELECT unnest(enum_range(NULL::chat_role))::text"))
            )
            statuses = scalars(
                connection.execute(text("SELECT unnest(enum_range(NULL::ai_message_status))::text"))
            )
        assert tuple(roles) == ("system", "user", "assistant", "tool")
        assert tuple(statuses) == ("succeeded", "failed", "refused")

    def test_a_role_outside_the_vocabulary_is_refused(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """The native type doing the work a CHECK constraint would otherwise have to do."""
        with pytest.raises(DBAPIError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_MESSAGE), honest_message_params(assistant_rows, role="analyst")
            )
        assert "invalid input value for enum chat_role" in str(excinfo.value)

    def test_message_identifiers_are_time_ordered(
        self, db_session: Session, assistant_rows: dict[str, Any]
    ) -> None:
        """A transcript is read in order; v7 makes that the primary key's job rather than a sort on
        ``created_at`` in every query."""
        with atomic(db_session):
            first = one(
                db_session.execute(
                    text(INSERT_MESSAGE), honest_message_params(assistant_rows, role="user")
                )
            )
        time.sleep(0.01)
        with atomic(db_session):
            second = one(
                db_session.execute(
                    text(INSERT_MESSAGE), honest_message_params(assistant_rows, role="assistant")
                )
            )
        assert first < second, f"{first} is not ordered before {second}"


class TestSweepRules:
    """§8.4's ``integrity_checks`` and EVID-07, against the server."""

    def test_a_sweep_cannot_report_verified_while_holding_two_different_digests(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """The row that would be worth forging, refused.

        "Verified" beside two unequal digests contradicts itself, and that contradiction is exactly
        what a tampered sweep record looks like.
        """
        expect_refusal(
            db_session,
            INSERT_INTEGRITY_CHECK,
            honest_check_params(rows, actual_sha256="b" * 64),
            "ck_integrity_checks_verified_means_the_digests_agree",
        )

    def test_a_sweep_cannot_report_a_mismatch_that_did_not_happen(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """The mirror image, and not a harmless one: EVID-07 makes a mismatch a critical integrity
        exception that an administrator acts on, so a false positive has a cost too."""
        expect_refusal(
            db_session,
            INSERT_INTEGRITY_CHECK,
            honest_check_params(rows, result="mismatch"),
            "ck_integrity_checks_mismatch_means_the_digests_differ",
        )

    def test_unverified_is_not_an_outcome_a_sweep_may_report(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """``integrity_status`` is shared with ``evidence_items``, where ``unverified`` means "never
        checked". A row here *is* a check that ran, so the shared enum needs this constraint beside it
        — otherwise the table can record that nothing happened."""
        expect_refusal(
            db_session,
            INSERT_INTEGRITY_CHECK,
            # With the digest present, so `a_digest_was_read_unless_missing` cannot fire first: two
            # violated constraints would make the assertion about which one answered arbitrary.
            honest_check_params(rows, result="unverified"),
            "ck_integrity_checks_result_is_an_outcome",
        )

    def test_a_sweep_may_report_that_the_bytes_were_unreadable(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """``missing`` is the one result with no digest, and it has to be writable: EVID-07 exists to
        raise an exception when an original cannot be read."""
        with atomic(db_session):
            identifier = one(
                db_session.execute(
                    text(INSERT_INTEGRITY_CHECK),
                    honest_check_params(rows, result="missing", actual_sha256=None),
                )
            )
        assert isinstance(identifier, UUID)

    def test_every_other_result_requires_the_digest_that_was_read(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """Without this, NULL in ``actual_sha256`` is ambiguous between "could not read it" and "did
        not record it" — and only the first is a finding."""
        expect_refusal(
            db_session,
            INSERT_INTEGRITY_CHECK,
            honest_check_params(rows, result="mismatch", actual_sha256=None),
            "ck_integrity_checks_a_digest_was_read_unless_missing",
        )

    @pytest.mark.parametrize("column", ["expected_sha256", "actual_sha256"])
    def test_a_malformed_digest_is_refused(
        self, db_session: Session, rows: dict[str, Any], column: str
    ) -> None:
        """The expected digest is copied from ``physical_objects.sha256`` rather than joined to it, so
        it carries the same alphabet check. An uppercase digest compares unequal to the same digest
        computed again, and presents as an integrity mismatch instead of a formatting bug."""
        expect_refusal(
            db_session,
            INSERT_INTEGRITY_CHECK,
            honest_check_params(rows, **{column: "A" * 64}),
            f"ck_integrity_checks_{column}_is_lowercase_hex",
        )

    def test_a_sweep_of_an_object_that_does_not_exist_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_INTEGRITY_CHECK), honest_check_params(rows, physical_object_id=uuid4())
            )
        assert (
            _refused_by(excinfo.value) == "fk_integrity_checks_physical_object_id_physical_objects"
        )

    def test_sweep_identifiers_are_time_ordered(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """§10 rolls these to cold storage after 24 months, which is a key-range operation."""
        with atomic(db_session):
            first = one(db_session.execute(text(INSERT_INTEGRITY_CHECK), honest_check_params(rows)))
        time.sleep(0.01)
        with atomic(db_session):
            second = one(
                db_session.execute(
                    text(INSERT_INTEGRITY_CHECK),
                    honest_check_params(rows, actual_sha256="b" * 64, result="mismatch"),
                )
            )
        assert first < second


class TestPlatformAdministrationRules:
    """§8.4's settings, flags and retention policies: every default is the closed one."""

    def test_a_flag_created_with_no_values_enables_nothing(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """Fail closed, observed on the server.

        A migration or an admin call that inserts a key and a reason gets ``false``, in the same
        direction as ``ai_provider_settings.is_enabled`` — a row that switches something on has to say
        so explicitly.
        """
        with atomic(db_session):
            row = db_session.execute(
                text(INSERT_FEATURE_FLAG),
                {
                    "key": "assistant.local_inference",
                    "reason": "ADR-0007: local-first by default",
                    "updated_by": rows["user"],
                },
            ).one()
        assert row.enabled is False

    @pytest.mark.parametrize("table_name", ["feature_flags", "system_settings"])
    def test_a_blank_key_is_refused(
        self, db_session: Session, rows: dict[str, Any], table_name: str
    ) -> None:
        """NOT NULL is satisfied by whitespace, which is why the ``btrim`` CHECK exists."""
        statement = (
            INSERT_FEATURE_FLAG
            if table_name == "feature_flags"
            else "INSERT INTO system_settings (key, updated_by) VALUES (:key, :updated_by)"
        )
        expect_refusal(
            db_session,
            statement,
            {"key": "   ", "reason": "   ", "updated_by": rows["user"]},
            f"ck_{table_name}_key_is_not_blank",
        )

    def test_a_blank_flag_reason_is_refused(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """A flag here states a licence position (ADR-0001's copyleft gates), a rollout decision or a
        legal constraint. "It was on" with nothing beside it is not answerable six months later when
        somebody asks who accepted that obligation."""
        expect_refusal(
            db_session,
            INSERT_FEATURE_FLAG,
            {"key": "assistant.local_inference", "reason": "   ", "updated_by": rows["user"]},
            "ck_feature_flags_reason_is_not_blank",
        )

    def test_no_policy_can_delete_the_audit_trail(self, db_session: Session) -> None:
        """ADR-0020's second decision, enforced where an administrator cannot reach around it.

        §12 says custody and audit history is never deleted in v1 — archival only. Without this CHECK
        the most destructive setting in the admin UI would be one dropdown away.
        """
        expect_refusal(
            db_session,
            INSERT_RETENTION_POLICY,
            retention_params(scope="custody_audit", action="delete"),
            "ck_retention_policies_audit_is_never_deleted",
        )

    def test_the_audit_trail_may_still_be_archived(self, db_session: Session) -> None:
        """§12's "archival only" is a permission as much as a prohibition: cold storage after 730 days
        is the documented lifecycle, so ``archive`` has to be writable."""
        with atomic(db_session):
            row = db_session.execute(
                text(INSERT_RETENTION_POLICY),
                retention_params(
                    scope="custody_audit",
                    keep_until_event="case_closed",
                    keep_duration="730 days",
                    action="archive",
                ),
            ).one()
        assert row.action == "archive"

    def test_deleting_an_original_without_an_approver_is_refused(self, db_session: Session) -> None:
        """ADR-0020's fourth decision: a hard delete needs an administrator, a justification, a second
        approver and a permanent audit record. This is the approver half."""
        expect_refusal(
            db_session,
            INSERT_RETENTION_POLICY,
            retention_params(scope="original", evidence_type="image", action="delete"),
            "ck_retention_policies_deletion_names_an_approver",
        )

    def test_deleting_an_original_is_permitted_once_somebody_approves_it(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """The constraint has to be satisfiable, or it is a prohibition on the action rather than a
        requirement about how it is authorised.

        Kept apart from the refusal above for the transaction reason noted in
        :meth:`TestAssistantRecordRules.test_a_large_temperature_is_accepted`.
        """
        with atomic(db_session):
            row = db_session.execute(
                text(INSERT_RETENTION_POLICY),
                retention_params(
                    scope="original",
                    evidence_type="image",
                    action="delete",
                    approved_by=rows["user"],
                ),
            ).one()
        assert row.action == "delete"

    def test_purging_a_derivative_needs_no_approver(self, db_session: Session) -> None:
        """§12 makes derivative purging automated and regenerable — a constraint demanding an approver
        there would contradict the rule it was written to serve."""
        with atomic(db_session):
            row = db_session.execute(
                text(INSERT_RETENTION_POLICY),
                retention_params(
                    scope="derivative",
                    evidence_type="image",
                    keep_duration="90 days",
                    action="purge",
                ),
            ).one()
        assert row.action == "purge"

    @pytest.mark.parametrize(
        ("overrides", "constraint"),
        [
            ({"scope": "everything"}, "ck_retention_policies_scope_is_a_known_data_class"),
            ({"action": "shred"}, "ck_retention_policies_action_is_a_known_action"),
        ],
    )
    def test_an_unknown_scope_or_action_is_refused(
        self, db_session: Session, overrides: dict[str, str], constraint: str
    ) -> None:
        """A scope nobody defined would match no deletion rule at all, silently retaining everything
        it was meant to govern — so these vocabularies are constrained even though they stay text."""
        expect_refusal(
            db_session, INSERT_RETENTION_POLICY, retention_params(**overrides), constraint
        )

    def test_a_new_setting_declares_an_empty_value_and_an_empty_shape(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        """``value`` and ``schema`` are both NOT NULL with ``{}`` defaults, so a setting exists as a
        declared-but-empty entry rather than as a NULL nobody can validate against.

        ``previous_value`` stays NULL, and that is a fact rather than a gap: it means this is the value
        the setting was created with.
        """
        with atomic(db_session):
            row = db_session.execute(
                text(INSERT_SYSTEM_SETTING),
                {"key": "retention.statutory_days", "updated_by": rows["user"]},
            ).one()
        assert row.value == {}
        # By position: the column is named `schema`, which is not a usable attribute name on a Row.
        assert row[2] == {}
        assert row.previous_value is None

    def test_two_settings_cannot_share_a_key(
        self, db_session: Session, rows: dict[str, Any]
    ) -> None:
        params = {"key": "retention.statutory_days", "updated_by": rows["user"]}
        with atomic(db_session):
            db_session.execute(text(INSERT_SYSTEM_SETTING), params)
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(text(INSERT_SYSTEM_SETTING), params)
        assert _refused_by(excinfo.value) == "uq_system_settings_key"


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# Revision 0004: the AR-4 limitation corpus
# ══════════════════════════════════════════════════════════════════════════════════════════════════

INSERT_LIMITATION_STATEMENT: Final[str] = """
INSERT INTO limitation_statements (code, version, text_en, effective_from, effective_to, approved_by)
VALUES (:code, :version, :text_en, CAST(:effective_from AS timestamptz),
        CAST(:effective_to AS timestamptz), :approved_by)
RETURNING code, version
"""

#: The resolution §5.3 describes in prose: the newest version of a code whose window covers the
#: moment the result was created. Written out rather than left to a service, because the corpus is
#: worthless if the query it exists to answer does not return one row.
RESOLVE_STATEMENT: Final[str] = """
SELECT text_en, version FROM limitation_statements
WHERE code = :code
  AND (effective_from IS NULL OR effective_from <= :moment)
  AND (effective_to IS NULL OR effective_to > :moment)
ORDER BY version DESC
LIMIT 1
"""

#: The codes §5.3 lists, transcribed. That list ends with an ellipsis, so it is illustrative rather
#: than exhaustive — but a corpus that quietly invents a code, or renames one, should fail here.
DOCUMENTED_LIMITATION_CODES: Final[tuple[str, ...]] = (
    "ELA",
    "DEEPFAKE",
    "ALPR",
    "ASR",
    "DQT",
    "COPY_MOVE",
    "GEO_PLAUSIBILITY",
)

#: The subset whose wording ``MASTER_PRD.md`` AR-4 ratifies verbatim, which is what revision 0004
#: seeds. The remaining codes have no ratified text anywhere in ``docs/``, and the engines that need
#: them do not exist yet — a disclaimer is a statement about what a specific engine cannot do, so
#: writing one now would be inventing wording nobody reviewed and attaching it to behaviour nobody
#: built. Each arrives with its engine as its own data migration (§11(6)); the omission is recorded
#: in ``backend/migrations/README.md``.
RATIFIED_LIMITATION_CODES: Final[tuple[str, ...]] = ("ALPR", "ASR", "DEEPFAKE", "ELA")

#: AR-4's label for each ratified code. The document's labels are prose ("Deepfake indicators");
#: §5.3's codes are the vocabulary. The mapping is the only judgement in the seed, so it is written
#: down here rather than buried in an insert statement.
RATIFIED_LABELS: Final[dict[str, str]] = {
    "ELA": "ELA",
    "DEEPFAKE": "Deepfake indicators",
    "ALPR": "ALPR",
    "ASR": "ASR",
}


class TestLimitationStatementRules:
    """§5.3's corpus on the server: what it seeds, how it resolves, what it refuses.

    M2's exit criterion (c) — "every seeded limitation statement resolves by ``(code, version)``" —
    is the first test. The second is the one that makes the corpus worth having: the wording in the
    database is the wording ``MASTER_PRD.md`` AR-4 ratified, character for character. A disclaimer is
    a published statement about the limits of a forensic method, so a paraphrase is not a small
    difference; it is the platform saying something its own documentation does not say.
    """

    @staticmethod
    def _revision() -> Any:
        """Revision 0004 as a module: the corpus and its window are its constants, not this file's."""
        return _load_revision("0004_limitation_statements")

    @staticmethod
    def _prd_statements() -> dict[str, str]:
        """AR-4's examples, read from ``MASTER_PRD.md`` and normalised for line wrapping.

        Read rather than transcribed. The property under test is that the database holds the
        *ratified* wording, and a test carrying its own copy of that wording could only ever agree
        with itself — the same reason :class:`TestRoleBootstrap` reads ``10-roles.sql`` instead of
        restating it. Whitespace is collapsed because the document wraps each sentence across lines
        inside a markdown bullet, while the database stores it unwrapped.
        """
        path = BACKEND_ROOT.parent / "docs" / "MASTER_PRD.md"
        assert path.is_file(), f"{path} is missing — AR-4 is the authority for the seeded wording"
        document = path.read_text(encoding="utf-8")
        for heading in ("**AR-4", "**AR-5"):
            assert heading in document, (
                f"{heading} moved or was renamed in MASTER_PRD.md; this test finds AR-4's "
                "examples by heading, so the seed would silently stop being checked against them"
            )
        block = document.split("**AR-4", 1)[1].split("**AR-5", 1)[0]
        found = {
            label.strip(): " ".join(body.split())
            for label, body in re.findall(r"^- \*(.+?)\*: \"(.+?)\"\s*$", block, flags=re.S | re.M)
        }
        assert found, "no AR-4 examples were parsed — the pattern no longer matches the document"
        return found

    def test_every_seeded_statement_resolves_by_its_code_and_version(
        self, scratch_engine: Engine
    ) -> None:
        """M2 exit criterion (c), literally: each code at its seeded version answers with text.

        Exactly one row, and not blank. A code that resolved to two rows would make "the ELA
        disclaimer" ambiguous, and one that resolved to an empty string would satisfy ``NOT NULL``
        while printing nothing under a finding.
        """
        with scratch_engine.connect() as connection:
            for code in RATIFIED_LIMITATION_CODES:
                found = connection.execute(
                    text(
                        "SELECT text_en FROM limitation_statements "
                        "WHERE code = :code AND version = :version"
                    ),
                    {"code": code, "version": 1},
                ).all()
                assert len(found) == 1, f"{code} v1 resolved to {len(found)} rows, not one"
                assert found[0][0].strip(), f"{code} v1 resolved to blank text"

    def test_the_seeded_wording_is_the_wording_the_prd_ratifies(
        self, scratch_engine: Engine
    ) -> None:
        """The corpus is a transcription of AR-4, asserted against AR-4 itself.

        Set equality in both directions: a statement whose text drifted fails, a code seeded with
        wording no document ratifies fails, and a ratified statement left unseeded fails. This is the
        test that makes "fixed, versioned limitations statement" (AR-4) a property of the database
        rather than a description of an intention.
        """
        ratified = self._prd_statements()
        with scratch_engine.connect() as connection:
            rows = connection.execute(text("SELECT code, text_en FROM limitation_statements")).all()
        # `str()` because a `text()` query hands back rows mypy types as `object`: the coercion is
        # explicit rather than an annotation that asserts what the driver has not promised.
        seeded: dict[str, str] = {str(code): str(statement) for code, statement in rows}
        assert seeded == {code: ratified[label] for code, label in RATIFIED_LABELS.items()}, (
            "the seeded corpus is not AR-4's ratified wording; a disclaimer is published text, so it "
            "is either the ratified sentence or it is something nobody approved"
        )

    def test_the_ratified_codes_are_the_documented_ones_the_prd_gives_wording_for(self) -> None:
        """The two constants above agree with each other and with §5.3's list.

        Hermetic, so it also runs where there is no database: a code added to §5.3 and given wording
        in AR-4 must be added in both places, and the failure names the mismatch instead of showing
        up as a KeyError in the test above.
        """
        assert set(RATIFIED_LIMITATION_CODES) == set(RATIFIED_LABELS)
        assert set(RATIFIED_LIMITATION_CODES) <= set(DOCUMENTED_LIMITATION_CODES), (
            "the corpus seeds a code §5.3 does not name"
        )
        assert set(self._prd_statements()) == set(RATIFIED_LABELS.values()), (
            "AR-4's examples changed; the seed and RATIFIED_LABELS have to change with them"
        )

    def test_the_seeded_window_is_a_date_and_not_a_clock(self, scratch_engine: Engine) -> None:
        """Deterministic across environments (§13(6)), still open, and attributed to nobody.

        ``effective_from`` is the revision's own date rather than ``now()``: two databases built from
        the same migrations must hold the same corpus byte for byte, or "every environment is
        identical" is true of the schema and not of the data. ``effective_to`` NULL means still
        current. ``approved_by`` NULL is the honest value — no account exists when a migration writes
        a fresh database's corpus, and its approval of record is the ratified text of AR-4.
        """
        revision = self._revision()
        with scratch_engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT code, effective_from, effective_to, approved_by "
                    "FROM limitation_statements"
                )
            ).all()
        assert rows, "the corpus is empty, so nothing below is being tested"
        for code, effective_from, effective_to, approved_by in rows:
            assert effective_from == revision.CORPUS_EFFECTIVE_FROM, (
                f"{code}'s window opens at {effective_from}, not at the revision's own date"
            )
            assert effective_to is None, f"{code} was seeded already superseded"
            assert approved_by is None, f"{code} was seeded naming an approver who does not exist"

    def test_a_statement_resolves_through_its_effective_window(
        self, scratch_engine: Engine
    ) -> None:
        """The window is load-bearing, not decoration.

        The moment is derived from the corpus's own ``effective_from`` rather than from ``now()``, so
        the test means the same thing whenever it runs — and so it also proves the window is a real
        bound: a moment before it opens resolves to nothing at all.
        """
        revision = self._revision()
        in_force = revision.CORPUS_EFFECTIVE_FROM + timedelta(days=1)
        before = revision.CORPUS_EFFECTIVE_FROM - timedelta(days=1)
        with scratch_engine.connect() as connection:
            for code in RATIFIED_LIMITATION_CODES:
                resolved = connection.execute(
                    text(RESOLVE_STATEMENT), {"code": code, "moment": in_force}
                ).all()
                assert len(resolved) == 1, f"{code} did not resolve to one row at {in_force}"
                assert resolved[0][1] == 1
            assert (
                connection.execute(text(RESOLVE_STATEMENT), {"code": "ELA", "moment": before}).all()
                == []
            ), "a statement resolved before its window opened"

    def test_a_correction_is_a_new_version_beside_the_old_one(self, db_session: Session) -> None:
        """§5.3's whole reason to exist, observed on the server.

        Version 2 closes version 1's window and opens its own; version 1 stays. A result created
        before the change still resolves to the wording it was published with, and one created after
        resolves to the correction. Editing version 1 in place would rewrite the meaning of every
        finding that ever cited it, which is the failure the versioning exists to prevent.
        """
        opened = datetime(2027, 1, 1, tzinfo=UTC)
        with atomic(db_session):
            db_session.execute(
                text(
                    "UPDATE limitation_statements SET effective_to = :opened "
                    "WHERE code = 'ELA' AND version = 1"
                ),
                {"opened": opened},
            )
            db_session.execute(
                text(INSERT_LIMITATION_STATEMENT),
                {
                    "code": "ELA",
                    "version": 2,
                    "text_en": (
                        "Error Level Analysis highlights recompression inconsistency, and the "
                        "signature is also produced by ordinary re-saving. Corrected wording."
                    ),
                    "effective_from": opened,
                    "effective_to": None,
                    "approved_by": None,
                },
            )

        earlier = db_session.execute(
            text(RESOLVE_STATEMENT), {"code": "ELA", "moment": opened - timedelta(days=1)}
        ).all()
        later = db_session.execute(
            text(RESOLVE_STATEMENT), {"code": "ELA", "moment": opened + timedelta(days=1)}
        ).all()
        assert [row[1] for row in earlier] == [1], "the pre-correction moment resolved to v2"
        assert [row[1] for row in later] == [2], "the post-correction moment still resolved to v1"
        assert earlier[0][0] != later[0][0]
        assert (
            _count(db_session, "SELECT count(*) FROM limitation_statements WHERE code = 'ELA'") == 2
        )

    @pytest.mark.parametrize("text_en", ["", "   "])
    def test_a_blank_disclaimer_is_refused(self, db_session: Session, text_en: str) -> None:
        """``NOT NULL`` alone would let a finding publish an empty limitation statement."""
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_LIMITATION_STATEMENT),
                {
                    "code": "PROBE",
                    "version": 1,
                    "text_en": text_en,
                    "effective_from": None,
                    "effective_to": None,
                    "approved_by": None,
                },
            )
        assert _refused_by(excinfo.value) == (
            "ck_limitation_statements_statement_text_is_not_blank"
        )

    @pytest.mark.parametrize("code", ["", "   "])
    def test_a_blank_code_is_refused(self, db_session: Session, code: str) -> None:
        """A blank code is unresolvable: ``limitations_code`` could name it and nothing would answer."""
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_LIMITATION_STATEMENT),
                {
                    "code": code,
                    "version": 1,
                    "text_en": "A probe statement.",
                    "effective_from": None,
                    "effective_to": None,
                    "approved_by": None,
                },
            )
        assert _refused_by(excinfo.value) == "ck_limitation_statements_code_is_not_blank"

    @pytest.mark.parametrize("version", [0, -1])
    def test_a_version_below_one_is_refused(self, db_session: Session, version: int) -> None:
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_LIMITATION_STATEMENT),
                {
                    "code": "PROBE",
                    "version": version,
                    "text_en": "A probe statement.",
                    "effective_from": None,
                    "effective_to": None,
                    "approved_by": None,
                },
            )
        assert _refused_by(excinfo.value) == "ck_limitation_statements_version_is_at_least_one"

    def test_a_window_that_closes_before_it_opens_is_refused(self, db_session: Session) -> None:
        """An inverted window resolves to nothing, so the wording would vanish while looking present."""
        opened = datetime(2027, 1, 1, tzinfo=UTC)
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_LIMITATION_STATEMENT),
                {
                    "code": "PROBE",
                    "version": 1,
                    "text_en": "A probe statement.",
                    "effective_from": opened,
                    "effective_to": opened - timedelta(days=1),
                    "approved_by": None,
                },
            )
        assert _refused_by(excinfo.value) == (
            "ck_limitation_statements_window_does_not_end_before_it_starts"
        )

    def test_two_statements_cannot_claim_the_same_code_and_version(
        self, db_session: Session
    ) -> None:
        """The composite key is the ambiguity rule: one wording per ``(code, version)``, ever."""
        params = {
            "code": "PROBE",
            "version": 1,
            "text_en": "A probe statement.",
            "effective_from": None,
            "effective_to": None,
            "approved_by": None,
        }
        with atomic(db_session):
            db_session.execute(text(INSERT_LIMITATION_STATEMENT), params)
        with pytest.raises(IntegrityError) as excinfo, atomic(db_session):
            db_session.execute(
                text(INSERT_LIMITATION_STATEMENT), {**params, "text_en": "Different wording."}
            )
        assert _refused_by(excinfo.value) == "pk_limitation_statements"

    def test_an_approver_being_erased_leaves_the_wording_in_place(
        self, db_session: Session
    ) -> None:
        """``SET NULL``, observed: the disclaimer survives the account that approved it.

        §12 permits erasure on a documented legal request. ``RESTRICT`` would make that request fail
        on a reference table nobody drafting it would think to look at, and the durable attribution
        for an administrative change is §8.3's ``audit_logs`` row rather than this pointer.
        """
        with atomic(db_session):
            approver = one(db_session.execute(text(INSERT_USER), {"email": "approver@example.org"}))
            db_session.execute(
                text(INSERT_LIMITATION_STATEMENT),
                {
                    "code": "PROBE",
                    "version": 1,
                    "text_en": "A probe statement with an approver.",
                    "effective_from": None,
                    "effective_to": None,
                    "approved_by": approver,
                },
            )
        with atomic(db_session):
            db_session.execute(text("DELETE FROM users WHERE id = :id"), {"id": approver})

        row = db_session.execute(
            text("SELECT text_en, approved_by FROM limitation_statements WHERE code = 'PROBE'")
        ).one()
        assert row.approved_by is None
        assert row.text_en == "A probe statement with an approver."


class TestDataLossProtectionOnTheWayDown:
    """The guards revisions 0002, 0003 and 0004 all have to pass on one rollback.

    These get a database each, because a downgrade leaves nothing for the next test to use. They also
    assert the property the guards depend on and which is easy to lose silently: ``migrations/env.py``
    runs the whole migration in one transaction, so a revision that refuses part-way down rolls back
    the drops the revisions above it already performed. A refusal that left the schema half-removed
    would be worse than no refusal at all.
    """

    @pytest.fixture
    def corpus_database(self, maintenance_url: URL) -> Iterator[str]:
        with disposable_database(maintenance_url) as url:
            yield url

    @staticmethod
    def _amend_the_corpus(url: str) -> None:
        """A second version of ELA — wording revision 0004 did not write, and cannot recreate."""
        engine = create_engine(url)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text(INSERT_LIMITATION_STATEMENT),
                    {
                        "code": "ELA",
                        "version": 2,
                        "text_en": "Amended wording an operator approved after the seed.",
                        "effective_from": datetime(2027, 1, 1, tzinfo=UTC),
                        "effective_to": None,
                        "approved_by": None,
                    },
                )
        finally:
            engine.dispose()

    @staticmethod
    def _record_a_login(url: str) -> None:
        """Real user data in one of revision 0003's tables, so its guard has something to protect."""
        engine = create_engine(url)
        try:
            with engine.begin() as connection:
                user = one(connection.execute(text(INSERT_USER), {"email": "roller@example.org"}))
                connection.execute(text(INSERT_SESSION), honest_session_params({"user": user}))
        finally:
            engine.dispose()

    def test_a_downgrade_refuses_while_amended_wording_exists(self, corpus_database: str) -> None:
        """The seeded rows are recreatable; wording an operator approved is not.

        The message has to name what would be lost, because "refusing to downgrade" without the row
        that caused it sends an operator looking through the whole corpus.
        """
        self._amend_the_corpus(corpus_database)
        with pytest.raises(RuntimeError, match=r"ELA v2"):
            alembic_downgrade(corpus_database, "0003")

        engine = create_engine(corpus_database)
        try:
            with engine.connect() as connection:
                assert "limitation_statements" in inspect(connection).get_table_names()
                assert _count(connection, "SELECT count(*) FROM limitation_statements") == 5
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == HEAD_REVISION
                ), "a refused downgrade still moved the revision pointer"
        finally:
            engine.dispose()

    def test_a_refusal_further_down_rolls_the_whole_attempt_back(
        self, corpus_database: str
    ) -> None:
        """Revision 0003's guard fires after 0004's drop has already run — and undoes it.

        This is the path a real rollback takes: ``downgrade 0002`` from head steps through 0004, which
        is allowed to drop a corpus holding nothing but seed rows, and then reaches 0003, which
        refuses because a login was recorded. One transaction for the whole run is what makes the
        answer "nothing changed" rather than "the disclaimer corpus is gone and the rollback failed
        anyway".
        """
        self._record_a_login(corpus_database)
        with pytest.raises(RuntimeError, match="user_sessions"):
            alembic_downgrade(corpus_database, "0002")

        engine = create_engine(corpus_database)
        try:
            with engine.connect() as connection:
                tables = inspect(connection).get_table_names()
                assert "limitation_statements" in tables, "0004's drop survived 0003's refusal"
                assert "user_sessions" in tables
                assert _count(connection, "SELECT count(*) FROM limitation_statements") == 4
                assert _count(connection, "SELECT count(*) FROM user_sessions") == 1
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == HEAD_REVISION
                )
        finally:
            engine.dispose()

    def test_the_escape_hatch_takes_both_revisions_with_it(self, corpus_database: str) -> None:
        """``-x allow_data_loss=true`` means it, and only that flag means it.

        With the flag, amended wording and a recorded login are both dropped on the way to 0002. The
        tables revision 0001 created are untouched, and so is the user row: 0002 leaves seeded rows
        alone under the same flag, because 0001 drops the tables holding them next.
        """
        self._amend_the_corpus(corpus_database)
        self._record_a_login(corpus_database)
        alembic_downgrade(corpus_database, "0002", x_args=("allow_data_loss=true",))

        engine = create_engine(corpus_database)
        try:
            with engine.connect() as connection:
                tables = inspect(connection).get_table_names()
                assert "limitation_statements" not in tables
                assert "user_sessions" not in tables
                assert "users" in tables
                assert "cases" in tables
                assert _count(connection, "SELECT count(*) FROM users") == 1
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == "0002"
                )
        finally:
            engine.dispose()

    def test_a_seeded_corpus_downgrades_cleanly_and_comes_back_identically(
        self, corpus_database: str
    ) -> None:
        """A corpus nobody amended is reference data: reversible, and rebuilt byte for byte.

        The re-upgrade runs in a fresh process, which is the execution a deployment performs and the
        one that caught revision 0003's ``CREATE TYPE`` defect — see
        :class:`TestRevisionIsReapplyable`.
        """
        engine = create_engine(corpus_database)
        try:
            with engine.connect() as connection:
                before = connection.execute(
                    text(
                        "SELECT code, version, text_en, effective_from, effective_to, approved_by "
                        "FROM limitation_statements ORDER BY code, version"
                    )
                ).all()

            alembic_downgrade(corpus_database, "0003")
            with engine.connect() as connection:
                assert "limitation_statements" not in inspect(connection).get_table_names()
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == "0003"
                )

            result = alembic_in_a_fresh_process(corpus_database, "upgrade", "head")
            assert result.returncode == 0, (
                f"re-applying revision 0004 in a fresh process failed:\n"
                f"{result.stdout}\n{result.stderr}"
            )
            with engine.connect() as connection:
                after = connection.execute(
                    text(
                        "SELECT code, version, text_en, effective_from, effective_to, approved_by "
                        "FROM limitation_statements ORDER BY code, version"
                    )
                ).all()
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == HEAD_REVISION
                )
        finally:
            engine.dispose()
        assert before == after, "the rebuilt corpus differs from the one that was dropped"


class TestRevisionIsReapplyable:
    """The path a deployment actually takes, which an empty-database run cannot prove.

    ``upgrade head`` from nothing applies four revisions in one process. A deployment applies one
    revision to a server that already holds the previous one — a different execution, with different
    state. Revision 0003 shipped a defect only the second path could show: every enum column was a
    plain ``sa.Enum``, so ``create_table`` emitted ``CREATE TYPE`` for types revision 0001 had already
    created. Inside one process SQLAlchemy's memo suppressed the duplicate and the run succeeded; in a
    fresh process against a database at 0002 it died with ``type "integrity_status" already exists``.
    """

    @pytest.fixture
    def revision_database(self, maintenance_url: URL) -> Iterator[str]:
        """A database of its own: this one is taken apart and put back together."""
        with disposable_database(maintenance_url) as url:
            yield url

    def test_a_database_at_the_previous_revision_can_be_upgraded_by_a_fresh_process(
        self, revision_database: str
    ) -> None:
        """Downgrade in one process, re-apply in another, exactly as a rollback-and-retry would."""
        engine = create_engine(revision_database)
        try:
            alembic_downgrade(
                revision_database, PREVIOUS_REVISION, x_args=("allow_data_loss=true",)
            )
            with engine.connect() as connection:
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == PREVIOUS_REVISION
                )
                assert "limitation_statements" in inspect(connection).get_table_names()
                assert one(connection.execute(text("SELECT count(*) FROM role_permissions"))) == 0

            result = alembic_in_a_fresh_process(revision_database, "upgrade", "head")

            assert result.returncode == 0, (
                f"`alembic upgrade head` from {PREVIOUS_REVISION} failed in a fresh process:\n"
                f"{result.stdout}\n{result.stderr}"
            )
            assert "already exists" not in result.stderr, (
                "the revision created a type or table that was already there:\n" + result.stderr
            )
            with engine.connect() as connection:
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == HEAD_REVISION
                )
                assert "limitation_statements" in inspect(connection).get_table_names()
                assert one(connection.execute(text("SELECT count(*) FROM role_permissions"))) == 13
            assert alembic_check(revision_database) is None, (
                "the re-applied revision drifted from the models"
            )
        finally:
            engine.dispose()

    def test_the_revision_references_enum_types_instead_of_creating_them(self) -> None:
        """The structural half, so the fix cannot be undone by a plausible-looking edit.

        ``create_type=False`` is what stops a column from emitting ``CREATE TYPE``; the types the
        revision owns are created once, explicitly, with ``checkfirst``. Asserting both halves names
        the mechanism rather than only its symptom.
        """
        module = _load_revision("0003_sessions_assistant_integrity_platform")
        assert set(module.NEW_ENUM_LABELS) == {"chat_role", "ai_message_status"}, (
            "the types this revision introduces changed; update the migration and this test together"
        )
        for name in (*module.NEW_ENUM_LABELS, *module.BORROWED_ENUM_LABELS):
            assert module._enum(name).create_type is False, (
                f"_enum({name!r}) would emit CREATE TYPE, so a second run of this revision would fail "
                "with DuplicateObject on any database already past revision 0001"
            )

    def test_the_types_it_borrows_are_the_ones_revision_0001_created(self) -> None:
        """Borrowed types must not be dropped on the way down.

        ``integrity_status`` and ``evidence_type`` belong to ``evidence_items`` and
        ``physical_objects``, both created by 0001, so 0003's downgrade leaves them alone — asserted
        here as a property of the two constants, and on the server by the teardown test below.
        """
        module = _load_revision("0003_sessions_assistant_integrity_platform")
        previous = _load_revision("0001_initial_schema")
        assert set(module.BORROWED_ENUM_LABELS) <= set(previous.ENUM_TYPES), (
            "0003 borrows a type 0001 never created"
        )
        assert not set(module.NEW_ENUM_LABELS) & set(previous.ENUM_TYPES), (
            "0003 claims to introduce a type that already existed"
        )

    def test_a_full_teardown_removes_the_types_this_revision_added(
        self, revision_database: str
    ) -> None:
        """Down to ``base`` and back, with the new enum types accounted for on both legs.

        A type left behind is what makes the next ``upgrade head`` fail with "already exists", and the
        error says nothing about which migration left it — so the teardown is asserted to remove them
        and the rebuild to restore exactly the set the models declare.
        """
        engine = create_engine(revision_database)
        try:
            alembic_downgrade(revision_database, "base", x_args=("allow_data_loss=true",))
            with engine.connect() as connection:
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
            alembic_upgrade(revision_database)
            with engine.connect() as connection:
                found = set(
                    scalars(
                        connection.execute(
                            text("""
                                SELECT t.typname FROM pg_type t
                                JOIN pg_namespace n ON n.oid = t.typnamespace
                                WHERE n.nspname = 'public' AND t.typtype = 'e'
                            """)
                        )
                    )
                )
        finally:
            engine.dispose()
        expected = {
            column.type.name
            for name in metadata.tables
            for column in metadata.tables[name].columns
            if isinstance(column.type, SAEnum) and column.type.name
        }
        assert found == expected, (
            f"the rebuilt enum types differ from the models: {found ^ expected}"
        )


#: §11's four roles, in the spelling ``infra/postgres/initdb/10-roles.sql`` creates them.
BOOTSTRAP_ROLES: Final[tuple[str, ...]] = (
    "tlx_migrator",
    "tlx_app",
    "tlx_worker",
    "tlx_auditor",
)

#: Mirrors the bootstrap script's grants. Written out rather than executed from the file because that
#: file is psql: ``\\gexec`` and ``\\getenv`` are client meta-commands and no driver will run them.
#: :class:`TestRoleBootstrap` is what keeps the two from drifting apart.
BOOTSTRAP_GRANTS: Final[tuple[str, ...]] = (
    "GRANT USAGE ON SCHEMA public TO tlx_migrator, tlx_app, tlx_worker, tlx_auditor",
    "GRANT CREATE ON SCHEMA public TO tlx_migrator",
    "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
    "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tlx_app, tlx_worker",
    "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
    "GRANT SELECT ON TABLES TO tlx_auditor",
    "ALTER DEFAULT PRIVILEGES FOR ROLE {owner} IN SCHEMA public "
    "GRANT USAGE, SELECT ON SEQUENCES TO tlx_app, tlx_worker",
)


class TestConnectionCredentials:
    """A masked URL is not a connection string, and nothing here may build one.

    ``str(URL)`` and ``URL.render_as_string()`` both replace the password with ``***``; only
    ``render_as_string(hide_password=False)`` returns something a driver can authenticate with. A
    masked URL does not fail loudly at the point of the mistake — it fails later as
    ``password authentication failed for user "postgres"``, which reads as a problem with the server's
    credentials and sends whoever is debugging to ``pg_hba.conf``. Against a server using trust
    authentication it does not fail at all, so the defect travels to the first environment that
    authenticates properly.

    These tests are hermetic: they assert on URL construction, not on a connection, so they hold
    whether or not the configured server asks for a password.
    """

    #: A URL with a password in it, so the assertions below mean something on a server that has none.
    CREDENTIALLED: Final[URL] = make_url(
        "postgresql+psycopg://postgres:ci-only-not-a-real-secret@localhost:5432/truthlens_ci"
    )

    def test_str_of_a_url_masks_the_password(self) -> None:
        """The trap itself, pinned so the fix cannot be "simplified" back into it."""
        assert "***" in str(self.CREDENTIALLED)
        assert "***" in self.CREDENTIALLED.render_as_string()
        assert self.CREDENTIALLED.render_as_string(hide_password=False) == (
            "postgresql+psycopg://postgres:ci-only-not-a-real-secret@localhost:5432/truthlens_ci"
        )

    @pytest.mark.parametrize("role", BOOTSTRAP_ROLES)
    def test_a_role_url_carries_the_real_password(self, role: str) -> None:
        """The exact regression: ``_as_role`` returned ``str(...)`` and handed ``create_engine`` a URL
        whose password was three asterisks."""
        scratch = self.CREDENTIALLED.set(database="tlx_roles_probe")
        addressed = _as_role(
            scratch.render_as_string(hide_password=False), role, self.CREDENTIALLED
        )
        assert addressed.password == "ci-only-not-a-real-secret"
        assert addressed.username == role
        assert addressed.database == "tlx_roles_probe"

    def test_a_role_url_recovers_the_password_from_a_masked_string(self) -> None:
        """Even if a caller passes a masked URL, the role connection must still authenticate.

        The password is taken from ``maintenance_url``, which is the configured URL and never masked,
        so a masked input degrades to the same working connection instead of to ``***``.
        """
        addressed = _as_role(
            str(self.CREDENTIALLED.set(database="tlx_roles_probe")), "tlx_app", self.CREDENTIALLED
        )
        assert addressed.password == "ci-only-not-a-real-secret"

    def test_the_migration_runner_refuses_a_masked_url(self) -> None:
        """The choke point every alembic helper passes through, so a masked URL fails here with an
        explanation instead of a hundred lines later as an authentication error."""
        with (
            pytest.raises(ValueError, match="masked database URL"),
            _settings_pointing_at(str(self.CREDENTIALLED)),
        ):
            pass  # pragma: no cover - the guard raises before the body runs

    @pytest.mark.parametrize("fixture_name", ["scratch_database", "least_privilege_database"])
    def test_the_database_fixtures_hand_out_connectable_urls(
        self, request: pytest.FixtureRequest, fixture_name: str
    ) -> None:
        """Whatever a fixture yields must carry the configured password, or nothing downstream can
        connect to it as anything other than a trust-authenticated role."""
        url = request.getfixturevalue(fixture_name)
        maintenance: URL = request.getfixturevalue("maintenance_url")
        assert make_url(url).password == maintenance.password, (
            f"{fixture_name} yielded a URL whose password is not the configured one"
        )


class TestRoleBootstrap:
    """``infra/postgres/initdb`` and the Compose service that mounts it.

    Text assertions rather than a container run: no Docker daemon was available where this was
    written, and a test that needs one would skip — the failure mode this milestone exists to remove.
    What is asserted is drift: the role names the script creates, the names ``.env.example`` documents,
    the privileges each is given, and the mount that makes the script run at all. The script's *effect*
    on a real server is :class:`TestLeastPrivilegeRoles` below.
    """

    @staticmethod
    def _repository_root() -> Path:
        return BACKEND_ROOT.parent

    @classmethod
    def _initdb_script(cls) -> str:
        """The script's SQL, with its comment lines removed and its whitespace collapsed.

        Comments are stripped because the assertions below are about statements. The header explains
        that giving the four roles distinct credentials would take "four ALTER ROLE statements", and a
        substring search that reads prose would report the script as containing an ``ALTER ROLE`` it
        does not execute.
        """
        path = cls._repository_root() / "infra" / "postgres" / "initdb" / "10-roles.sql"
        assert path.is_file(), (
            f"{path} is missing — .env.example and migrations/README.md both cite that directory"
        )
        sql = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("--")
        ]
        return " ".join(" ".join(sql).split())

    @classmethod
    def _documented_roles(cls) -> tuple[str, ...]:
        """The four role names ``.env.example`` advertises, parsed rather than retyped."""
        env = (cls._repository_root() / ".env.example").read_text(encoding="utf-8")
        found = dict(re.findall(r"^(TLX_DB_ROLE_\w+)=(\w+)", env, flags=re.MULTILINE))
        assert set(found) == {
            "TLX_DB_ROLE_APP",
            "TLX_DB_ROLE_MIGRATOR",
            "TLX_DB_ROLE_WORKER",
            "TLX_DB_ROLE_AUDITOR",
        }, f".env.example documents {sorted(found)}"
        return tuple(found.values())

    def test_the_script_creates_every_role_the_environment_documents(self) -> None:
        script = self._initdb_script()
        for role in self._documented_roles():
            assert f"'{role}'" in script, f"{role} is documented but never created"

    def test_only_the_migration_role_may_create_schema_objects(self) -> None:
        """``backend/migrations/README.md``: migrations run as ``tlx_migrator``, and the application
        role cannot ``CREATE``."""
        script = self._initdb_script()
        grants = re.findall(r"GRANT CREATE ON SCHEMA public TO ([\w, ]+)", script)
        assert grants, "no CREATE grant at all — the migration role could not build the schema"
        assert {name.strip() for grant in grants for name in grant.split(",")} == {"tlx_migrator"}

    def test_no_role_is_made_a_superuser_or_allowed_to_create_databases(self) -> None:
        script = self._initdb_script()
        assert "NOSUPERUSER" in script, "the CREATE ROLE should state its privileges explicitly"
        assert "NOCREATEDB" in script
        assert "CREATEROLE" not in script.replace("NOCREATEROLE", ""), (
            "a role that can create roles can create a superuser"
        )

    def test_the_application_and_worker_roles_get_dml_and_the_auditor_gets_read_access(
        self,
    ) -> None:
        """§11(7): ``tlx_app`` DML only, ``tlx_auditor`` read-only."""
        script = self._initdb_script()
        dml = re.search(r"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ([\w, ]+)", script)
        assert dml, "the application roles need DML on tables created after this script runs"
        assert {name.strip() for name in dml.group(1).split(",")} == {"tlx_app", "tlx_worker"}
        reads = re.search(r"GRANT SELECT ON TABLES TO ([\w, ]+)", script)
        assert reads, "the auditor must be able to read"
        assert "tlx_auditor" in reads.group(1)

    def test_the_script_never_overwrites_an_existing_credential(self) -> None:
        """Re-running it against a live deployment must not undo a password rotation."""
        script = self._initdb_script()
        assert "WHERE NOT EXISTS" in script, (
            "role creation is not conditional, so a re-run either fails or resets the password"
        )
        assert "ALTER ROLE" not in script, "an ALTER ROLE here could reset a rotated password"

    def test_compose_mounts_the_script_where_the_entrypoint_looks(self) -> None:
        compose = (self._repository_root() / "infra" / "compose" / "docker-compose.yml").read_text(
            encoding="utf-8"
        )
        assert "../../infra/postgres/initdb:/docker-entrypoint-initdb.d" in compose, (
            "the roles are never created, so the migration's append-only revokes no-op"
        )
        assert ":ro" in compose.split("/docker-entrypoint-initdb.d")[1][:8], (
            "the database container should not be able to write to its own bootstrap script"
        )

    def test_compose_and_the_example_environment_agree_on_the_bootstrap_user(self) -> None:
        """They disagreed: Compose said ``tlx`` and ``.env.example`` said ``tlx_admin``, so the
        documented environment described a different database from the one the stack created — and the
        healthcheck probed as a user the container was never told to create."""
        compose = (self._repository_root() / "infra" / "compose" / "docker-compose.yml").read_text(
            encoding="utf-8"
        )
        env = (self._repository_root() / ".env.example").read_text(encoding="utf-8")
        documented = re.search(r"^POSTGRES_USER=(\w+)", env, flags=re.MULTILINE)
        assert documented, ".env.example no longer documents POSTGRES_USER"
        assert f"${{POSTGRES_USER:-{documented.group(1)}}}" in compose, (
            "Compose does not read POSTGRES_USER, or defaults to a different user"
        )
        assert f"pg_isready -U ${{POSTGRES_USER:-{documented.group(1)}}}" in compose, (
            "the healthcheck probes as a user the container may not have created"
        )


@pytest.fixture
def least_privilege_database(maintenance_url: URL) -> Iterator[str]:
    """A database migrated with §11's roles already present, and the roles removed afterwards.

    Ordering is the entire point. The migration's append-only revokes are role-guarded ``DO`` blocks
    that test ``pg_roles`` and no-op when a role is absent, so creating the roles *after* migrating
    would prove nothing — the grants would be whatever a blank database gives every role. Roles first,
    then ``upgrade head``, is the sequence a deployment performs.

    Default privileges are per-database and apply to tables created *afterwards*, which is what makes
    "the roles exist before the schema does" work at all: ``GRANT … ON ALL TABLES`` at bootstrap time
    would grant nothing, because no table exists yet.

    Roles are cluster-wide, so the fixture records which ones it created and drops only those — a
    server that already has them (one initialised by the Compose stack, say) is left as it was.
    """
    created: list[str] = []
    name = f"tlx_roles_{uuid4().hex[:12]}"
    scratch_url = maintenance_url.set(database=name)
    # The bootstrap password, reused for the roles: `_as_role` hands it back when connecting as one of
    # them, and a role created without a password cannot authenticate against a server that requires
    # one. `or ""` keeps a trust-authenticated server (no password at all) working unchanged.
    password = maintenance_url.password or ""
    admin = create_engine(maintenance_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            for role in BOOTSTRAP_ROLES:
                if not one(
                    connection.execute(
                        text("SELECT count(*) FROM pg_roles WHERE rolname = :role"), {"role": role}
                    )
                ):
                    # The password is interpolated rather than bound: CREATE ROLE is a utility
                    # statement, and PostgreSQL rejects a parameter placeholder in the PASSWORD
                    # position with a syntax error. Both values are known here — the role name from
                    # BOOTSTRAP_ROLES, the password from the test URL — and the one character that
                    # could break out of the literal is doubled.
                    literal = password.replace("'", "''")
                    connection.execute(
                        text(
                            f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                            f"PASSWORD '{literal}'"
                        )
                    )
                    created.append(role)
            connection.execute(text(f'CREATE DATABASE "{name}"'))
    except BaseException:
        _drop_roles(admin, created)
        admin.dispose()
        raise

    scratch_admin = create_engine(scratch_url, isolation_level="AUTOCOMMIT")
    try:
        owner = maintenance_url.username or "postgres"
        with scratch_admin.connect() as connection:
            for statement in BOOTSTRAP_GRANTS:
                connection.execute(text(statement.format(owner=owner)))
        # `render_as_string(hide_password=False)`, matching `disposable_database`: `str(URL)` masks
        # the password as `***`, which under trust authentication connects anyway and under scram
        # fails as an authentication error against the bootstrap user. See TestConnectionCredentials.
        url = scratch_url.render_as_string(hide_password=False)
        alembic_upgrade(url)
        yield url
    finally:
        scratch_admin.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        _drop_roles(admin, created)
        admin.dispose()


class TestLeastPrivilegeRoles:
    """M2's exit criterion (a): the application role genuinely cannot delete an audit row."""

    def test_the_application_role_cannot_delete_an_audit_row(
        self, least_privilege_database: str, maintenance_url: URL
    ) -> None:
        """The criterion the roadmap states, on the ledger it names.

        Privilege is checked before rows are read, so an empty ``audit_logs`` proves the same thing a
        full one would; the assertion is about the *statement* being refused, and the refusal names the
        table, which is what an operator would see in a log.
        """
        engine = create_engine(_as_role(least_privilege_database, "tlx_app", maintenance_url))
        try:
            with pytest.raises(DBAPIError) as excinfo, engine.begin() as connection:
                connection.execute(text("DELETE FROM audit_logs"))
            assert "permission denied for table audit_logs" in str(excinfo.value.orig)
        finally:
            engine.dispose()

    def test_the_application_role_cannot_rewrite_a_sweep_result(
        self, least_privilege_database: str, maintenance_url: URL
    ) -> None:
        """``integrity_checks`` joined the append-only set in revision 0003, tested with a real row.

        A sweep that reported ``mismatch`` and was then edited to ``verified`` is the exact tampering
        §10's append-only rule exists to prevent, so this asserts the denial against a row that exists
        and then asserts the row is unchanged.
        """
        owner = create_engine(least_privilege_database)
        application = create_engine(_as_role(least_privilege_database, "tlx_app", maintenance_url))
        try:
            with owner.begin() as connection:
                physical_object = one(
                    connection.execute(
                        text(INSERT_PHYSICAL_OBJECT_FOR_SWEEP),
                        {"sha256": "f" * 64, "storage_path": "/var/lib/truthlens/evidence/ff/ffff"},
                    )
                )
                connection.execute(
                    text(INSERT_INTEGRITY_CHECK),
                    {
                        "physical_object_id": physical_object,
                        "checked_at": datetime.now(UTC),
                        "expected_sha256": "f" * 64,
                        "actual_sha256": "0" * 64,
                        "result": "mismatch",
                        "job_id": None,
                    },
                )

            with pytest.raises(DBAPIError) as update, application.begin() as connection:
                connection.execute(text("UPDATE integrity_checks SET result = 'verified'"))
            assert "permission denied for table integrity_checks" in str(update.value.orig)

            with pytest.raises(DBAPIError) as deletion, application.begin() as connection:
                connection.execute(text("DELETE FROM integrity_checks"))
            assert "permission denied for table integrity_checks" in str(deletion.value.orig)

            with owner.connect() as connection:
                results = scalars(connection.execute(text("SELECT result FROM integrity_checks")))
            assert tuple(results) == ("mismatch",), "the sweep result changed"
        finally:
            application.dispose()
            owner.dispose()

    def test_the_denial_is_specific_to_the_append_only_tables(
        self, least_privilege_database: str, maintenance_url: URL
    ) -> None:
        """A role denied everything would also pass the two tests above.

        ``cases`` is mutable, so ``tlx_app`` must still be able to delete from it — otherwise those
        assertions say nothing about the revokes and everything about a blanket denial.
        """
        engine = create_engine(_as_role(least_privilege_database, "tlx_app", maintenance_url))
        try:
            with engine.begin() as connection:
                result = connection.execute(text("DELETE FROM cases WHERE id = gen_random_uuid()"))
            assert result.rowcount == 0
            with pytest.raises(DBAPIError) as excinfo, engine.begin() as connection:
                connection.execute(text("CREATE TABLE tlx_app_probe (id integer)"))
            assert "permission denied for schema public" in str(excinfo.value.orig)
        finally:
            engine.dispose()

    def test_the_application_role_can_still_write_and_read(
        self, least_privilege_database: str, maintenance_url: URL
    ) -> None:
        """DML only, per §11(7): the denial above must not be a role that cannot do its job."""
        engine = create_engine(_as_role(least_privilege_database, "tlx_app", maintenance_url))
        try:
            with engine.connect() as connection:
                assert one(connection.execute(text("SELECT count(*) FROM audit_logs"))) == 0
            with engine.begin() as connection:
                connection.execute(
                    text("INSERT INTO system_settings (key, updated_by) VALUES ('probe', NULL)")
                )
            with engine.connect() as connection:
                assert one(connection.execute(text("SELECT count(*) FROM system_settings"))) == 1
        finally:
            engine.dispose()

    def test_the_auditor_can_read_but_not_write(
        self, least_privilege_database: str, maintenance_url: URL
    ) -> None:
        """§11(7): read-only, and that includes the administration tables revision 0003 added."""
        engine = create_engine(_as_role(least_privilege_database, "tlx_auditor", maintenance_url))
        try:
            with engine.connect() as connection:
                assert one(connection.execute(text("SELECT count(*) FROM audit_logs"))) == 0
            with pytest.raises(DBAPIError) as excinfo, engine.begin() as connection:
                connection.execute(
                    text("INSERT INTO system_settings (key, updated_by) VALUES ('probe', NULL)")
                )
            assert "permission denied for table system_settings" in str(excinfo.value.orig)
        finally:
            engine.dispose()

    def test_the_revokes_left_exactly_the_documented_split(
        self, least_privilege_database: str
    ) -> None:
        """The whole matrix at once, so a fixture that stopped applying the revokes fails here rather
        than making every test above pass for the wrong reason.

        It also proves the migration ran: a database at the wrong revision would have no tables to
        report privileges on at all.
        """
        engine = create_engine(least_privilege_database)
        try:
            with engine.connect() as connection:
                assert (
                    one(connection.execute(text("SELECT version_num FROM alembic_version")))
                    == HEAD_REVISION
                )
                privileges = connection.execute(
                    text("""
                        SELECT relname,
                               has_table_privilege('tlx_app', c.oid, 'SELECT'),
                               has_table_privilege('tlx_app', c.oid, 'INSERT'),
                               has_table_privilege('tlx_app', c.oid, 'UPDATE'),
                               has_table_privilege('tlx_app', c.oid, 'DELETE'),
                               has_table_privilege('tlx_auditor', c.oid, 'SELECT'),
                               has_table_privilege('tlx_auditor', c.oid, 'INSERT')
                        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relkind = 'r'
                        ORDER BY relname
                    """)
                ).all()
        finally:
            engine.dispose()

        by_name = {row[0]: tuple(row[1:]) for row in privileges}
        for name in ("audit_logs", "custody_events", "integrity_checks"):
            assert by_name[name] == (True, True, False, False, True, False), (
                f"{name} is append-only: tlx_app must read and insert but never update or delete, and "
                f"tlx_auditor must only read; got {by_name[name]}"
            )
        for name in (
            "cases",
            "evidence_items",
            "ai_messages",
            "user_sessions",
            "system_settings",
            # §10 does not list the disclaimer corpus as append-only, so it takes the ordinary DML
            # split — asserted because a table added by a later revision is exactly the kind that
            # ends up with no grants at all when the default privileges are not what applied it.
            "limitation_statements",
        ):
            assert by_name[name][:4] == (True, True, True, True), (
                f"{name} is not a ledger; tlx_app needs full DML, got {by_name[name]}"
            )
            assert by_name[name][4:] == (True, False), (
                f"{name} must be readable and not writable by tlx_auditor, got {by_name[name]}"
            )


def _drop_roles(admin: Engine, created: list[str]) -> None:
    """Remove the roles this fixture created, and only those."""
    with admin.connect() as connection:
        for role in reversed(created):
            connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))


def _as_role(url: str, role: str, maintenance_url: URL) -> URL:
    """The same database, addressed as one of §11's roles.

    Returns a :class:`~sqlalchemy.engine.URL` rather than a string, and that is deliberate: ``str()``
    of a URL masks the password as ``***``, so a string round-trip here would hand ``create_engine`` a
    URL whose password is three asterisks. A ``URL`` object carries the real one. The password is
    re-supplied from ``maintenance_url`` rather than trusted from ``url`` for the same reason — the
    caller may well have been given a masked string by something upstream.
    """
    return make_url(url).set(
        username=role,
        password=maintenance_url.password or None,
        drivername=maintenance_url.drivername,
    )


def _load_revision(module_name: str) -> Any:
    """A revision module, imported by file name.

    ``migrations/versions`` is not a package and is excluded from mypy on purpose — a revision is a
    frozen script, not library code — so importing one means loading the file. Module-level execution
    is constants and function definitions only, which is what makes that safe to do in a test.
    """
    path = BACKEND_ROOT / "migrations" / "versions" / f"{module_name}.py"
    assert path.is_file(), f"no revision file at {path}"
    specification = importlib.util.spec_from_file_location(f"revision_{module_name}", path)
    assert specification is not None, f"{path} could not be loaded as a module"
    assert specification.loader is not None, f"{path} has no loader"
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


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
