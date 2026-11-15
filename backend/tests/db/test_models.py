"""Schema assertions that need no database.

Everything here is read from ``Base.metadata``: the models are imported, the declarative mapping is
configured, and the resulting tables, columns, constraints, indexes and relationships are inspected.
No PostgreSQL is required, so these run in every environment — which is the point. A missing primary
key, a foreign key with no delete behaviour, or a column that could hold a plaintext password is a
schema defect, and a schema defect must not be able to hide behind "there was no database in CI".

The tests that *do* need a database — that the migration builds this schema, that the CHECK
constraints actually refuse a dishonest row, that the write-once trigger fires — live beside these
and skip with a reason when no server is reachable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    DefaultClause,
    Enum as SAEnum,
    ForeignKeyConstraint,
    Index,
    Table,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapper, configure_mappers
from sqlalchemy.types import LargeBinary

from app.db.base import NAMING_CONVENTION, Base
from app.models import metadata

#: tests/db/test_models.py -> db -> tests -> backend
BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

#: Every entity the M2 milestone requires, mapped to the table that implements it.
#:
#: The right-hand names are the ones ``docs/DATABASE_DESIGN.md`` ratifies. Four differ from the
#: milestone's entity list because the design document renamed them, and one column of the design
#: (``organisations``) exists because ``cases.organisation_id`` needs something to point at. The
#: reconciliation is recorded in ``DATABASE_DESIGN.md`` §14; encoding it here means a table cannot be
#: renamed by accident without a test saying so.
ENTITY_TO_TABLE: Final[dict[str, str]] = {
    "users": "users",
    "roles": "roles",
    "permissions": "permissions",
    "user_roles": "user_roles",
    "cases": "cases",
    "case_members": "case_members",
    "evidence": "evidence_items",
    "evidence_hashes": "physical_objects",
    "custody_events": "custody_events",
    "analysis_jobs": "analysis_jobs",
    "analysis_results": "analysis_results",
    "evidence_artifacts": "derivatives",
    "case_notes": "case_notes",
    "reports": "reports",
    "report_versions": "report_versions",
    "audit_logs": "audit_logs",
    "model_registry": "ai_models",
    "ai_provider_settings": "ai_provider_settings",
    "notifications": "notifications",
}

#: Tables this milestone creates, including the two the entity list does not name: ``organisations``
#: (the inert tenancy placeholder of §3.2b, which ``cases.organisation_id`` references) and
#: ``role_permissions`` (the RBAC matrix of SECURITY_ARCHITECTURE §4.2, which is what turns ``roles``
#: and ``permissions`` from two unrelated lists into an authorization model).
EXPECTED_TABLES: Final[frozenset[str]] = frozenset(
    {*ENTITY_TO_TABLE.values(), "organisations", "role_permissions"}
)

#: §1.1 / ADR-0009: time-ordered keys for high-volume append-only tables, random keys for anything
#: an outsider can see.
UUIDV7_TABLES: Final[frozenset[str]] = frozenset(
    {"custody_events", "audit_logs", "analysis_jobs", "derivatives"}
)
UUIDV4_TABLES: Final[frozenset[str]] = frozenset(
    {"users", "cases", "evidence_items", "physical_objects", "ai_models", "reports"}
)

#: Principle DB-3: append-only. No updated_at, no deleted_at, and UPDATE/DELETE revoked from the
#: application role by the migration.
APPEND_ONLY_TABLES: Final[frozenset[str]] = frozenset({"custody_events", "audit_logs"})

#: §10: case_id leads the composite index on every case-scoped table, because the authorization
#: choke point always supplies it.
CASE_SCOPED_TABLES: Final[frozenset[str]] = frozenset(
    {
        "case_members",
        "case_notes",
        "custody_events",
        "derivatives",
        "evidence_items",
        "analysis_jobs",
        "analysis_results",
        "notifications",
        "reports",
        "audit_logs",
    }
)

#: The only columns in the whole schema permitted to hold opaque bytes — all three are ciphertext.
#:
#: ``wrapped_dek`` is the per-object data encryption key sealed by the master key (§4.1's envelope
#: scheme); the other two are encrypted secrets. Nothing else may be binary, which is what makes
#: "originals are never in the database" a schema fact rather than a convention.
ENCRYPTED_SECRET_COLUMNS: Final[frozenset[str]] = frozenset(
    {
        "users.mfa_secret_encrypted",
        "ai_provider_settings.api_key_encrypted",
        "physical_objects.wrapped_dek",
    }
)


def table(name: str) -> Table:
    """A table from the single metadata, or a failure that names what is missing."""
    assert name in metadata.tables, f"{name} is not registered on Base.metadata"
    return metadata.tables[name]


@pytest.fixture(scope="module", autouse=True)
def _mappers_configured() -> None:
    """Force mapper configuration once, so relationship errors surface here and not as an odd
    failure in whichever test happened to touch the model first."""
    configure_mappers()


class TestTableRegistration:
    def test_every_required_entity_has_a_table(self) -> None:
        missing = sorted(
            f"{entity} -> {name}"
            for entity, name in ENTITY_TO_TABLE.items()
            if name not in metadata.tables
        )
        assert not missing, f"required entities with no table: {missing}"

    def test_the_schema_is_exactly_the_tables_this_milestone_defines(self) -> None:
        """No table appears that nobody asked for, and none is missing.

        Set equality rather than a subset check: an extra table is not a harmless bonus. It is a
        concept nobody specified, and §11's CI drift gate would then be comparing against a schema
        the documentation does not describe.
        """
        assert set(metadata.tables) == set(EXPECTED_TABLES)

    def test_every_model_module_is_imported_by_the_package(self) -> None:
        """The failure mode this guards is silent and total.

        A model module that ``app/models/__init__.py`` forgets to import is invisible to Alembic's
        autogenerate, which reads "not in the metadata" as "should not exist" and emits a ``DROP``.
        Nothing raises; the next migration simply removes a table.
        """
        models_dir = BACKEND_ROOT / "app" / "models"
        init_source = (models_dir / "__init__.py").read_text(encoding="utf-8")
        modules = sorted(
            path.stem
            for path in models_dir.glob("*.py")
            if path.name != "__init__.py" and path.stem not in {"enums", "types"}
        )
        assert modules, "no model modules found — the path in this test is wrong"
        unimported = [name for name in modules if f"app.models.{name} import" not in init_source]
        assert not unimported, (
            f"{unimported} are never imported by app/models/__init__.py, so their tables are missing "
            "from Base.metadata and Alembic will drop them"
        )

    def test_there_is_one_metadata_object(self) -> None:
        """Two ``DeclarativeBase`` subclasses would split the schema into two graphs.

        Neither ``alembic check`` nor these tests could then see the whole schema, and the half that
        is invisible is the half that gets dropped.
        """
        assert metadata is Base.metadata
        assert metadata.naming_convention == NAMING_CONVENTION


class TestPrimaryKeys:
    @pytest.mark.parametrize("name", sorted(EXPECTED_TABLES))
    def test_every_table_has_a_primary_key(self, name: str) -> None:
        assert table(name).primary_key.columns, f"{name} has no primary key"

    @pytest.mark.parametrize("name", sorted(EXPECTED_TABLES - {"case_members", "role_permissions"}))
    def test_entity_tables_use_a_single_uuid_key_named_id(self, name: str) -> None:
        columns = list(table(name).primary_key.columns)
        assert len(columns) == 1, f"{name} should have a single-column primary key"
        assert columns[0].name == "id", f"{name}'s primary key should be named id (§1.1)"
        assert columns[0].type.python_type.__name__ == "UUID"

    def test_association_tables_use_composite_keys(self) -> None:
        """``(case_id, user_id)`` *is* the uniqueness rule §3.4 asks for.

        A surrogate ``id`` alongside it would allow two rows for the same user in the same case —
        two contradictory answers to "what may this user do here".
        """
        assert [c.name for c in table("case_members").primary_key.columns] == ["case_id", "user_id"]
        assert [c.name for c in table("role_permissions").primary_key.columns] == [
            "role_id",
            "permission_id",
        ]

    @pytest.mark.parametrize("name", sorted(UUIDV7_TABLES))
    def test_append_only_tables_default_to_uuidv7(self, name: str) -> None:
        """ADR-0009: time-ordered keys keep the B-tree appending instead of scattering."""
        default = _default_text(table(name).primary_key.columns[0])
        assert "uuid_generate_v7()" in default

    @pytest.mark.parametrize("name", sorted(UUIDV4_TABLES))
    def test_publicly_visible_entities_default_to_uuidv4(self, name: str) -> None:
        """ADR-0009: a v7 identifier discloses when an item was created to anyone who can see it."""
        default = _default_text(table(name).primary_key.columns[0])
        assert "gen_random_uuid()" in default


class TestForeignKeys:
    @pytest.mark.parametrize("name", sorted(EXPECTED_TABLES))
    def test_every_foreign_key_declares_delete_behaviour(self, name: str) -> None:
        """An undeclared ``ON DELETE`` means ``NO ACTION``, chosen by omission rather than by thought.

        For a schema where some tables must outlive the rows that reference them — custody and audit
        outlive the case (§12) — the behaviour has to be a decision visible in the model.
        """
        undeclared = [
            f"{constraint.name or '(unnamed)'}"
            for constraint in _foreign_key_constraints(table(name))
            if constraint.ondelete is None
        ]
        assert not undeclared, f"{name} has foreign keys with no ondelete: {undeclared}"

    @pytest.mark.parametrize("name", sorted(APPEND_ONLY_TABLES))
    def test_ledgers_outlive_the_case_they_record(self, name: str) -> None:
        """§12: custody and audit history is never deleted, and neither is a case's record of it.

        ``RESTRICT`` on the case reference means destroying a case cannot take its history with it —
        not through a service rule, but because the database refuses the statement.
        """
        to_cases = [
            constraint
            for constraint in _foreign_key_constraints(table(name))
            if constraint.referred_table.name == "cases"
        ]
        assert to_cases, f"{name} does not reference cases at all"
        assert all(constraint.ondelete == "RESTRICT" for constraint in to_cases)

    def test_evidence_items_cannot_be_orphaned_from_their_bytes(self) -> None:
        """The physical object is ``RESTRICT``: an item pointing at bytes that no longer exist is a
        broken chain of custody, so the deletion has to happen the other way round (§12's
        ``reference_count = 0`` rule)."""
        constraint = _only_foreign_key_to(table("evidence_items"), "physical_objects")
        assert constraint.ondelete == "RESTRICT"

    def test_composite_foreign_keys_keep_children_inside_their_case(self) -> None:
        """Every table holding both a case and an item of that case references the *pair*.

        That makes "a note in case A about evidence in case B" unrepresentable, which is the database
        backing ADR-0004's rule that case scoping is the authorization boundary.
        """
        expected = {
            "case_notes",
            "custody_events",
            "derivatives",
            "analysis_jobs",
            "analysis_results",
        }
        found = {constraint.table.name for constraint in _composite_foreign_keys_to_evidence()}
        assert found == expected

    def test_evidence_items_exposes_the_pair_those_constraints_target(self) -> None:
        """A composite foreign key needs a matching unique constraint, or PostgreSQL refuses it.

        ``UNIQUE (case_id, id)`` on a table whose primary key is already ``id`` looks redundant and is
        not: it is the target the composite references, and without it the constraints above cannot
        exist at all.
        """
        uniques = _unique_column_tuples("evidence_items")
        assert ("case_id", "id") in uniques, (
            f"missing the composite unique target; have {sorted(uniques)}"
        )


class TestUniqueness:
    @pytest.mark.parametrize(
        ("table_name", "columns"),
        [
            ("cases", ("case_number",)),
            ("physical_objects", ("sha256",)),
            ("evidence_items", ("case_id", "evidence_number")),
            ("evidence_items", ("case_id", "id")),
            ("custody_events", ("case_id", "sequence")),
            ("audit_logs", ("sequence",)),
            ("reports", ("lineage_id",)),
            ("report_versions", ("report_id", "version")),
            ("ai_models", ("family", "name", "version")),
            ("organisations", ("slug",)),
            ("roles", ("code",)),
            ("permissions", ("code",)),
        ],
    )
    def test_declared_unique_constraints_exist(
        self, table_name: str, columns: tuple[str, ...]
    ) -> None:
        found = _unique_column_tuples(table_name)
        assert columns in found, f"{table_name} has no UNIQUE {columns}; it has {sorted(found)}"

    @pytest.mark.parametrize(
        ("table_name", "index_name"),
        [
            ("users", "uq_users_email_lower"),
            ("users", "uq_users_username_lower"),
            ("user_roles", "uq_user_roles_user_role"),
            ("user_roles", "uq_user_roles_primary_active"),
            ("ai_models", "uq_ai_models_default_per_family_task"),
            ("analysis_jobs", "uq_analysis_jobs_idempotency_key"),
        ],
    )
    def test_unique_indexes_exist_where_a_constraint_cannot_express_the_rule(
        self, table_name: str, index_name: str
    ) -> None:
        indexes = {str(index.name): index for index in table(table_name).indexes}
        assert index_name in indexes, f"{table_name} is missing {index_name}"
        assert indexes[index_name].unique, f"{index_name} is not unique"

    def test_email_uniqueness_is_case_insensitive(self) -> None:
        """§3.1 asks for ``citext``; a functional index on ``lower(email)`` is the same guarantee.

        Without it, ``Admin@x`` and ``admin@x`` are two accounts — and for a platform where an
        account is an actor in an audit trail, two accounts for one person is a defect that only
        shows up during an investigation.
        """
        index = _index(table("users"), "uq_users_email_lower")
        assert [_expression_name(expression) for expression in index.expressions] == [
            "lower(email)"
        ]

    @pytest.mark.parametrize(
        ("table_name", "index_name", "expected_predicate"),
        [
            # A soft-deleted account must not burn its email address or its username forever.
            ("users", "ix_users_active_email", "deleted_at IS NULL"),
            ("users", "uq_users_username_lower", "username IS NOT NULL"),
            # A revoked grant must not block re-granting the same primary role.
            ("user_roles", "uq_user_roles_primary_active", "revoked_at IS NULL"),
            # A deprecated model must not hold the family's default slot.
            ("ai_models", "uq_ai_models_default_per_family_task", "is_default"),
        ],
    )
    def test_partial_indexes_exclude_the_rows_that_no_longer_apply(
        self, table_name: str, index_name: str, expected_predicate: str
    ) -> None:
        predicate = _predicate(_index(table(table_name), index_name))
        assert predicate is not None, f"{index_name} is not a partial index"
        assert expected_predicate in str(predicate)

    def test_derivative_deduplication_covers_case_level_artifacts(self) -> None:
        """``NULLS NOT DISTINCT``, so a retried job cannot add a second case-level artifact.

        With PostgreSQL's default (NULLs distinct) every retry of a derivative with no
        ``evidence_id`` would insert a new row and the constraint would be decoration.
        """
        constraint = next(
            item
            for item in table("derivatives").constraints
            if getattr(item, "name", None) == "uq_derivatives_retry_safe"
        )
        options = constraint.dialect_options["postgresql"]
        assert options.get("nulls_not_distinct") is True


class TestIndexing:
    @pytest.mark.parametrize("name", sorted(CASE_SCOPED_TABLES))
    def test_case_scoped_tables_index_on_case_id(self, name: str) -> None:
        """§10: ``case_id`` leads, because the authorization choke point always supplies it."""
        indexed_columns = {
            tuple(_expression_name(expression) for expression in index.expressions)
            for index in table(name).indexes
        }
        leading = {columns[0] for columns in indexed_columns if columns}
        assert "case_id" in leading, (
            f"{name} has no index leading with case_id: {sorted(indexed_columns)}"
        )

    def test_the_verification_backlog_query_is_indexed(self) -> None:
        """§10's partial index: what a reviewer is waiting for must stay cheap as the table grows."""
        index = _index(table("analysis_results"), "ix_analysis_results_verification_backlog")
        predicate = str(_predicate(index))
        assert "verification_status" in predicate
        assert "is_current" in predicate
        assert index.unique is False

    def test_gin_indexes_back_the_jsonb_and_array_columns(self) -> None:
        gin = {
            (name, str(index.name))
            for name in EXPECTED_TABLES
            for index in table(name).indexes
            if index.dialect_options["postgresql"].get("using") == "gin"
        }
        assert ("cases", "ix_cases_tags_gin") in gin
        assert ("cases", "ix_cases_search_vector_gin") in gin
        assert ("evidence_items", "ix_evidence_items_tags_gin") in gin
        assert ("analysis_results", "ix_analysis_results_indicators_gin") in gin


class TestRelationships:
    @pytest.mark.parametrize(
        ("model", "attribute", "target"),
        [
            ("User", "role_assignments", "UserRole"),
            ("UserRole", "role", "Role"),
            ("Role", "permissions", "Permission"),
            ("Permission", "roles", "Role"),
            ("RolePermission", "role", "Role"),
            ("RolePermission", "permission", "Permission"),
            ("Case", "evidence_items", "EvidenceItem"),
            ("EvidenceItem", "case", "Case"),
            ("EvidenceItem", "physical_object", "PhysicalObject"),
            ("EvidenceItem", "children", "EvidenceItem"),
            ("EvidenceItem", "custody_events", "CustodyEvent"),
            ("CustodyEvent", "evidence", "EvidenceItem"),
            ("AnalysisJob", "results", "AnalysisResult"),
            ("AnalysisResult", "job", "AnalysisJob"),
            ("AnalysisResult", "supersedes", "AnalysisResult"),
            ("Report", "versions", "ReportVersion"),
            ("ReportVersion", "report", "Report"),
            ("Report", "current", "ReportVersion"),
            ("ReportVersion", "pdf_derivative", "Derivative"),
            ("AIProviderSettings", "default_model", "AIModel"),
            ("AIModel", "provider_defaults", "AIProviderSettings"),
            ("Case", "members", "CaseMember"),
            ("CaseMember", "case", "Case"),
            ("AuditLog", "case", "Case"),
            ("CaseNote", "evidence", "EvidenceItem"),
            ("Derivative", "produced_by_job", "AnalysisJob"),
            ("Notification", "user", "User"),
        ],
    )
    def test_typed_relationships_point_where_the_domain_says(
        self, model: str, attribute: str, target: str
    ) -> None:
        """The relationships later milestones navigate, asserted as data.

        A relationship whose direction or target is wrong is not caught by any other test in this
        suite: the column exists, the foreign key is right, and the query only fails when a service
        in M4 tries to follow it.
        """
        mapper = _mapper(model)
        assert attribute in mapper.relationships, f"{model}.{attribute} is not a relationship"
        relationship = mapper.relationships[attribute]
        assert relationship.entity.entity == _model_class(target), (
            f"{model}.{attribute} points at {relationship.entity.entity}, not {target}"
        )

    def test_the_user_role_permission_chain_is_navigable(self) -> None:
        """user → assignment → role → permission, which is the query M3's authorization runs."""
        user = _mapper("User")
        assert user.relationships["role_assignments"].entity.entity is _model_class("UserRole")
        assert _mapper("UserRole").relationships["role"].entity.entity is _model_class("Role")
        assert _mapper("Role").relationships["permissions"].entity.entity is _model_class(
            "Permission"
        )

    def test_report_current_version_is_read_only(self) -> None:
        """Assigning to it would move the pointer without updating the integer that defines it."""
        assert _mapper("Report").relationships["current"].viewonly is True

    def test_self_referential_relationships_are_separated(self) -> None:
        """``parent``/``children`` on evidence and on notes must not collapse into one another."""
        evidence = _mapper("EvidenceItem")
        assert evidence.relationships["parent"].entity.entity is evidence.class_
        assert evidence.relationships["children"].entity.entity is evidence.class_
        note = _mapper("CaseNote")
        assert note.relationships["parent"].entity.entity is note.class_


class TestTimestamps:
    @pytest.mark.parametrize("name", sorted(EXPECTED_TABLES - APPEND_ONLY_TABLES))
    def test_every_table_records_when_a_row_was_created(self, name: str) -> None:
        column = table(name).columns.get("created_at")
        assert column is not None, f"{name} has no created_at"
        assert column.nullable is False
        assert isinstance(column.type, DateTime), f"{name}.created_at must be a datetime (§1 DB-6)"
        assert column.type.timezone is True, f"{name}.created_at must be timestamptz (§1 DB-6)"
        assert "now()" in _default_text(column), (
            f"{name}.created_at must default server-side, so a wrong client clock cannot write it"
        )

    @pytest.mark.parametrize(
        "name",
        sorted(
            EXPECTED_TABLES
            - APPEND_ONLY_TABLES
            - {"derivatives", "analysis_results", "report_versions"}
        ),
    )
    def test_mutable_tables_maintain_updated_at(self, name: str) -> None:
        column = table(name).columns.get("updated_at")
        assert column is not None, f"{name} has no updated_at"
        assert column.nullable is False
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True

    @pytest.mark.parametrize(
        ("name", "event_column"),
        [("custody_events", "acted_at"), ("audit_logs", "occurred_at")],
    )
    def test_ledgers_stamp_when_the_event_happened_not_when_the_row_arrived(
        self, name: str, event_column: str
    ) -> None:
        """These two tables carry no ``created_at``: the time a transfer was acted on is the fact.

        An insert time on a ledger invites code to order events by it, and a retried or backfilled
        write would then reorder the history the ledger exists to preserve.
        """
        assert "created_at" not in table(name).columns
        column = table(name).columns[event_column]
        assert column.nullable is False
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True

    @pytest.mark.parametrize("name", sorted(APPEND_ONLY_TABLES))
    def test_append_only_tables_have_no_updated_at_and_no_soft_delete(self, name: str) -> None:
        """A column that does not exist cannot be written by a future refactor.

        ``custody_events`` and ``audit_logs`` carry their event time (``acted_at``/``occurred_at``)
        and nothing else: a second, insert-time timestamp is an invitation for code to use the wrong
        one, and ``deleted_at`` on an append-only ledger is a contradiction.
        """
        columns = set(table(name).columns.keys())
        assert "updated_at" not in columns
        assert "deleted_at" not in columns

    @pytest.mark.parametrize(
        "name", sorted({"users", "cases", "evidence_items", "case_notes", "reports"})
    )
    def test_soft_deletable_tables_carry_deleted_at(self, name: str) -> None:
        """§1.1 and §12: deactivation, not erasure — attribution survives."""
        column = table(name).columns.get("deleted_at")
        assert column is not None
        assert column.nullable is True
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True

    def test_no_timestamp_column_is_naive(self) -> None:
        """DB-6 in one sweep: every datetime column in the schema stores an instant, not a reading."""
        naive = [
            f"{name}.{column.name}"
            for name in EXPECTED_TABLES
            for column in table(name).columns
            if isinstance(column.type, DateTime) and column.type.timezone is not True
        ]
        assert not naive, f"naive timestamp columns: {naive}"


class TestSecurityProperties:
    def test_no_column_can_hold_a_plaintext_password(self) -> None:
        """The one requirement that needs no explanation.

        Exactly three columns may mention a password: the argon2id encoded hash, the algorithm that
        produced it, and when it last changed. Anything else with "password" in the name is a
        defect, and this test names it.
        """
        allowed = {"password_hash", "password_alg", "password_changed_at"}
        found = {
            column.name
            for name in EXPECTED_TABLES
            for column in table(name).columns
            if "password" in column.name.lower() or "secret" in column.name.lower()
        }
        assert found <= allowed | {"mfa_secret_encrypted"}, (
            f"unexpected credential columns: {sorted(found)}"
        )
        assert "password_hash" in found

    def test_the_password_column_stores_a_hash_not_a_password(self) -> None:
        """``text``, because an argon2id encoded string carries its own algorithm and parameters."""
        column = table("users").columns["password_hash"]
        assert column.nullable is False
        assert column.type.__class__.__name__ == "Text"

    def test_no_column_can_hold_evidence_bytes(self) -> None:
        """DB-1: metadata in PostgreSQL, bytes on disk.

        The only opaque binary columns in the schema are the encrypted secrets and the wrapped
        encryption key. A ``bytea``
        column on an evidence table would mean originals in the database — which §4.1 forbids, which
        the backup strategy is not sized for, and which turns every database dump into a copy of
        the evidence store.
        """
        binary = {
            f"{name}.{column.name}"
            for name in EXPECTED_TABLES
            for column in table(name).columns
            if isinstance(column.type, LargeBinary)
        }
        assert binary == set(ENCRYPTED_SECRET_COLUMNS)

    def test_evidence_is_referenced_by_path_and_digest_not_stored(self) -> None:
        columns = table("physical_objects").columns
        assert "storage_path" in columns
        assert "storage_backend" in columns
        assert "sha256" in columns
        assert columns["sha256"].nullable is False
        assert columns["sha256"].unique is True

    def test_original_filenames_are_data_and_never_a_path(self) -> None:
        """§4.2: the verbatim name is preserved for the record, a sanitised one is used for display,
        and ``physical_objects.storage_path`` is built from neither."""
        columns = table("evidence_items").columns
        assert "original_filename" in columns
        assert "sanitized_filename" in columns
        assert columns["original_filename"].nullable is False
        assert columns["sanitized_filename"].nullable is False

    def test_secrets_are_only_ever_stored_encrypted_or_by_reference(self) -> None:
        provider = table("ai_provider_settings").columns
        assert "api_key_encrypted" in provider
        assert "api_key_ref" in provider
        assert "api_key" not in provider
        assert isinstance(provider["api_key_encrypted"].type, LargeBinary)

    def test_custody_chain_fields_exist_without_implementing_the_algorithm(self) -> None:
        """The milestone forbids implementing the hash chain; the columns must still be here.

        Adding ``prev_hash``/``record_hash`` to a populated ledger later means rewriting history, and
        a rewritten history is worthless as evidence — so the shape arrives now and the
        canonicalisation arrives in M6.
        """
        for name in ("custody_events", "audit_logs"):
            columns = table(name).columns
            assert "prev_hash" in columns
            assert "record_hash" in columns
            assert columns["prev_hash"].nullable is False
            assert columns["record_hash"].nullable is False
            assert "sequence" in columns

    def test_honesty_constraints_are_declared_on_analysis_results(self) -> None:
        """§5.2's four CHECK constraints, by name.

        They are the mechanism that makes "findings are indicators, not verdicts" true in the
        database rather than only in the documentation: no code path can persist a score without an
        interval, a confidence without a basis, or a verdict without notes.
        """
        required = {
            "ck_analysis_results_score_requires_confidence_interval",
            "ck_analysis_results_confidence_requires_basis",
            "ck_analysis_results_verdict_requires_notes",
            "ck_analysis_results_unverified_has_no_verifier",
        }
        found = _check_constraint_names("analysis_results")
        assert required <= found, f"missing honesty constraints: {sorted(required - found)}"

    def test_human_verification_defaults_to_required(self) -> None:
        """ADR-0023. The default is the safety property: an omission produces the safe value."""
        column = table("analysis_results").columns["requires_human_verification"]
        assert column.nullable is False
        assert _default_text(column) == "true"

    def test_external_egress_defaults_to_closed(self) -> None:
        """ADR-0012. A row created by a migration with no other values must permit nothing."""
        columns = table("ai_provider_settings").columns
        assert _default_text(columns["allow_external_egress"]) == "false"
        assert _default_text(columns["is_enabled"]) == "false"
        assert _default_text(columns["requires_confirmation"]) == "true"
        assert "ck_ai_provider_settings_egress_requires_confirmation" in _check_constraint_names(
            "ai_provider_settings"
        )

    def test_legal_hold_defaults_to_holding(self) -> None:
        """§12: an oversight must block destruction, not permit it."""
        assert _default_text(table("cases").columns["legal_hold"]) == "true"


class TestEnumVocabulary:
    #: Transcribed from ``DATABASE_DESIGN.md`` §9 and ``SECURITY_ARCHITECTURE.md`` §4.2. A drift here
    #: is a drift between the ratified vocabulary and the database, and it shows up as a CHECK
    #: constraint or a seeded row that matches nothing.
    EXPECTED: Final[dict[str, tuple[str, ...]]] = {
        "global_role": (
            "admin",
            "lead_investigator",
            "investigator",
            "analyst",
            "reviewer",
            "auditor",
        ),
        "user_status": ("active", "suspended", "pending_activation", "deactivated"),
        "password_alg": ("argon2id", "bcrypt_legacy"),
        "case_role": ("owner", "lead", "member", "contributor", "viewer"),
        "case_status": ("draft", "active", "under_review", "closed", "archived"),
        "sensitivity": ("public", "internal", "confidential", "restricted"),
        "evidence_type": ("image", "video", "audio", "document", "archive", "text", "other"),
        "evidence_status": (
            "ingesting",
            "hashing",
            "stored",
            "analysis_pending",
            "failed",
            "quarantined",
            "integrity_failed",
        ),
        "integrity_status": ("unverified", "verified", "mismatch", "missing"),
        "source_type": ("upload", "intake_directory", "api", "third_party", "extracted_child"),
        "enc_state": ("none", "aes256gcm_envelope"),
        "custody_event_type": (
            "ingested",
            "hash_computed",
            "hash_verified",
            "accessed",
            "downloaded",
            "analyzed",
            "verification_set",
            "custody_transferred",
            "custody_accepted",
            "legal_hold",
            "released",
            "exported",
            "quarantined",
            "integrity_alert",
        ),
        "derivative_kind": (
            "thumbnail",
            "frame",
            "heatmap",
            "overlay",
            "transcript",
            "spectrogram",
            "waveform",
            "extracted_audio",
            "extracted_file",
            "report_pdf",
            "graph_image",
            "annotation",
            "masked_preview",
        ),
        "artifact_status": ("available", "stale", "purged", "failed"),
        "job_status": (
            "queued",
            "running",
            "succeeded",
            "failed",
            "cancelled",
            "retrying",
            "dead_letter",
        ),
        "verification_status": ("unverified", "confirmed", "rejected", "inconclusive"),
        "model_status": ("active", "deprecated", "retired"),
        "report_status": ("generating", "draft", "final", "superseded", "failed"),
        "audit_result": ("success", "failure", "denied"),
    }

    def test_native_enum_types_carry_the_documented_values(self) -> None:
        found: dict[str, tuple[str, ...]] = {}
        for name in EXPECTED_TABLES:
            for column in table(name).columns:
                column_type = column.type
                if isinstance(column_type, SAEnum):
                    assert column_type.name is not None, f"{name}.{column.name} has an unnamed enum"
                    found[column_type.name] = tuple(column_type.enums)
        assert set(found) == set(self.EXPECTED), (
            f"enum types differ from §9: missing {sorted(set(self.EXPECTED) - set(found))}, "
            f"unexpected {sorted(set(found) - set(self.EXPECTED))}"
        )
        for type_name, values in self.EXPECTED.items():
            assert found[type_name] == values, (
                f"{type_name} is {found[type_name]}, §9 says {values}"
            )

    def test_enum_labels_are_lower_snake_case_values_not_python_names(self) -> None:
        """The whole vocabulary is spelled in lowercase in the documentation, the CHECK constraints
        and the seeded rows. Storing ``LEAD_INVESTIGATOR`` would make every one of them match
        nothing — and the failure would be a query that silently returns no rows."""
        for name in EXPECTED_TABLES:
            for column in table(name).columns:
                if isinstance(column.type, SAEnum):
                    for label in column.type.enums:
                        assert label == label.lower(), f"{name}.{column.name} stores {label!r}"
                        assert " " not in label

    def test_growing_vocabularies_are_text_not_enums(self) -> None:
        """§9's asymmetry rule: PostgreSQL cannot drop an enum value.

        These vocabularies grow with features and deployments, so fixing them as native types would
        guarantee a table rewrite the first time somebody adds a provider or a queue.
        """
        for table_name, column_name in (
            ("ai_provider_settings", "provider"),
            ("notifications", "kind"),
            ("analysis_jobs", "queue"),
            ("audit_logs", "action"),
            ("cases", "case_type"),
        ):
            column = table(table_name).columns[column_name]
            assert not isinstance(column.type, SAEnum), (
                f"{table_name}.{column_name} must stay text — its vocabulary grows"
            )


class TestNaming:
    def test_constraint_names_are_deterministic(self) -> None:
        """DB-7 and §11 require deterministic migrations.

        Without a naming convention SQLAlchemy derives constraint names from a hash of the column
        expressions, so the same model change can produce a different name on a different machine —
        and renaming a constraint later means dropping and recreating it on a table holding evidence.
        """
        unnamed = []
        for name in EXPECTED_TABLES:
            for constraint in table(name).constraints:
                if not getattr(constraint, "name", None):
                    unnamed.append(f"{name}.{constraint.__class__.__name__}")
        assert not unnamed, f"constraints without a deterministic name: {unnamed}"

    def test_constraint_names_follow_the_convention(self) -> None:
        prefixes = {
            "UniqueConstraint": "uq_",
            "CheckConstraint": "ck_",
            "ForeignKeyConstraint": "fk_",
            "PrimaryKeyConstraint": "pk_",
        }
        mismatched = []
        for name in EXPECTED_TABLES:
            for constraint in table(name).constraints:
                expected = prefixes.get(constraint.__class__.__name__)
                if expected and not str(constraint.name).startswith(expected):
                    mismatched.append(f"{name}.{constraint.name}")
        assert not mismatched, f"constraint names off-convention: {mismatched}"

    def test_indexes_are_prefixed_by_kind(self) -> None:
        mismatched = [
            f"{name}.{index.name}"
            for name in EXPECTED_TABLES
            for index in table(name).indexes
            if index.name and not index.name.startswith(("ix_", "uq_"))
        ]
        assert not mismatched, f"index names off-convention: {mismatched}"

    def test_check_constraints_are_all_named(self) -> None:
        """An unnamed CHECK is unnameable in an error message, so an operator cannot tell which rule
        refused their write."""
        for name in EXPECTED_TABLES:
            for constraint in table(name).constraints:
                if isinstance(constraint, CheckConstraint):
                    assert constraint.name, f"{name} has an unnamed CHECK constraint"


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────


def _mapper(name: str) -> Mapper[Any]:
    """The mapper of a mapped class, looked up by name from the registry rather than by import.

    By name, so the test states the class it means in the same vocabulary as the assertion, and a
    renamed class fails here with the old name in the message instead of failing at import.
    """
    for mapper in Base.registry.mappers:
        if mapper.class_.__name__ == name:
            return mapper
    raise AssertionError(f"no mapped class named {name}")


def _model_class(name: str) -> type[Any]:
    """The mapped class itself, for identity comparisons against a relationship's target."""
    return _mapper(name).class_


def _default_text(column: Column[Any]) -> str:
    """The SQL of a column's server default, asserting that it has one.

    A default that silently became NULL is the difference between "new evidence is held by default"
    and "new evidence is not held", so the absence is asserted rather than rendered as the string
    "None" and compared against.
    """
    default = column.server_default
    assert isinstance(default, DefaultClause), (
        f"{column.table.name}.{column.name} has no SQL server default (got {default!r})"
    )
    return str(default.arg)


def _unique_column_tuples(name: str) -> set[tuple[str, ...]]:
    """The column tuples of every UNIQUE constraint on a table."""
    return {
        tuple(column.name for column in constraint.columns)
        for constraint in table(name).constraints
        if isinstance(constraint, UniqueConstraint)
    }


def _foreign_key_constraints(target: Table) -> list[ForeignKeyConstraint]:
    return [
        constraint
        for constraint in target.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    ]


def _composite_foreign_keys_to_evidence() -> list[ForeignKeyConstraint]:
    return [
        constraint
        for name in EXPECTED_TABLES
        for constraint in _foreign_key_constraints(table(name))
        if constraint.referred_table.name == "evidence_items" and len(constraint.columns) > 1
    ]


def _only_foreign_key_to(target: Table, referred: str) -> ForeignKeyConstraint:
    matches = [
        constraint
        for constraint in _foreign_key_constraints(target)
        if constraint.referred_table.name == referred
    ]
    assert len(matches) == 1, (
        f"expected one foreign key from {target.name} to {referred}, got {len(matches)}"
    )
    return matches[0]


def _index(target: Table, name: str) -> Index:
    for index in target.indexes:
        if index.name == name:
            return index
    raise AssertionError(
        f"{target.name} has no index named {name}; it has {sorted(i.name or '' for i in target.indexes)}"
    )


def _predicate(index: Index) -> object:
    return index.dialect_options["postgresql"].get("where")


def _expression_name(expression: object) -> str:
    """The index's own spelling of one expression: a column name, or the SQL of a functional one."""
    name = getattr(expression, "name", None)
    return str(name) if name else str(expression)


def _check_constraint_names(name: str) -> set[str]:
    return {
        str(constraint.name)
        for constraint in table(name).constraints
        if isinstance(constraint, CheckConstraint)
    }
