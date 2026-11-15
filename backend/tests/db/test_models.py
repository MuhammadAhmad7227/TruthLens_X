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
    CHAR,
    CheckConstraint,
    Column,
    DateTime,
    DefaultClause,
    Enum as SAEnum,
    ForeignKeyConstraint,
    Index,
    Interval,
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
    # §5.3, and roadmap 2.3 names it: the versioned AR-4 disclaimer corpus that
    # ``analysis_results.limitations_code`` has pointed at since revision 0001.
    "limitation_statements": "limitation_statements",
    "evidence_artifacts": "derivatives",
    "case_notes": "case_notes",
    "reports": "reports",
    "report_versions": "report_versions",
    "audit_logs": "audit_logs",
    "model_registry": "ai_models",
    "ai_provider_settings": "ai_provider_settings",
    "notifications": "notifications",
    "user_sessions": "user_sessions",
    "ai_conversations": "ai_conversations",
    "ai_messages": "ai_messages",
    "integrity_checks": "integrity_checks",
    "system_settings": "system_settings",
    "feature_flags": "feature_flags",
    "retention_policies": "retention_policies",
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
    {
        "custody_events",
        "audit_logs",
        "analysis_jobs",
        "derivatives",
        # The three additions are all high-volume and written in time order: one row per login, per
        # assistant turn, per swept object. None of their ids is published outside the platform, so
        # ADR-0009's disclosure concern does not reach them.
        "user_sessions",
        "ai_messages",
        "integrity_checks",
    }
)
UUIDV4_TABLES: Final[frozenset[str]] = frozenset(
    {
        "users",
        "cases",
        "evidence_items",
        "physical_objects",
        "ai_models",
        "reports",
        # Externally visible in API paths, or addressable by an administrator, so their ids must not
        # carry a timestamp anybody outside can read.
        "ai_conversations",
        "system_settings",
        "feature_flags",
        "retention_policies",
    }
)

#: Principle DB-3: append-only. No updated_at, no deleted_at, and UPDATE/DELETE revoked from the
#: application role by the migration.
APPEND_ONLY_TABLES: Final[frozenset[str]] = frozenset(
    {
        "custody_events",
        "audit_logs",
        # §10 lists integrity checks beside the ledgers: append-only, partitioned monthly, rolled to
        # cold storage after 24 months. A sweep result is an observation, and revision 0003 revokes
        # UPDATE/DELETE/TRUNCATE on it from the application roles exactly as 0001 does for these two.
        "integrity_checks",
    }
)

#: Tables that carry the time of the event they record instead of the time the row arrived, and so
#: have no ``created_at``. The two ledgers, plus the two logs added by revision 0003: a session's
#: ``issued_at`` and a sweep's ``checked_at`` are the facts, and an insert-time column beside either
#: would invite code to order history by the wrong one.
EVENT_TIME_TABLES: Final[dict[str, str]] = {
    "custody_events": "acted_at",
    "audit_logs": "occurred_at",
    "integrity_checks": "checked_at",
    "user_sessions": "issued_at",
}

#: Written once and never edited, so no ``updated_at``: a transcript entry (AI-08's regenerate
#: *appends* a turn) and a session, whose only change is revocation and which records that with
#: ``revoked_at`` — a more precise answer than a generic "last updated" would be.
WRITE_ONCE_TABLES: Final[frozenset[str]] = frozenset({"ai_messages", "user_sessions"})

#: Tables whose primary key is the identity the document specifies rather than a surrogate ``id``.
#: ``case_members`` and ``role_permissions`` are associations, and §5.3 makes ``(code, version)`` the
#: identity of a disclaimer: two rows both claiming to be ELA version 3 would be two answers to
#: "what was this finding's limitation", which is the ambiguity versioning exists to remove.
COMPOSITE_KEY_TABLES: Final[frozenset[str]] = frozenset(
    {"case_members", "role_permissions", "limitation_statements"}
)

#: Tables ``DATABASE_DESIGN.md`` specifies exhaustively, so the house timestamp convention does not
#: reach them. §5.3 names six columns for ``limitation_statements`` and no others: its place in time
#: is ``effective_from``/``effective_to``, the window a wording was in force, and an ``updated_at``
#: beside that would record edits to text a report may already have printed. The version number is
#: the honest answer to "which wording was this". :class:`TestLimitationCorpus` asserts the column
#: set exactly, so this exclusion cannot become a way to grow the table quietly.
TIMESTAMP_FREE_TABLES: Final[frozenset[str]] = frozenset({"limitation_statements"})

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
        # §8.2 / AI-01: retrieval is hard-scoped to a case, so every conversation belongs to one.
        # ``ai_messages`` is deliberately absent — it reaches its case through its conversation.
        "ai_conversations",
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

    @pytest.mark.parametrize("name", sorted(EXPECTED_TABLES - COMPOSITE_KEY_TABLES))
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

    @pytest.mark.parametrize("name", ["audit_logs", "custody_events"])
    def test_ledgers_outlive_the_case_they_record(self, name: str) -> None:
        """§12: custody and audit history is never deleted, and neither is a case's record of it.

        ``RESTRICT`` on the case reference means destroying a case cannot take its history with it —
        not through a service rule, but because the database refuses the statement.

        Parametrised over the two ledgers rather than over ``APPEND_ONLY_TABLES``: the third
        append-only table, ``integrity_checks``, references a *physical object* rather than a case,
        and has its own ``RESTRICT`` assertion below. Feeding it here would fail on "does not
        reference cases at all" — a true statement about a table that is nonetheless append-only.
        """
        to_cases = [
            constraint
            for constraint in _foreign_key_constraints(table(name))
            if constraint.referred_table.name == "cases"
        ]
        assert to_cases, f"{name} does not reference cases at all"
        assert all(constraint.ondelete == "RESTRICT" for constraint in to_cases)

    def test_integrity_history_outlives_the_object_it_describes(self) -> None:
        """``RESTRICT`` on the object, for the same reason the ledgers restrict the case.

        §12 permits destroying an original only with an administrator, a justification, a second
        approver and an audit record — and that approval was granted against a known integrity
        history. An object whose bytes once failed verification and were then deleted, taking the
        failed row with them, is indistinguishable from tampering. §10 already gives these rows a
        lifecycle (cold storage after 24 months), so the approved path archives them.
        """
        constraint = _only_foreign_key_to(table("integrity_checks"), "physical_objects")
        assert constraint.ondelete == "RESTRICT"

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
            ("LimitationStatement", "approved_by_user", "User"),
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
    @pytest.mark.parametrize(
        "name",
        sorted(
            EXPECTED_TABLES - APPEND_ONLY_TABLES - TIMESTAMP_FREE_TABLES - set(EVENT_TIME_TABLES)
        ),
    )
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
            - WRITE_ONCE_TABLES
            - TIMESTAMP_FREE_TABLES
            - {"derivatives", "analysis_results", "report_versions"}
        ),
    )
    def test_mutable_tables_maintain_updated_at(self, name: str) -> None:
        column = table(name).columns.get("updated_at")
        assert column is not None, f"{name} has no updated_at"
        assert column.nullable is False
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True

    @pytest.mark.parametrize(("name", "event_column"), sorted(EVENT_TIME_TABLES.items()))
    def test_logs_stamp_when_the_event_happened_not_when_the_row_arrived(
        self, name: str, event_column: str
    ) -> None:
        """These tables carry no ``created_at``: the time the thing happened is the fact.

        An insert time on a log invites code to order events by it, and a retried or backfilled write
        would then reorder the history the table exists to preserve.
        """
        assert "created_at" not in table(name).columns
        column = table(name).columns[event_column]
        assert column.nullable is False
        assert isinstance(column.type, DateTime)
        assert column.type.timezone is True

    @pytest.mark.parametrize("name", sorted(APPEND_ONLY_TABLES | WRITE_ONCE_TABLES))
    def test_append_only_tables_have_no_updated_at_and_no_soft_delete(self, name: str) -> None:
        """A column that does not exist cannot be written by a future refactor.

        ``custody_events``, ``audit_logs`` and ``integrity_checks`` carry their event time and nothing
        else: a second, insert-time timestamp is an invitation for code to use the wrong one, and
        ``deleted_at`` on an append-only ledger is a contradiction. ``ai_messages`` and
        ``user_sessions`` are here for the same structural reason — a transcript entry is never
        edited, and a session's only change is revocation, which ``revoked_at`` records precisely.
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
        # §9 names chat_role; ai_message_status carries the three outcomes §8.2 specifies in prose
        # without declaring a type, so the type is named in app/models/enums.py.
        "chat_role": ("system", "user", "assistant", "tool"),
        "ai_message_status": ("succeeded", "failed", "refused"),
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
            # Revision 0003's additions. A provider list the two documents do not even spell the same
            # way; a conversation status §8.2 names without a vocabulary; retention scopes, actions
            # and clock-start events, which grow with the lifecycle features M4 adds.
            ("ai_conversations", "provider"),
            ("ai_conversations", "status"),
            ("retention_policies", "scope"),
            ("retention_policies", "action"),
            ("retention_policies", "keep_until_event"),
            ("system_settings", "key"),
            ("feature_flags", "key"),
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


class TestSessionCredentials:
    """§3.2: the durable half of authentication state, holding nothing replayable."""

    #: Transcribed from §3.2's column table. An exact set comparison, not a subset: a column nobody
    #: specified is a column whose purpose nobody has stated, and on a credentials table that is the
    #: one place "we added it later and it seemed useful" must not be allowed to pass silently.
    COLUMNS: Final[frozenset[str]] = frozenset(
        {
            "id",
            "user_id",
            "refresh_token_hash",
            "family_id",
            "issued_at",
            "expires_at",
            "revoked_at",
            "ip",
            "user_agent",
        }
    )

    def test_the_table_is_exactly_the_columns_the_design_specifies(self) -> None:
        assert set(table("user_sessions").columns.keys()) == set(self.COLUMNS)

    def test_the_token_is_stored_as_a_fixed_width_digest(self) -> None:
        """A bearer credential stored in the clear is replayable by anyone who can read the row —
        a stolen backup, an over-broad SELECT, a ``tlx_auditor`` session."""
        column = table("user_sessions").columns["refresh_token_hash"]
        assert column.nullable is False
        assert column.unique is True, "rotation presents a token, so the lookup must be unique"
        assert _char_width(column) == 64
        assert "ck_user_sessions_refresh_token_hash_is_lowercase_hex" in _check_constraint_names(
            "user_sessions"
        )

    def test_there_is_no_column_that_could_hold_the_token_itself(self) -> None:
        """The structural version of the assertion above: no spare text column to put one in.

        ``user_agent`` is the only free-text column, and it is a client-supplied description, not a
        credential. A ``token`` or ``refresh_token`` column added later fails here with its name in
        the message rather than arriving in a database dump.
        """
        # A set of names, not the ColumnCollection: iterating that yields Column objects, and
        # `"token" in column` is a SQL expression rather than a substring test.
        names = set(table("user_sessions").columns.keys())
        credential_shaped = sorted(
            name for name in names if "token" in name and name != "refresh_token_hash"
        )
        assert not credential_shaped, f"columns that could hold a token: {credential_shaped}"

    def test_sessions_outlive_the_account_they_belong_to(self) -> None:
        """``RESTRICT``, per §3.2: deleting a user must not erase the record that they authenticated,
        from where, with what client. §12 deactivates users rather than erasing them while cases
        reference them, and this is the same rule applied to their login history."""
        assert _only_foreign_key_to(table("user_sessions"), "users").ondelete == "RESTRICT"

    def test_rotation_can_find_a_whole_family_including_the_revoked_tokens(self) -> None:
        """Reuse detection revokes the *family* when an already-rotated token is presented.

        ``family_id`` is NOT NULL — a session outside any family could not be revoked by association,
        which is the whole defence — and its index is deliberately **not** partial: the token an
        attacker replays is one that has already been rotated, so it is revoked, and an index over
        live sessions only would not find it.
        """
        columns = table("user_sessions").columns
        assert columns["family_id"].nullable is False
        index = _index(table("user_sessions"), "ix_user_sessions_family")
        assert _predicate(index) is None, "a partial index here could not find a rotated token"
        assert [_expression_name(expression) for expression in index.expressions] == ["family_id"]

    def test_the_active_session_query_is_indexed(self) -> None:
        """``revoked_at IS NULL`` is the predicate every authentication check runs."""
        index = _index(table("user_sessions"), "ix_user_sessions_user_active")
        assert "revoked_at IS NULL" in str(_predicate(index))

    def test_a_session_cannot_expire_before_it_was_issued(self) -> None:
        required = {
            "ck_user_sessions_expiry_after_issue",
            "ck_user_sessions_revocation_after_issue",
        }
        assert required <= _check_constraint_names("user_sessions")

    def test_there_is_no_revoked_by_column(self) -> None:
        """Unlike ``user_roles`` and ``case_members``, a session revocation has no human actor.

        Reuse detection revokes a family automatically, and requiring an actor there would either
        fabricate one or block the revocation. Who detected the reuse is an ``audit_logs`` row.
        """
        assert "revoked_by" not in table("user_sessions").columns
        assert "revocation_names_an_actor" not in " ".join(_check_constraint_names("user_sessions"))

    def test_the_ip_is_an_inet_not_a_string(self) -> None:
        """So PostgreSQL validates the literal and can answer "every session from this subnet" —
        the question an incident response into a compromised account actually asks."""
        assert table("user_sessions").columns["ip"].type.__class__.__name__ == "INET"


class TestAssistantHonesty:
    """§8.2, AI-02, AI-04 and ``AI_ARCHITECTURE.md`` §10."""

    def test_an_assistant_turn_must_cite_case_data_or_declare_itself_unsupported(self) -> None:
        """AI-02 as a database constraint rather than a prompt instruction.

        The guardrail prompt is the first line of defence and a model can ignore it; a CHECK cannot be
        ignored. This is what makes an uncited claim unstoreable except as an explicit "the case data
        does not support this", which turns a hallucination from an invisible defect into a recorded
        one.
        """
        sql = _check_sql("ai_messages", "ck_ai_messages_assistant_cites_or_declares_unsupported")
        assert "role <> 'assistant'" in sql
        assert "jsonb_array_length(citations) > 0" in sql
        assert "unsupported = true" in sql

    def test_the_citation_check_does_not_use_cardinality(self) -> None:
        """§8.2 writes ``cardinality(citations)``; PostgreSQL has no ``cardinality(jsonb)``.

        Verified against 16.2: the function does not exist, so the constraint as documented cannot be
        created at all. ``jsonb_array_length`` is the array-length equivalent for JSONB. Asserting the
        absence as well as the presence, because a later "fix" that restores the documented spelling
        would break the migration on a fresh database — and the deviation is recorded in
        ``migrations/README.md``.
        """
        sql = _check_sql("ai_messages", "ck_ai_messages_assistant_cites_or_declares_unsupported")
        assert "cardinality" not in sql

    def test_malformed_citations_are_refused_by_a_named_constraint(self) -> None:
        """``jsonb_array_length`` raises an internal error on a non-array, so the type is checked
        first: both reject the row, but only one tells the operator which rule they broke."""
        sql = _check_sql("ai_messages", "ck_ai_messages_citations_is_a_json_array")
        assert sql == "jsonb_typeof(citations) = 'array'"

    def test_citations_and_retrieval_context_default_to_empty_not_unknown(self) -> None:
        """``[]`` means "nothing was retrieved"; NULL would have meant "we did not record it", and the
        difference between "the case had nothing" and "we did not look" is what AI-01 turns on."""
        columns = table("ai_messages").columns
        for name in ("citations", "retrieval_context"):
            assert columns[name].nullable is False
            assert _default_text(columns[name]) == "'[]'::jsonb"
        assert _default_text(columns["unsupported"]) == "false"

    def test_a_succeeded_turn_names_the_model_that_produced_it(self) -> None:
        """AI-04 (mandatory): model and version logged for every interaction.

        Scoped to ``succeeded`` because a turn that failed or was refused may never have reached a
        model, and requiring one there would force the platform to record a model it did not use.
        """
        sql = _check_sql("ai_messages", "ck_ai_messages_a_succeeded_turn_names_its_model")
        assert "model_name IS NOT NULL" in sql
        assert "model_version IS NOT NULL" in sql
        assert "status <> 'succeeded'" in sql

    def test_the_provenance_rule_binds_assistant_turns_only(self) -> None:
        """A user's question and a tool's retrieval result never reached a model.

        Without the ``role`` clause, ``succeeded`` is unwritable for them — the only statuses left
        would be "failed" and "refused", both of which are lies about a question somebody asked. A
        live-database test in ``test_migrations.py`` stores such a row and would fail without it.
        """
        sql = _check_sql("ai_messages", "ck_ai_messages_a_succeeded_turn_names_its_model")
        assert "role <> 'assistant'" in sql

    def test_model_provenance_is_snapshotted_beside_the_message(self) -> None:
        """A registry row is mutable; "what produced this sentence" must be answerable from the
        message alone, years later, without joining to a table that has since changed."""
        columns = table("ai_messages").columns
        assert "model_name" in columns
        assert "model_version" in columns
        assert columns["model_name"].type.__class__.__name__ == "Text"

    def test_no_assistant_message_can_carry_a_verification_status(self) -> None:
        """``AI_ARCHITECTURE.md`` §10's hard structural rule, tested as structure.

        Not "defaults to unverified" — the column must not exist, so no code path can set one and no
        migration can add it without failing here. An examiner confirms ``analysis_results``; a green
        tick on a chat bubble would be a verification nobody performed.
        """
        columns = set(table("ai_messages").columns.keys())
        verification_shaped = [
            name for name in columns if "verif" in name or name in {"confirmed", "rejected"}
        ]
        assert not verification_shaped, (
            f"assistant output must not be verifiable: {verification_shaped}"
        )
        assert "requires_human_verification" not in columns

    def test_every_turn_records_the_guardrail_and_template_revisions(self) -> None:
        """§8.2 makes ``guardrail_version`` NOT NULL; ``AI_ARCHITECTURE.md`` requires the prompt
        template version on every message too, because §11.1 builds prompts from a *versioned*
        template — an answer reproduced without it is not reproduced.

        Neither has a default: a default would fabricate a revision for any row that forgot to say
        which rules it was written under.
        """
        columns = table("ai_messages").columns
        for name in ("guardrail_version", "prompt_template_version"):
            assert columns[name].nullable is False, f"{name} must be recorded on every turn"
            assert columns[name].server_default is None, f"{name} must not be defaulted"

    def test_a_transcript_cannot_be_edited_in_place(self) -> None:
        """AI-08's regenerate *appends* a turn. An answer an analyst already read, quoted in a note or
        acted on must still exist in the form they saw it, so there is no ``updated_at`` to advance and
        no ``deleted_at`` to hide behind."""
        columns = set(table("ai_messages").columns.keys())
        assert "updated_at" not in columns
        assert "deleted_at" not in columns

    def test_sampling_parameters_are_bounded_only_where_the_bound_is_definitional(self) -> None:
        """``top_p`` is a probability, so [0,1] is not an invented limit. ``temperature`` has no
        universal ceiling across providers, so only its sign is constrained — a scale invented here
        would silently round a provider's own value."""
        names = _check_constraint_names("ai_messages")
        assert "ck_ai_messages_top_p_is_a_probability" in names
        assert "ck_ai_messages_temperature_not_negative" in names
        for column in ("prompt_tokens", "completion_tokens", "latency_ms", "seed"):
            assert (
                f"ck_ai_messages_{'latency' if column == 'latency_ms' else column}_not_negative"
                in names
            )

    def test_conversations_are_hard_scoped_to_a_case(self) -> None:
        """AI-01 / ``AI_ARCHITECTURE.md`` §11.1: a conversation with no case would be a channel to the
        model scoped to nothing, which is the one thing the assistant must not be."""
        column = table("ai_conversations").columns["case_id"]
        assert column.nullable is False
        assert _only_foreign_key_to(table("ai_conversations"), "cases").ondelete == "CASCADE"
        index = _index(table("ai_conversations"), "ix_ai_conversations_case_created")
        assert [_expression_name(expression) for expression in index.expressions] == [
            "case_id",
            "created_at",
        ], "§10: case_id leads, because ACL scoping supplies it to essentially every query"

    def test_the_conversation_owner_is_named_and_cannot_be_erased(self) -> None:
        assert table("ai_conversations").columns["created_by"].nullable is False
        assert _only_foreign_key_to(table("ai_conversations"), "users").ondelete == "RESTRICT"

    def test_a_retired_model_does_not_block_the_threads_that_used_it(self) -> None:
        """``SET NULL``, as ``ai_provider_settings.default_model_id`` reasons: retiring a model must
        not be blocked by a chat thread, and every message keeps its own snapshot regardless."""
        assert _only_foreign_key_to(table("ai_conversations"), "ai_models").ondelete == "SET NULL"

    def test_transcript_relationships_navigate_both_ways(self) -> None:
        conversation = _mapper("AIConversation")
        message = _mapper("AIMessage")
        assert conversation.relationships["messages"].entity.entity is _model_class("AIMessage")
        assert message.relationships["conversation"].entity.entity is _model_class("AIConversation")
        assert _mapper("Case").relationships["conversations"].entity.entity is _model_class(
            "AIConversation"
        )


class TestIntegritySweeps:
    """§8.4's ``integrity_checks``, EVID-07, and §10's append-only rule."""

    def test_a_sweep_cannot_report_verified_while_holding_two_different_digests(self) -> None:
        """The row that would be worth forging. "Verified" beside two unequal digests contradicts
        itself, and the contradiction is exactly what a tampered sweep record would look like."""
        sql = _check_sql("integrity_checks", "ck_integrity_checks_verified_means_the_digests_agree")
        assert "result <> 'verified'" in sql
        assert "actual_sha256 = expected_sha256" in sql

    def test_a_sweep_cannot_report_a_mismatch_that_did_not_happen(self) -> None:
        """The mirror image: EVID-07 makes a mismatch a **critical integrity exception** that an
        administrator acts on, so a false one is not harmless."""
        sql = _check_sql(
            "integrity_checks", "ck_integrity_checks_mismatch_means_the_digests_differ"
        )
        assert "result <> 'mismatch'" in sql
        assert "IS DISTINCT FROM" in sql

    def test_unverified_is_not_a_sweep_outcome(self) -> None:
        """``integrity_status`` is shared with ``evidence_items``, where ``unverified`` means "never
        checked". A row here *is* a check that ran, so the value would be a result saying nothing
        happened — which is why sharing the enum needs this constraint beside it."""
        assert _check_sql("integrity_checks", "ck_integrity_checks_result_is_an_outcome") == (
            "result <> 'unverified'"
        )
        column = table("integrity_checks").columns["result"]
        assert isinstance(column.type, SAEnum)
        assert column.type.name == "integrity_status", (
            "shared with evidence_items, not a second type"
        )

    def test_a_missing_digest_can_only_mean_the_bytes_were_unreadable(self) -> None:
        """Without this, NULL in ``actual_sha256`` is ambiguous between "could not read it" and
        "did not record it" — and EVID-07's ``missing`` result exists to say the first."""
        sql = _check_sql("integrity_checks", "ck_integrity_checks_a_digest_was_read_unless_missing")
        assert "actual_sha256 IS NOT NULL" in sql
        assert "result = 'missing'" in sql

    def test_both_digests_are_fixed_width_lowercase_hex(self) -> None:
        """The expected digest is copied from ``physical_objects.sha256`` rather than joined to it, so
        it gets the same alphabet check — an uppercase digest compares unequal to the same digest
        computed again, and presents as an integrity mismatch rather than a formatting bug."""
        columns = table("integrity_checks").columns
        for name in ("expected_sha256", "actual_sha256"):
            assert _char_width(columns[name]) == 64
        names = _check_constraint_names("integrity_checks")
        assert "ck_integrity_checks_expected_sha256_is_lowercase_hex" in names
        assert "ck_integrity_checks_actual_sha256_is_lowercase_hex" in names
        assert columns["expected_sha256"].nullable is False
        assert columns["actual_sha256"].nullable is True

    def test_the_exception_queue_is_a_partial_index(self) -> None:
        """EVID-07 surfaces every mismatch as a critical exception. Finding them must not mean
        scanning 24 months of clean results — which is how a sweep table grows."""
        index = _index(table("integrity_checks"), "ix_integrity_checks_exceptions")
        predicate = str(_predicate(index))
        assert "mismatch" in predicate
        assert "missing" in predicate
        assert [_expression_name(expression) for expression in index.expressions] == ["checked_at"]

    def test_a_sweep_records_the_object_and_the_time_it_read_it(self) -> None:
        columns = table("integrity_checks").columns
        assert columns["physical_object_id"].nullable is False
        assert columns["checked_at"].nullable is False
        assert "created_at" not in columns, "checked_at is the observation's time"
        index = _index(table("integrity_checks"), "ix_integrity_checks_object_time")
        assert [_expression_name(expression) for expression in index.expressions] == [
            "physical_object_id",
            "checked_at",
        ]

    def test_the_sweep_job_is_optional_and_does_not_own_the_result(self) -> None:
        """``SET NULL``, like the other artifact-to-job references: an on-demand check (EVID-07's
        other trigger) has no job at all, and coupling job retention to a table §10 keeps for 24
        months would fight both."""
        constraint = _only_foreign_key_to(table("integrity_checks"), "analysis_jobs")
        assert constraint.ondelete == "SET NULL"
        assert table("integrity_checks").columns["job_id"].nullable is True

    def test_sweep_history_is_navigable_from_the_object(self) -> None:
        assert _mapper("PhysicalObject").relationships[
            "integrity_checks"
        ].entity.entity is _model_class("IntegrityCheck")


class TestPlatformAdministration:
    """§8.4's settings, flags and retention policies — every default is the closed one."""

    #: Transcribed from §12's retention table (Originals, Derivatives, Analysis results,
    #: Custody/audit, Embeddings, User PII) rather than imported from the model: a test that reads the
    #: constant it is checking can only ever agree with itself.
    SCOPES: Final[tuple[str, ...]] = (
        "original",
        "derivative",
        "analysis_result",
        "custody_audit",
        "embedding",
        "user_pii",
    )
    #: §12's deletion paths and ADR-0020's decisions: retain, archive to cold storage, purge
    #: regenerable derivatives, delete an original under four conditions.
    ACTIONS: Final[tuple[str, ...]] = ("retain", "archive", "purge", "delete")

    def test_a_new_feature_flag_enables_nothing(self) -> None:
        """Fail closed, in the same direction as ``ai_provider_settings.is_enabled`` and the
        ``ai_services`` registry's ``capability_enabled(default=False)``: a row created by a migration
        with nothing else set switches nothing on."""
        assert _default_text(table("feature_flags").columns["enabled"]) == "false"

    def test_a_flag_must_carry_a_reason(self) -> None:
        """Stricter than §8.4's column list, deliberately. A flag here states a licence position
        (ADR-0001's copyleft gates), a rollout decision or a legal constraint, and "it was on" with
        nothing beside it is not answerable six months later when somebody asks who accepted that
        obligation. A blank reason is refused too — it satisfies NOT NULL while saying nothing."""
        column = table("feature_flags").columns["reason"]
        assert column.nullable is False
        assert column.server_default is None, "a default reason would be a fabricated justification"
        assert _check_sql("feature_flags", "ck_feature_flags_reason_is_not_blank") == (
            "btrim(reason) <> ''"
        )

    def test_setting_and_flag_keys_are_unique_and_cannot_be_blank(self) -> None:
        for name in ("system_settings", "feature_flags"):
            assert ("key",) in _unique_column_tuples(name), f"{name}.key must be unique"
            assert _check_sql(name, f"ck_{name}_key_is_not_blank") == "btrim(key) <> ''"

    def test_a_new_retention_policy_deletes_nothing(self) -> None:
        """ADR-0020's first decision: until an operator sets ``RETENTION_STATUTORY_DAYS`` on legal
        advice, retention jobs delete nothing. A policy row defaulting to anything else would undo
        that decision by omission."""
        assert _default_text(table("retention_policies").columns["action"]) == "'retain'"

    def test_no_policy_can_delete_the_audit_trail(self) -> None:
        """ADR-0020's second decision and §12's "never deleted in v1; archival only", as a CHECK — so
        the most destructive mistake available in an admin UI is not available at all."""
        sql = _check_sql("retention_policies", "ck_retention_policies_audit_is_never_deleted")
        assert "scope <> 'custody_audit'" in sql
        assert "'retain'" in sql
        assert "'archive'" in sql
        assert "delete" not in sql.replace("'custody_audit'", "")

    def test_deleting_an_original_names_an_approver(self) -> None:
        """ADR-0020's fourth decision requires an administrator, a justification, a second approver and
        a permanent audit record. This schema holds the approver and refuses the row without one; the
        justification and the audit record are §8.3's and M19's."""
        sql = _check_sql("retention_policies", "ck_retention_policies_deletion_names_an_approver")
        assert sql == "action <> 'delete' OR approved_by IS NOT NULL"

    def test_purging_a_derivative_needs_no_approver(self) -> None:
        """§12 is explicit that derivatives are automated with no approval, because they are
        regenerable from the original. A constraint demanding an approver there would contradict the
        rule it was written to serve — so this asserts the CHECK is scoped to ``delete`` alone."""
        sql = _check_sql("retention_policies", "ck_retention_policies_deletion_names_an_approver")
        assert "'purge'" not in sql
        assert table("retention_policies").columns["approved_by"].nullable is True

    def test_retention_vocabularies_are_constrained_without_being_enums(self) -> None:
        """§9's rule for a growing set: ``text`` plus a CHECK, not a native type. Unlike a provider
        name, though, a retention scope selects which deletion rule applies — and a scope nobody
        defined would match no rule at all, silently retaining everything it was meant to govern."""
        scope_sql = _check_sql(
            "retention_policies", "ck_retention_policies_scope_is_a_known_data_class"
        )
        action_sql = _check_sql(
            "retention_policies", "ck_retention_policies_action_is_a_known_action"
        )
        for value in self.SCOPES:
            assert f"'{value}'" in scope_sql, f"§12's {value!r} is not in the scope CHECK"
        for value in self.ACTIONS:
            assert f"'{value}'" in action_sql, f"{value!r} is not in the action CHECK"
        columns = table("retention_policies").columns
        assert not isinstance(columns["scope"].type, SAEnum)
        assert not isinstance(columns["action"].type, SAEnum)

    def test_a_policy_can_name_an_evidence_type_using_the_canonical_enum(self) -> None:
        """NULL means "every type in this scope"; a named type reuses §9's ``evidence_type``, so a
        policy cannot refer to a type the platform does not have."""
        column = table("retention_policies").columns["evidence_type"]
        assert column.nullable is True
        assert isinstance(column.type, SAEnum)
        assert column.type.name == "evidence_type"

    def test_retention_is_an_event_plus_a_duration_and_neither_is_mandatory(self) -> None:
        """§12 composes retention from a clock-start event and a period; ADR-0020 sources the
        statutory period from configuration, so a row may carry no duration of its own."""
        columns = table("retention_policies").columns
        assert columns["keep_until_event"].nullable is True
        assert columns["keep_duration"].nullable is True
        assert isinstance(columns["keep_duration"].type, Interval)

    def test_overlapping_policies_are_allowed_because_the_winner_is_not_decided_yet(self) -> None:
        """No UNIQUE on ``(scope, evidence_type)``. A scope-wide policy and a narrower type-specific
        one may legitimately coexist, and which wins is a resolution rule belonging to the retention
        service in M19 — a unique constraint would forbid the override before anybody designed it."""
        tuples = _unique_column_tuples("retention_policies")
        assert ("scope", "evidence_type") not in tuples

    def test_a_setting_always_declares_the_shape_of_its_value(self) -> None:
        """ADM-06's "curated allowlist" is what makes the admin UI able to validate before writing.
        PostgreSQL has no JSON Schema validator, so conformance is the service layer's job — but the
        database can and does require that a shape was declared at all."""
        columns = table("system_settings").columns
        for name in ("value", "schema"):
            assert columns[name].nullable is False
            assert _default_text(columns[name]) == "'{}'::jsonb"

    def test_the_value_shape_column_is_named_as_the_design_spells_it(self) -> None:
        """§8.4 names the column ``schema``; the model attribute is ``value_schema``, because
        ``SystemSetting.schema`` in Python reads as the *database* schema. Same device ``audit_logs``
        uses to keep a column named ``metadata`` behind ``event_metadata`` — the design names the
        column, and the attribute name is the code's problem, not the schema's."""
        attribute = _model_class("SystemSetting").value_schema.property.columns[0]
        assert attribute.name == "schema"
        assert "schema" in table("system_settings").columns

    def test_previous_value_is_one_level_of_history_not_an_audit_trail(self) -> None:
        """NULL means "this is the value it was created with", which is a fact rather than a gap. The
        full trail — who, when, from where, allowed or not — is §8.3's ``audit_logs``, and a settings
        table that tried to be its own audit log would end up with neither."""
        column = table("system_settings").columns["previous_value"]
        assert column.nullable is True
        assert column.type.__class__.__name__ == "JSONB"

    def test_administration_tables_attribute_their_last_editor_without_blocking_deactivation(
        self,
    ) -> None:
        """``SET NULL`` on all three: deactivating an administrator must not be blocked by rows they
        once touched, and the durable attribution is the audit row rather than this pointer."""
        for name in ("system_settings", "feature_flags", "retention_policies"):
            constraint = _only_foreign_key_to(table(name), "users")
            assert constraint.ondelete == "SET NULL", name


class TestLimitationCorpus:
    """§5.3's versioned disclaimer corpus — transcribed here, not inherited from the model.

    ``analysis_results.limitations_code`` has been ``NOT NULL`` since revision 0001: AR-4's rule that a
    finding which cannot state its limits is not a finding. This table is what the code means, and the
    assertions below are a transcription of §5.3's six columns rather than a reading of the model,
    because the failure worth catching is a model that has quietly grown a column the design never
    ratified — on the one table whose text ends up printed in a report years after it was written.
    """

    #: §5.3's columns, in the order the document lists them. Set equality is asserted below, in both
    #: directions: a missing column loses a rule, and an extra one is behaviour nobody reviewed.
    COLUMNS: Final[tuple[str, ...]] = (
        "code",
        "version",
        "text_en",
        "effective_from",
        "effective_to",
        "approved_by",
    )

    def test_the_column_set_is_exactly_what_the_design_specifies(self) -> None:
        assert tuple(table("limitation_statements").columns.keys()) == self.COLUMNS

    def test_code_and_version_are_the_primary_key(self) -> None:
        """The identity of a disclaimer is which wording, and which version of it.

        A surrogate ``id`` beside this key would add a second way to address a row without adding an
        identity, and two rows both claiming to be ELA version 3 would be two different answers to
        "what was this finding's limitation" — the ambiguity the versioning exists to remove.
        """
        key = [column.name for column in table("limitation_statements").primary_key.columns]
        assert key == ["code", "version"]

    def test_a_code_is_text_because_the_set_grows(self) -> None:
        """§9's rule for a growing vocabulary: ``text`` plus a lookup, not a native enum.

        Every engine the platform gains adds a code, and while adding an enum label is migration-safe,
        retiring one is not — it needs a type rebuild with an explicit data path. A disclaimer code
        must stay retireable, because a code whose statements are all withdrawn is exactly the case
        §5.3's versioning has to survive.
        """
        column = table("limitation_statements").columns["code"]
        assert not isinstance(column.type, SAEnum)
        assert column.type.__class__.__name__ == "Text"
        assert column.nullable is False

    def test_the_statement_text_is_mandatory_and_cannot_be_blank(self) -> None:
        """NOT NULL per §5.3, and non-blank because an empty string satisfies NOT NULL while saying
        nothing — a finding whose disclaimer is ``""`` has met the column and defeated AR-4."""
        column = table("limitation_statements").columns["text_en"]
        assert column.nullable is False
        assert column.type.__class__.__name__ == "Text"
        assert column.server_default is None, "a default disclaimer would be a fabricated one"
        assert (
            _check_sql(
                "limitation_statements", "ck_limitation_statements_statement_text_is_not_blank"
            )
            == "btrim(text_en) <> ''"
        )

    def test_the_effective_window_is_open_until_a_revision_closes_it(self) -> None:
        """``effective_to`` NULL means "still current"; neither bound has a default.

        A default on ``effective_from`` would date a statement by the clock of whichever server
        inserted it, and §13(6) requires every environment to end up identical — so the seeded corpus
        carries an explicit date and a later revision closes a window deliberately, with an approver.
        """
        columns = table("limitation_statements").columns
        for name in ("effective_from", "effective_to"):
            column = columns[name]
            assert column.nullable is True, f"§5.3 leaves {name} optional"
            assert isinstance(column.type, DateTime)
            assert column.type.timezone is True, f"{name} stores an instant (§1 DB-6)"
            assert column.server_default is None

    def test_a_window_cannot_close_before_it_opens(self) -> None:
        """An inverted window resolves to nothing, so the wording would silently stop existing at the
        moment it was meant to take effect — and every result citing that code would print no
        disclaimer at all while the row still looked present."""
        assert _check_sql(
            "limitation_statements", "ck_limitation_statements_window_does_not_end_before_it_starts"
        ) == ("effective_from IS NULL OR effective_to IS NULL OR effective_to >= effective_from")

    def test_versions_are_counted_from_one(self) -> None:
        """So "the latest version" has a natural floor, and a corpus whose first entry is numbered
        zero is visibly one somebody renumbered by hand."""
        assert (
            _check_sql("limitation_statements", "ck_limitation_statements_version_is_at_least_one")
            == "version >= 1"
        )
        assert (
            table("limitation_statements").columns["version"].type.__class__.__name__ == "Integer"
        )

    def test_a_code_cannot_be_blank(self) -> None:
        assert _check_sql(
            "limitation_statements", "ck_limitation_statements_code_is_not_blank"
        ) == ("btrim(code) <> ''")

    def test_an_approver_leaving_does_not_take_the_disclaimer_with_them(self) -> None:
        """``SET NULL``, matching ``retention_policies.approved_by``.

        §12 deactivates accounts rather than erasing them, but an erasure on documented legal request
        is still a path; a disclaimer that outlives its approver is nonetheless the disclaimer a
        report printed. Attribution is not a load-bearing reference, and ``RESTRICT`` here would make
        a lawful erasure fail on a table nobody would think to look at.
        """
        constraint = _only_foreign_key_to(table("limitation_statements"), "users")
        assert constraint.ondelete == "SET NULL"
        assert table("limitation_statements").columns["approved_by"].nullable is True

    def test_the_corpus_carries_no_insert_or_update_stamps(self) -> None:
        """§5.3 specifies no timestamps, and none are added.

        The row's place in time *is* its effective window. An ``updated_at`` beside a version number
        would record edits to wording a report may already have printed, and would make "which text
        did the reader see" answerable two different ways — one of them mutable. A correction is a new
        version, and a new version is a new row with its own window.
        """
        columns = set(table("limitation_statements").columns.keys())
        assert not columns & {"created_at", "updated_at", "deleted_at"}

    def test_the_primary_key_is_the_only_index(self) -> None:
        """Resolution filters on ``code`` first, which the ``(code, version)`` key already leads with.

        The corpus is dozens of rows and grows by one row per wording change, so a second index here
        would be maintenance with nothing to speed up. Asserted rather than left implicit: an index
        added to a table nobody queries is invisible until it slows the write path.
        """
        assert {str(index.name) for index in table("limitation_statements").indexes} == set()

    def test_limitations_code_stays_a_text_reference_and_not_a_foreign_key(self) -> None:
        """§5.3's own word is "FK-ish", and turning it into a foreign key would break two things.

        A single-column key cannot express the reference, which is to a *version* resolved through an
        effective window rather than to one row — and it would make a retired code unreadable, so a
        historical result whose statements have all been withdrawn would fail to load instead of
        reporting the wording it was published with. The constraint stays in the reader, which is
        where the resolution rule lives.
        """
        column = table("analysis_results").columns["limitations_code"]
        assert column.nullable is False
        assert column.type.__class__.__name__ == "Text"
        assert not column.foreign_keys
        targets = {
            foreign_key.column.table.name for foreign_key in table("analysis_results").foreign_keys
        }
        assert "limitation_statements" not in targets


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


def _char_width(column: Column[Any]) -> int:
    """The declared width of a fixed-length ``CHAR`` column, asserting that it is one.

    ``Column.type`` is a ``TypeEngine``, which declares no ``length`` attribute; narrowing to ``CHAR``
    first satisfies the type checker and states the property under test at the same time — these
    digest columns are fixed width, which is why a truncated or space-padded digest cannot be stored
    in one and then compare equal to a freshly computed one.
    """
    assert isinstance(column.type, CHAR), (
        f"{column.table.name}.{column.name} is {type(column.type).__name__}, not a fixed-width CHAR"
    )
    assert column.type.length is not None, (
        f"{column.table.name}.{column.name} is a CHAR with no width"
    )
    return column.type.length


def _check_sql(table_name: str, constraint_name: str) -> str:
    """The SQL of one named CHECK constraint, or a failure naming what the table does have.

    Read as SQL rather than assumed from the model source: a constraint that reads correctly in the
    Python can still be vacuous once rendered, and the rendered text is what PostgreSQL evaluates.
    """
    for constraint in table(table_name).constraints:
        if isinstance(constraint, CheckConstraint) and constraint.name == constraint_name:
            return " ".join(str(constraint.sqltext).split())
    raise AssertionError(
        f"{table_name} has no CHECK named {constraint_name}; it has "
        f"{sorted(_check_constraint_names(table_name))}"
    )


def _check_constraint_names(name: str) -> set[str]:
    return {
        str(constraint.name)
        for constraint in table(name).constraints
        if isinstance(constraint, CheckConstraint)
    }
