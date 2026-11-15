"""Initial schema — every table, index and server-side function the M2 foundation needs.

Revision ID: 0001
Revises:
Create Date: 2026-11-15

Generated with ``alembic revision --autogenerate`` against an empty PostgreSQL 16 database and then
reviewed and extended by hand, which is the workflow ``DATABASE_DESIGN.md`` §1 principle DB-7
requires: autogenerate proposes, a human decides, and ``alembic check`` in CI proves afterwards that
the models and the migration still agree.

What a metadata diff cannot generate, and is therefore written here explicitly
-----------------------------------------------------------------------------
1. ``uuid_generate_v7()`` — the PL/pgSQL UUIDv7 generator (ADR-0009, §1.1). PostgreSQL 16 has no
   built-in v7. It must exist *before* the tables whose ``id`` defaults to it.
2. ``tlx_array_to_text(text[])`` — an ``IMMUTABLE`` stand-in for ``array_to_string``, which
   PostgreSQL marks ``STABLE`` and therefore rejects inside ``cases.search_vector``'s generation
   expression.
3. ``case_number_seq`` — the sequence ``cases.case_number`` is minted from (§3.3). The numbering
   *policy* belongs to the case service in M4; the sequence is here because adding one later means
   taking a lock on ``cases``.
4. The write-once trigger on ``physical_objects`` (§4.1).
5. ``REVOKE UPDATE, DELETE`` on the two append-only ledgers (§4.3, §8.3, principle DB-3).

Downgrade
---------
Reversing this revision drops every table in the schema, which is data loss by definition. It is
therefore **refused** unless the database is empty or the operator states the intention explicitly
with ``alembic -x allow_data_loss=true downgrade base``. See ``migrations/README.md``.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy import Connection, inspect
from sqlalchemy.dialects import postgresql

#: One revision id, referenced by name so a rename cannot silently detach it from its file.
revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: PostgreSQL has no built-in UUIDv7 generator, so the platform ships one. RFC 9562 §5.7: 48 bits of
#: Unix milliseconds, then the version nibble, then random bits carrying the RFC 4122 variant.
#:
#: Entropy comes from ``gen_random_uuid()``, which draws on the server CSPRNG. ``pgcrypto``'s
#: ``gen_random_bytes()`` would be the obvious choice, but it is a contrib module: requiring an
#: extension in order to generate identifiers would make the schema depend on what the distribution
#: happens to ship, and the same schema must build on a plain postgres:16 image in CI.
#:
#: Ordering is *across* milliseconds only — the low bits are random, so two rows inserted within one
#: millisecond can compare either way. Nothing depends on v7 for correctness of order:
#: ``custody_events.sequence`` and ``audit_logs.sequence`` are the authoritative ordering. v7 buys
#: B-tree locality, which is why §1.1 asks for it on the high-volume append-only tables and not on
#: the ones whose identifiers are publicly visible (ADR-0009).
UUID_V7_FUNCTION = """
CREATE OR REPLACE FUNCTION uuid_generate_v7() RETURNS uuid
LANGUAGE plpgsql VOLATILE
AS $function$
DECLARE
    ts_ms bigint;
    octets bytea;
    i int;
BEGIN
    -- clock_timestamp(), not now(): now() is fixed at transaction start, so a transaction that
    -- appends fifty custody events would give them all the same timestamp prefix.
    ts_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;

    octets := substring(uuid_send(gen_random_uuid()) from 1 for 16);
    FOR i IN 0..5 LOOP
        octets := set_byte(octets, i, ((ts_ms >> (40 - 8 * i)) & 255)::int);
    END LOOP;

    -- version 7 in the high nibble of byte 6; RFC 4122 variant in the high bits of byte 8
    octets := set_byte(octets, 6, ((get_byte(octets, 6) & 15) | 112));
    octets := set_byte(octets, 8, ((get_byte(octets, 8) & 63) | 128));

    RETURN encode(octets, 'hex')::uuid;
END;
$function$
"""

#: ``array_to_string`` is ``STABLE`` in PostgreSQL, so it cannot appear in a generated column's
#: expression. For ``text[]`` the operation genuinely is immutable — concatenate with a fixed
#: delimiter, skip NULLs — so the schema provides its own. Marking a function IMMUTABLE that is not
#: would silently corrupt every index built on it, which is why this one is declared for ``text[]``
#: alone rather than written generically over ``anyarray``.
ARRAY_TO_TEXT_FUNCTION = """
CREATE OR REPLACE FUNCTION tlx_array_to_text(elements text[]) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $function$
    SELECT coalesce(string_agg(element, ' ' ORDER BY n), '')
    FROM unnest(elements) WITH ORDINALITY AS t(element, n)
$function$
"""

#: ``cases.case_number`` is minted from this sequence inside the creating transaction (§3.3).
#: NO CYCLE: running out of case numbers must fail loudly rather than silently reissue one that an
#: existing case already holds.
CASE_NUMBER_SEQUENCE = """
CREATE SEQUENCE IF NOT EXISTS case_number_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    NO CYCLE
"""

#: Write-once protection for stored originals (§4.1). Code-level immutability is a promise the next
#: refactor can break; a trigger makes it a property of the database.
#:
#: The scope is deliberate. It protects the **content-addressed identity** of the object — digests,
#: size, where the bytes live, how they are encrypted, and when they arrived. It does not freeze the
#: whole row: §4.1 has the application maintaining ``reference_count`` and recording antivirus
#: results, and blocking those would push that bookkeeping into a second table where nobody would
#: think to look for it.
#:
#: The escape hatch is a session setting, ``SET LOCAL app.maintenance = on``, which is how an
#: approved physical deletion (§12: administrator, justification, second approver, audit record) is
#: performed. ``current_setting(name, true)`` returns NULL instead of raising when the parameter has
#: never been set, so an ordinary connection is denied by default.
#:
#: §4.1 also describes the escape hatch as requiring the ``tlx_migrator`` role. That half is enforced
#: by the grants in ``infra/postgres/initdb`` rather than by a trigger inspecting ``current_user``,
#: which would silently stop working the moment the deployment introduces connection pooling or role
#: assumption — and would fail in a way that looks like data corruption rather than a permissions
#: problem.
WRITE_ONCE_FUNCTION = """
CREATE OR REPLACE FUNCTION tlx_enforce_write_once_physical_objects() RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    maintenance text := coalesce(current_setting('app.maintenance', true), 'off');
    changed text[];
BEGIN
    IF lower(maintenance) = 'on' THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'physical_objects is a write-once store: DELETE requires the app.maintenance session '
            'setting and the approval path in DATABASE_DESIGN section 12'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    changed := array_remove(ARRAY[
        CASE WHEN NEW.sha256          IS DISTINCT FROM OLD.sha256          THEN 'sha256' END,
        CASE WHEN NEW.sha1            IS DISTINCT FROM OLD.sha1            THEN 'sha1' END,
        CASE WHEN NEW.md5             IS DISTINCT FROM OLD.md5             THEN 'md5' END,
        CASE WHEN NEW.size_bytes      IS DISTINCT FROM OLD.size_bytes      THEN 'size_bytes' END,
        CASE WHEN NEW.storage_backend IS DISTINCT FROM OLD.storage_backend THEN 'storage_backend' END,
        CASE WHEN NEW.storage_path    IS DISTINCT FROM OLD.storage_path    THEN 'storage_path' END,
        CASE WHEN NEW.detected_mime   IS DISTINCT FROM OLD.detected_mime   THEN 'detected_mime' END,
        CASE WHEN NEW.merkle_root     IS DISTINCT FROM OLD.merkle_root     THEN 'merkle_root' END,
        CASE WHEN NEW.block_size      IS DISTINCT FROM OLD.block_size      THEN 'block_size' END,
        CASE WHEN NEW.encryption      IS DISTINCT FROM OLD.encryption      THEN 'encryption' END,
        CASE WHEN NEW.wrapped_dek     IS DISTINCT FROM OLD.wrapped_dek     THEN 'wrapped_dek' END,
        CASE WHEN NEW.written_at      IS DISTINCT FROM OLD.written_at      THEN 'written_at' END
    ]::text[], NULL);

    IF cardinality(changed) > 0 THEN
        RAISE EXCEPTION
            'physical_objects is a write-once store: column(s) % cannot change after write',
            array_to_string(changed, ', ')
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'approved maintenance runs inside a transaction that sets app.maintenance';
    END IF;

    RETURN NEW;
END;
$function$
"""

#: Dropped first so that re-running the revision over an existing trigger cannot fail on a duplicate.
WRITE_ONCE_TRIGGER_DROP = """
DROP TRIGGER IF EXISTS tlx_physical_objects_write_once ON physical_objects
"""

WRITE_ONCE_TRIGGER_CREATE = """
CREATE TRIGGER tlx_physical_objects_write_once
    BEFORE UPDATE OR DELETE ON physical_objects
    FOR EACH ROW EXECUTE FUNCTION tlx_enforce_write_once_physical_objects()
"""

#: Principle DB-3: the custody and audit ledgers are append-only, enforced at the database-role level
#: so the guarantee does not depend on every future service being written carefully. Guarded by a
#: role-existence check so this same revision runs unchanged in CI and against a test database, where
#: the least-privilege roles from ``infra/postgres/initdb`` do not exist and the connecting role owns
#: the tables.
APPEND_ONLY_REVOKES = """
DO $do$
DECLARE
    target_role text;
BEGIN
    FOREACH target_role IN ARRAY ARRAY['tlx_app', 'tlx_worker', 'tlx_auditor'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target_role) THEN
            EXECUTE format(
                'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE custody_events, audit_logs FROM %I',
                target_role
            );
        END IF;
    END LOOP;
END
$do$
"""

#: The native enum types this revision creates, listed explicitly for the downgrade. A revision is a
#: snapshot: deriving this from the live models would make an old migration's behaviour depend on code
#: written after it.
ENUM_TYPES: tuple[str, ...] = (
    "global_role",
    "user_status",
    "password_alg",
    "case_role",
    "case_status",
    "sensitivity",
    "evidence_type",
    "evidence_status",
    "integrity_status",
    "source_type",
    "enc_state",
    "custody_event_type",
    "derivative_kind",
    "artifact_status",
    "job_status",
    "verification_status",
    "model_status",
    "report_status",
    "audit_result",
)


def _data_loss_permitted() -> bool:
    """True only when the operator said so on the command line.

    ``alembic -x allow_data_loss=true downgrade base``. A flag rather than a prompt, because
    migrations run unattended in a deploy pipeline — and a flag survives in the logged command,
    which an interactive "y" does not.
    """
    value = context.get_x_argument(as_dictionary=True).get("allow_data_loss", "")
    return value.strip().lower() == "true"


def _populated_tables(bind: Connection) -> list[str]:
    """Every table in the current schema that holds at least one row.

    ``EXISTS`` rather than ``count(*)``: a downgrade check must not spend ten minutes counting an
    audit table in order to decide whether it is empty. Table names come from the database catalog,
    not from any input, so quoting them into the statement is safe.
    """
    populated: list[str] = []
    for name in sorted(inspect(bind).get_table_names()):
        if name == "alembic_version":
            continue
        statement = sa.text(f'SELECT EXISTS (SELECT 1 FROM "{name}")')
        if bool(bind.execute(statement).scalar()):
            populated.append(name)
    return populated


def _refuse_data_loss(bind: Connection) -> None:
    """Raise unless this downgrade can proceed without destroying rows."""
    if _data_loss_permitted():
        return
    populated = _populated_tables(bind)
    if not populated:
        return
    preview = ", ".join(populated[:8]) + ("…" if len(populated) > 8 else "")
    raise RuntimeError(
        f"refusing to downgrade revision 0001: {len(populated)} table(s) hold data ({preview}). "
        "Dropping them destroys evidence metadata, custody history and audit records, which "
        "DATABASE_DESIGN §12 keeps for the statutory retention period and §11 forbids a downgrade "
        "from removing silently. If this is a deliberate, backed-up teardown, re-run with: "
        "alembic -x allow_data_loss=true downgrade <target>"
    )

def upgrade() -> None:
    """Apply the change.

    Expand first, contract later: a revision that stops writing to a column and a revision that
    drops it are two revisions, never one (§11). A single deploy must be reversible while the
    previous build is still running.
    """
    # Server-side functions and the sequence first: two tables default their primary key to
    # uuid_generate_v7(), and cases.search_vector is generated from tlx_array_to_text().
    op.execute(UUID_V7_FUNCTION)
    op.execute(ARRAY_TO_TEXT_FUNCTION)
    op.execute(CASE_NUMBER_SEQUENCE)

    op.create_table('organisations',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('slug', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), server_default=sa.text("'active'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_organisations')),
    sa.UniqueConstraint('slug', name=op.f('uq_organisations_slug'))
    )
    op.create_table('permissions',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('code', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('resource', sa.Text(), nullable=True),
    sa.Column('is_system', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_permissions')),
    sa.UniqueConstraint('code', name=op.f('uq_permissions_code'))
    )
    op.create_table('roles',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('code', sa.Enum('admin', 'lead_investigator', 'investigator', 'analyst', 'reviewer', 'auditor', name='global_role'), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('is_system', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_roles')),
    sa.UniqueConstraint('code', name=op.f('uq_roles_code'))
    )
    op.create_table('users',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('email', sa.Text(), nullable=False),
    sa.Column('username', sa.Text(), nullable=True),
    sa.Column('full_name', sa.Text(), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('password_alg', sa.Enum('argon2id', 'bcrypt_legacy', name='password_alg'), server_default=sa.text("'argon2id'"), nullable=False),
    sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('global_role', sa.Enum('admin', 'lead_investigator', 'investigator', 'analyst', 'reviewer', 'auditor', name='global_role'), server_default=sa.text("'investigator'"), nullable=False),
    sa.Column('status', sa.Enum('active', 'suspended', 'pending_activation', 'deactivated', name='user_status'), server_default=sa.text("'pending_activation'"), nullable=False),
    sa.Column('mfa_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('mfa_secret_encrypted', sa.LargeBinary(), nullable=True),
    sa.Column('mfa_required_by_policy', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('failed_login_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_ip', postgresql.INET(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users'))
    )
    op.create_index('ix_users_active_email', 'users', [sa.literal_column('lower(email)')], unique=False, postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index('ix_users_global_role', 'users', ['global_role'], unique=False)
    op.create_index('ix_users_status', 'users', ['status'], unique=False)
    op.create_index('uq_users_email_lower', 'users', [sa.literal_column('lower(email)')], unique=True)
    op.create_index('uq_users_username_lower', 'users', [sa.literal_column('lower(username)')], unique=True, postgresql_where=sa.text('username IS NOT NULL'))
    op.create_table('ai_models',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('family', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('version', sa.Text(), nullable=False),
    sa.Column('task', sa.Text(), nullable=False),
    sa.Column('weights_sha256', sa.CHAR(length=64), nullable=True),
    sa.Column('weights_path', sa.Text(), nullable=True),
    sa.Column('framework', sa.Text(), nullable=True),
    sa.Column('framework_version', sa.Text(), nullable=True),
    sa.Column('licence', sa.Text(), nullable=True),
    sa.Column('source_url', sa.Text(), nullable=True),
    sa.Column('size_bytes', sa.BigInteger(), nullable=True),
    sa.Column('min_vram_mb', sa.Integer(), nullable=True),
    sa.Column('status', sa.Enum('active', 'deprecated', 'retired', name='model_status'), server_default=sa.text("'active'"), nullable=False),
    sa.Column('is_default', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('measured_performance', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('model_card_summary', sa.Text(), nullable=True),
    sa.Column('registered_by', sa.Uuid(), nullable=True),
    sa.Column('registered_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("is_default = false OR status = 'active'", name=op.f('ck_ai_models_only_active_models_are_default')),
    sa.CheckConstraint("weights_sha256 IS NULL OR weights_sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_ai_models_weights_sha256_is_lowercase_hex')),
    sa.CheckConstraint('min_vram_mb IS NULL OR min_vram_mb >= 0', name=op.f('ck_ai_models_vram_not_negative')),
    sa.CheckConstraint('size_bytes IS NULL OR size_bytes >= 0', name=op.f('ck_ai_models_size_not_negative')),
    sa.ForeignKeyConstraint(['registered_by'], ['users.id'], name=op.f('fk_ai_models_registered_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_models')),
    sa.UniqueConstraint('family', 'name', 'version', name='uq_ai_models_family_name_version')
    )
    op.create_index('ix_ai_models_family', 'ai_models', ['family'], unique=False)
    op.create_index('ix_ai_models_task_status', 'ai_models', ['task', 'status'], unique=False)
    op.create_index('uq_ai_models_default_per_family_task', 'ai_models', ['family', 'task'], unique=True, postgresql_where=sa.text("is_default AND status = 'active'"))
    op.create_table('cases',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_number', sa.Text(), nullable=False),
    sa.Column('organisation_id', sa.Uuid(), server_default=sa.text("'00000000-0000-4000-8000-000000000001'::uuid"), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('draft', 'active', 'under_review', 'closed', 'archived', name='case_status'), server_default=sa.text("'draft'"), nullable=False),
    sa.Column('sensitivity', sa.Enum('public', 'internal', 'confidential', 'restricted', name='sensitivity'), nullable=False),
    sa.Column('case_type', sa.Text(), nullable=True),
    sa.Column('jurisdiction', sa.Text(), nullable=True),
    sa.Column('lead_investigator_id', sa.Uuid(), nullable=True),
    sa.Column('opened_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('statutory_deadline', sa.DateTime(timezone=True), nullable=True),
    sa.Column('legal_hold', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('storage_quota_bytes', sa.BigInteger(), nullable=True),
    sa.Column('storage_used_bytes', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('tags', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('search_vector', postgresql.TSVECTOR(), sa.Computed("to_tsvector('english'::regconfig, coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(tlx_array_to_text(tags), ''))", persisted=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("case_number ~ '^TLX-[0-9]{4}-[0-9]{6}$'", name=op.f('ck_cases_case_number_has_required_format')),
    sa.CheckConstraint('closed_at IS NULL OR opened_at IS NULL OR closed_at >= opened_at', name=op.f('ck_cases_closed_after_opened')),
    sa.CheckConstraint('storage_quota_bytes IS NULL OR storage_quota_bytes > 0', name=op.f('ck_cases_storage_quota_positive')),
    sa.CheckConstraint('storage_used_bytes >= 0', name=op.f('ck_cases_storage_used_not_negative')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_cases_created_by_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['lead_investigator_id'], ['users.id'], name=op.f('fk_cases_lead_investigator_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organisation_id'], ['organisations.id'], name=op.f('fk_cases_organisation_id_organisations'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_cases')),
    sa.UniqueConstraint('case_number', name=op.f('uq_cases_case_number'))
    )
    op.create_index('ix_cases_created_at', 'cases', ['created_at'], unique=False)
    op.create_index('ix_cases_lead_investigator', 'cases', ['lead_investigator_id'], unique=False)
    op.create_index('ix_cases_search_vector_gin', 'cases', ['search_vector'], unique=False, postgresql_using='gin')
    op.create_index('ix_cases_status', 'cases', ['status'], unique=False)
    op.create_index('ix_cases_tags_gin', 'cases', ['tags'], unique=False, postgresql_using='gin')
    op.create_table('physical_objects',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('sha256', sa.CHAR(length=64), nullable=False),
    sa.Column('sha1', sa.CHAR(length=40), nullable=True),
    sa.Column('md5', sa.CHAR(length=32), nullable=True),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('storage_backend', sa.Text(), nullable=False),
    sa.Column('storage_path', sa.Text(), nullable=False),
    sa.Column('detected_mime', sa.Text(), nullable=False),
    sa.Column('declared_mime', sa.Text(), nullable=True),
    sa.Column('merkle_root', sa.CHAR(length=64), nullable=True),
    sa.Column('block_size', sa.Integer(), nullable=True),
    sa.Column('encryption', sa.Enum('none', 'aes256gcm_envelope', name='enc_state'), nullable=False),
    sa.Column('wrapped_dek', sa.LargeBinary(), nullable=True),
    sa.Column('av_scan_status', sa.Text(), nullable=True),
    sa.Column('av_scan_detail', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('written_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('first_ingested_by', sa.Uuid(), nullable=True),
    sa.Column('reference_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("encryption = 'none' OR wrapped_dek IS NOT NULL", name=op.f('ck_physical_objects_encrypted_requires_wrapped_key')),
    sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_physical_objects_sha256_is_lowercase_hex')),
    sa.CheckConstraint('merkle_root IS NULL OR block_size IS NOT NULL', name=op.f('ck_physical_objects_merkle_root_has_block_size')),
    sa.CheckConstraint('reference_count >= 0', name=op.f('ck_physical_objects_reference_count_not_negative')),
    sa.CheckConstraint('size_bytes >= 0', name=op.f('ck_physical_objects_size_not_negative')),
    sa.ForeignKeyConstraint(['first_ingested_by'], ['users.id'], name=op.f('fk_physical_objects_first_ingested_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_physical_objects')),
    sa.UniqueConstraint('sha256', name=op.f('uq_physical_objects_sha256'))
    )
    op.create_index('ix_physical_objects_unreferenced', 'physical_objects', ['sha256'], unique=False, postgresql_where=sa.text('reference_count = 0'))
    op.create_index('ix_physical_objects_written_at', 'physical_objects', ['written_at'], unique=False)
    op.create_table('role_permissions',
    sa.Column('role_id', sa.Uuid(), nullable=False),
    sa.Column('permission_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], name=op.f('fk_role_permissions_permission_id_permissions'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_role_permissions_role_id_roles'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('role_id', 'permission_id', name=op.f('pk_role_permissions'))
    )
    op.create_table('user_roles',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('role_id', sa.Uuid(), nullable=False),
    sa.Column('is_primary', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('granted_by', sa.Uuid(), nullable=True),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True),
    sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('revoked_at IS NULL OR revoked_by IS NOT NULL', name=op.f('ck_user_roles_revocation_names_an_actor')),
    sa.CheckConstraint('valid_from IS NULL OR valid_until IS NULL OR valid_until > valid_from', name=op.f('ck_user_roles_validity_window_is_ordered')),
    sa.ForeignKeyConstraint(['granted_by'], ['users.id'], name=op.f('fk_user_roles_granted_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['revoked_by'], ['users.id'], name=op.f('fk_user_roles_revoked_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_user_roles_role_id_roles'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_roles_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user_roles'))
    )
    op.create_index('ix_user_roles_user_active', 'user_roles', ['user_id'], unique=False, postgresql_where=sa.text('revoked_at IS NULL'))
    op.create_index(op.f('ix_user_roles_user_id'), 'user_roles', ['user_id'], unique=False)
    op.create_index('uq_user_roles_primary_active', 'user_roles', ['user_id'], unique=True, postgresql_where=sa.text('is_primary AND revoked_at IS NULL'))
    op.create_index('uq_user_roles_user_role', 'user_roles', ['user_id', 'role_id'], unique=True)
    op.create_table('ai_provider_settings',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('provider', sa.Text(), nullable=False),
    sa.Column('display_name', sa.Text(), nullable=True),
    sa.Column('base_url', sa.Text(), nullable=True),
    sa.Column('api_key_ref', sa.Text(), nullable=True),
    sa.Column('api_key_encrypted', sa.LargeBinary(), nullable=True),
    sa.Column('allow_external_egress', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('requires_confirmation', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('allowed_categories', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('default_model_id', sa.Uuid(), nullable=True),
    sa.Column('rate_limit_rpm', sa.Integer(), nullable=True),
    sa.Column('timeout_ms', sa.Integer(), nullable=True),
    sa.Column('is_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('allow_external_egress = false OR cardinality(allowed_categories) > 0', name=op.f('ck_ai_provider_settings_egress_names_allowed_categories')),
    sa.CheckConstraint('allow_external_egress = false OR requires_confirmation = true', name=op.f('ck_ai_provider_settings_egress_requires_confirmation')),
    sa.CheckConstraint('api_key_ref IS NULL OR api_key_encrypted IS NULL', name=op.f('ck_ai_provider_settings_one_credential_mechanism')),
    sa.CheckConstraint('rate_limit_rpm IS NULL OR rate_limit_rpm > 0', name=op.f('ck_ai_provider_settings_rate_limit_positive')),
    sa.CheckConstraint('timeout_ms IS NULL OR timeout_ms > 0', name=op.f('ck_ai_provider_settings_timeout_positive')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_ai_provider_settings_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['default_model_id'], ['ai_models.id'], name=op.f('fk_ai_provider_settings_default_model_id_ai_models'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_provider_settings')),
    sa.UniqueConstraint('provider', name=op.f('uq_ai_provider_settings_provider'))
    )
    op.create_index('ix_ai_provider_settings_enabled', 'ai_provider_settings', ['is_enabled'], unique=False)
    op.create_table('audit_logs',
    sa.Column('id', sa.Uuid(), server_default=sa.text('uuid_generate_v7()'), nullable=False),
    sa.Column('sequence', sa.BigInteger(), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('actor_role', sa.Text(), nullable=True),
    sa.Column('actor_ip', postgresql.INET(), nullable=True),
    sa.Column('user_agent', sa.Text(), nullable=True),
    sa.Column('action', sa.Text(), nullable=False),
    sa.Column('resource_type', sa.Text(), nullable=True),
    sa.Column('resource_id', sa.Uuid(), nullable=True),
    sa.Column('case_id', sa.Uuid(), nullable=True),
    sa.Column('result', sa.Enum('success', 'failure', 'denied', name='audit_result'), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('request_id', sa.Text(), nullable=True),
    sa.Column('before', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('after', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('prev_hash', sa.CHAR(length=64), nullable=False),
    sa.Column('record_hash', sa.CHAR(length=64), nullable=False),
    sa.CheckConstraint("action ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$'", name=op.f('ck_audit_logs_action_is_namespaced')),
    sa.CheckConstraint("before IS NOT NULL OR after IS NOT NULL OR action NOT LIKE '%%.changed'", name=op.f('ck_audit_logs_change_action_carries_a_snapshot')),
    sa.CheckConstraint("prev_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_audit_logs_prev_hash_is_lowercase_hex')),
    sa.CheckConstraint("record_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_audit_logs_record_hash_is_lowercase_hex')),
    sa.CheckConstraint("result <> 'denied' OR reason IS NOT NULL", name=op.f('ck_audit_logs_denial_states_why')),
    sa.CheckConstraint('sequence > 0', name=op.f('ck_audit_logs_sequence_is_positive')),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_audit_logs_actor_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_audit_logs_case_id_cases'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_logs')),
    sa.UniqueConstraint('sequence', name=op.f('uq_audit_logs_sequence'))
    )
    op.create_index('ix_audit_logs_action_occurred', 'audit_logs', ['action', 'occurred_at'], unique=False)
    op.create_index('ix_audit_logs_actor_occurred', 'audit_logs', ['actor_id', 'occurred_at'], unique=False)
    op.create_index('ix_audit_logs_case_occurred', 'audit_logs', ['case_id', 'occurred_at'], unique=False)
    op.create_index('ix_audit_logs_denied', 'audit_logs', ['occurred_at'], unique=False, postgresql_where=sa.text("result = 'denied'"))
    op.create_index('ix_audit_logs_occurred_at', 'audit_logs', ['occurred_at'], unique=False)
    op.create_index('ix_audit_logs_request', 'audit_logs', ['request_id'], unique=False)
    op.create_index('ix_audit_logs_resource', 'audit_logs', ['resource_type', 'resource_id'], unique=False)
    op.create_table('case_members',
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('case_role', sa.Enum('owner', 'lead', 'member', 'contributor', 'viewer', name='case_role'), server_default=sa.text("'viewer'"), nullable=False),
    sa.Column('granted_by', sa.Uuid(), nullable=False),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True),
    sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('capability_overrides', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('can_view_original_content', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('can_verify_findings', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('revoked_at IS NULL OR revoked_by IS NOT NULL', name=op.f('ck_case_members_revocation_names_an_actor')),
    sa.CheckConstraint('valid_from IS NULL OR valid_until IS NULL OR valid_until > valid_from', name=op.f('ck_case_members_validity_window_is_ordered')),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_case_members_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['granted_by'], ['users.id'], name=op.f('fk_case_members_granted_by_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['revoked_by'], ['users.id'], name=op.f('fk_case_members_revoked_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_case_members_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('case_id', 'user_id', name=op.f('pk_case_members'))
    )
    op.create_index('ix_case_members_case_role', 'case_members', ['case_id', 'case_role'], unique=False)
    op.create_index('ix_case_members_user_active', 'case_members', ['user_id'], unique=False, postgresql_where=sa.text('revoked_at IS NULL'))
    op.create_table('evidence_items',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('physical_object_id', sa.Uuid(), nullable=False),
    sa.Column('evidence_number', sa.Text(), nullable=False),
    sa.Column('original_filename', sa.Text(), nullable=False),
    sa.Column('sanitized_filename', sa.Text(), nullable=False),
    sa.Column('item_type', sa.Enum('image', 'video', 'audio', 'document', 'archive', 'text', 'other', name='evidence_type'), nullable=False),
    sa.Column('subcategory', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('ingesting', 'hashing', 'stored', 'analysis_pending', 'failed', 'quarantined', 'integrity_failed', name='evidence_status'), server_default=sa.text("'ingesting'"), nullable=False),
    sa.Column('integrity_status', sa.Enum('unverified', 'verified', 'mismatch', 'missing', name='integrity_status'), server_default=sa.text("'unverified'"), nullable=False),
    sa.Column('integrity_last_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('source_type', sa.Enum('upload', 'intake_directory', 'api', 'third_party', 'extracted_child', name='source_type'), nullable=False),
    sa.Column('parent_evidence_id', sa.Uuid(), nullable=True),
    sa.Column('submitted_by', sa.Uuid(), nullable=False),
    sa.Column('acquired_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('acquisition_method', sa.Text(), nullable=True),
    sa.Column('acquisition_device', sa.Text(), nullable=True),
    sa.Column('collection_location', sa.Text(), nullable=True),
    sa.Column('custody_holder_id', sa.Uuid(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('tags', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('sensitivity_override', sa.Enum('public', 'internal', 'confidential', 'restricted', name='sensitivity'), nullable=True),
    sa.Column('deleted_by', sa.Uuid(), nullable=True),
    sa.Column('deletion_justification', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint('deleted_at IS NULL OR (deleted_by IS NOT NULL AND deletion_justification IS NOT NULL)', name=op.f('ck_evidence_items_soft_delete_requires_actor_and_reason')),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_evidence_items_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['custody_holder_id'], ['users.id'], name=op.f('fk_evidence_items_custody_holder_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['deleted_by'], ['users.id'], name=op.f('fk_evidence_items_deleted_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['parent_evidence_id'], ['evidence_items.id'], name=op.f('fk_evidence_items_parent_evidence_id_evidence_items'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['physical_object_id'], ['physical_objects.id'], name=op.f('fk_evidence_items_physical_object_id_physical_objects'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['submitted_by'], ['users.id'], name=op.f('fk_evidence_items_submitted_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence_items')),
    sa.UniqueConstraint('case_id', 'evidence_number', name='uq_evidence_items_case_evidence_number'),
    sa.UniqueConstraint('case_id', 'id', name='uq_evidence_items_case_id')
    )
    op.create_index('ix_evidence_items_case_created', 'evidence_items', ['case_id', 'created_at'], unique=False, postgresql_where=sa.text('deleted_at IS NULL'))
    op.create_index('ix_evidence_items_case_status', 'evidence_items', ['case_id', 'status'], unique=False)
    op.create_index('ix_evidence_items_case_type', 'evidence_items', ['case_id', 'item_type'], unique=False)
    op.create_index('ix_evidence_items_integrity_exception', 'evidence_items', ['case_id', 'integrity_status'], unique=False, postgresql_where=sa.text("integrity_status IN ('mismatch', 'missing')"))
    op.create_index('ix_evidence_items_parent', 'evidence_items', ['parent_evidence_id'], unique=False)
    op.create_index('ix_evidence_items_physical_object', 'evidence_items', ['physical_object_id'], unique=False)
    op.create_index('ix_evidence_items_tags_gin', 'evidence_items', ['tags'], unique=False, postgresql_using='gin')
    op.create_table('notifications',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('case_id', sa.Uuid(), nullable=True),
    sa.Column('kind', sa.Text(), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('expires_at IS NULL OR expires_at > created_at', name=op.f('ck_notifications_expiry_after_creation')),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_notifications_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_notifications_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notifications'))
    )
    op.create_index('ix_notifications_case', 'notifications', ['case_id', 'created_at'], unique=False)
    op.create_index('ix_notifications_kind', 'notifications', ['kind'], unique=False)
    op.create_index('ix_notifications_user_unread', 'notifications', ['user_id', 'created_at'], unique=False, postgresql_where=sa.text('read_at IS NULL'))
    op.create_table('reports',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('lineage_id', sa.Uuid(), nullable=False),
    sa.Column('template', sa.Text(), nullable=False),
    sa.Column('title', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('generating', 'draft', 'final', 'superseded', 'failed', name='report_status'), server_default=sa.text("'generating'"), nullable=False),
    sa.Column('current_version', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status = 'generating' OR current_version > 0", name=op.f('ck_reports_issued_report_has_a_version')),
    sa.CheckConstraint('current_version >= 0', name=op.f('ck_reports_current_version_not_negative')),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_reports_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_reports_created_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_reports')),
    sa.UniqueConstraint('lineage_id', name=op.f('uq_reports_lineage_id'))
    )
    op.create_index('ix_reports_case_created', 'reports', ['case_id', 'created_at'], unique=False)
    op.create_index('ix_reports_case_status', 'reports', ['case_id', 'status'], unique=False)
    op.create_index('ix_reports_created_by', 'reports', ['created_by'], unique=False)
    op.create_table('analysis_jobs',
    sa.Column('id', sa.Uuid(), server_default=sa.text('uuid_generate_v7()'), nullable=False),
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('evidence_id', sa.Uuid(), nullable=True),
    sa.Column('pipeline', sa.Text(), nullable=False),
    sa.Column('pipeline_version', sa.Text(), nullable=False),
    sa.Column('params', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('params_hash', sa.CHAR(length=64), nullable=False),
    sa.Column('priority', sa.SmallInteger(), server_default=sa.text('5'), nullable=False),
    sa.Column('queue', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('queued', 'running', 'succeeded', 'failed', 'cancelled', 'retrying', 'dead_letter', name='job_status'), server_default=sa.text("'queued'"), nullable=False),
    sa.Column('celery_task_id', sa.Text(), nullable=True),
    sa.Column('idempotency_key', sa.Text(), nullable=True),
    sa.Column('requested_by', sa.Uuid(), nullable=True),
    sa.Column('worker_id', sa.Text(), nullable=True),
    sa.Column('attempt', sa.SmallInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('queued_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('progress_pct', sa.SmallInteger(), nullable=True),
    sa.Column('progress_message', sa.Text(), nullable=True),
    sa.Column('error_class', sa.Text(), nullable=True),
    sa.Column('error_detail', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('resource_stats', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("error_class IS NULL OR status IN ('failed', 'retrying', 'dead_letter')", name=op.f('ck_analysis_jobs_error_only_on_failing_states')),
    sa.CheckConstraint("params_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_analysis_jobs_params_hash_is_lowercase_hex')),
    sa.CheckConstraint("status <> 'running' OR started_at IS NOT NULL", name=op.f('ck_analysis_jobs_running_has_started_at')),
    sa.CheckConstraint("status NOT IN ('succeeded', 'failed', 'cancelled', 'dead_letter') OR finished_at IS NOT NULL", name=op.f('ck_analysis_jobs_terminal_has_finished_at')),
    sa.CheckConstraint('attempt >= 0', name=op.f('ck_analysis_jobs_attempt_not_negative')),
    sa.CheckConstraint('duration_ms IS NULL OR duration_ms >= 0', name=op.f('ck_analysis_jobs_duration_not_negative')),
    sa.CheckConstraint('priority BETWEEN 0 AND 9', name=op.f('ck_analysis_jobs_priority_in_range')),
    sa.CheckConstraint('progress_pct IS NULL OR progress_pct BETWEEN 0 AND 100', name=op.f('ck_analysis_jobs_progress_in_range')),
    sa.CheckConstraint('started_at IS NULL OR finished_at IS NULL OR finished_at >= started_at', name=op.f('ck_analysis_jobs_finished_after_started')),
    sa.ForeignKeyConstraint(['case_id', 'evidence_id'], ['evidence_items.case_id', 'evidence_items.id'], name='fk_analysis_jobs_case_evidence_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_analysis_jobs_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name=op.f('fk_analysis_jobs_requested_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_analysis_jobs'))
    )
    op.create_index('ix_analysis_jobs_case_status', 'analysis_jobs', ['case_id', 'status'], unique=False)
    op.create_index('ix_analysis_jobs_evidence', 'analysis_jobs', ['evidence_id'], unique=False)
    op.create_index('ix_analysis_jobs_queue_status_priority', 'analysis_jobs', ['queue', 'status', 'priority'], unique=False)
    op.create_index('ix_analysis_jobs_requested_by', 'analysis_jobs', ['requested_by'], unique=False)
    op.create_index('ix_analysis_jobs_running', 'analysis_jobs', ['queue', 'started_at'], unique=False, postgresql_where=sa.text("status = 'running'"))
    op.create_index('uq_analysis_jobs_idempotency_key', 'analysis_jobs', ['idempotency_key'], unique=True)
    op.create_table('case_notes',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('evidence_id', sa.Uuid(), nullable=True),
    sa.Column('author_id', sa.Uuid(), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('parent_note_id', sa.Uuid(), nullable=True),
    sa.Column('pinned', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('deleted_by', sa.Uuid(), nullable=True),
    sa.Column('deletion_justification', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint('deleted_at IS NULL OR deleted_by IS NOT NULL', name=op.f('ck_case_notes_deletion_names_an_actor')),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], name=op.f('fk_case_notes_author_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['case_id', 'evidence_id'], ['evidence_items.case_id', 'evidence_items.id'], name='fk_case_notes_case_evidence_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_case_notes_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['deleted_by'], ['users.id'], name=op.f('fk_case_notes_deleted_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['parent_note_id'], ['case_notes.id'], name=op.f('fk_case_notes_parent_note_id_case_notes'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_case_notes'))
    )
    op.create_index('ix_case_notes_author', 'case_notes', ['author_id'], unique=False)
    op.create_index('ix_case_notes_case_created', 'case_notes', ['case_id', 'created_at'], unique=False)
    op.create_index('ix_case_notes_evidence', 'case_notes', ['evidence_id'], unique=False)
    op.create_table('custody_events',
    sa.Column('id', sa.Uuid(), server_default=sa.text('uuid_generate_v7()'), nullable=False),
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('evidence_id', sa.Uuid(), nullable=True),
    sa.Column('sequence', sa.BigInteger(), nullable=False),
    sa.Column('event_type', sa.Enum('ingested', 'hash_computed', 'hash_verified', 'accessed', 'downloaded', 'analyzed', 'verification_set', 'custody_transferred', 'custody_accepted', 'legal_hold', 'released', 'exported', 'quarantined', 'integrity_alert', name='custody_event_type'), nullable=False),
    sa.Column('actor_id', sa.Uuid(), nullable=True),
    sa.Column('system_actor', sa.Text(), nullable=True),
    sa.Column('acted_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('sha256_at_event', sa.CHAR(length=64), nullable=False),
    sa.Column('purpose', sa.Text(), nullable=True),
    sa.Column('ip', postgresql.INET(), nullable=True),
    sa.Column('user_agent', sa.Text(), nullable=True),
    sa.Column('request_id', sa.Text(), nullable=True),
    sa.Column('recipient_id', sa.Uuid(), nullable=True),
    sa.Column('detail', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('prev_hash', sa.CHAR(length=64), server_default=sa.text("'0000000000000000000000000000000000000000000000000000000000000000'"), nullable=False),
    sa.Column('record_hash', sa.CHAR(length=64), nullable=False),
    sa.CheckConstraint("event_type NOT IN ('accessed', 'downloaded', 'exported') OR purpose IS NOT NULL", name=op.f('ck_custody_events_content_access_states_purpose')),
    sa.CheckConstraint("prev_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_custody_events_prev_hash_is_lowercase_hex')),
    sa.CheckConstraint("record_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_custody_events_record_hash_is_lowercase_hex')),
    sa.CheckConstraint("sha256_at_event ~ '^[0-9a-f]{64}$'", name=op.f('ck_custody_events_sha256_is_lowercase_hex')),
    sa.CheckConstraint('(actor_id IS NOT NULL) <> (system_actor IS NOT NULL)', name=op.f('ck_custody_events_names_exactly_one_actor')),
    sa.CheckConstraint("system_actor IS NULL OR btrim(system_actor) <> ''", name=op.f('ck_custody_events_system_actor_is_not_blank')),
    sa.CheckConstraint('sequence > 0', name=op.f('ck_custody_events_sequence_is_positive')),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_custody_events_actor_id_users'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['case_id', 'evidence_id'], ['evidence_items.case_id', 'evidence_items.id'], name='fk_custody_events_case_evidence_evidence_items', ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_custody_events_case_id_cases'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['recipient_id'], ['users.id'], name=op.f('fk_custody_events_recipient_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_custody_events')),
    sa.UniqueConstraint('case_id', 'sequence', name='uq_custody_events_case_sequence')
    )
    op.create_index('ix_custody_events_actor', 'custody_events', ['actor_id', 'acted_at'], unique=False)
    op.create_index('ix_custody_events_case_acted', 'custody_events', ['case_id', 'acted_at'], unique=False)
    op.create_index('ix_custody_events_case_type', 'custody_events', ['case_id', 'event_type'], unique=False)
    op.create_index('ix_custody_events_evidence', 'custody_events', ['evidence_id', 'sequence'], unique=False)
    op.create_table('analysis_results',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('job_id', sa.Uuid(), nullable=False),
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('evidence_id', sa.Uuid(), nullable=True),
    sa.Column('pipeline', sa.Text(), nullable=False),
    sa.Column('pipeline_version', sa.Text(), nullable=False),
    sa.Column('result_kind', sa.Text(), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('indicators', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
    sa.Column('advisory_score', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('score_confidence_low', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('score_confidence_high', sa.Numeric(precision=5, scale=2), nullable=True),
    sa.Column('confidence', sa.Numeric(precision=5, scale=4), nullable=True),
    sa.Column('confidence_basis', sa.Text(), nullable=True),
    sa.Column('limitations_code', sa.Text(), nullable=False),
    sa.Column('requires_human_verification', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('verification_status', sa.Enum('unverified', 'confirmed', 'rejected', 'inconclusive', name='verification_status'), server_default=sa.text("'unverified'"), nullable=False),
    sa.Column('verified_by', sa.Uuid(), nullable=True),
    sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('verification_notes', sa.Text(), nullable=True),
    sa.Column('supersedes_id', sa.Uuid(), nullable=True),
    sa.Column('is_current', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('region_ref', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('derivative_ids', postgresql.ARRAY(sa.UUID()), nullable=True),
    sa.Column('raw_output', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('raw_output_schema_version', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("jsonb_typeof(indicators) = 'array'", name=op.f('ck_analysis_results_indicators_is_array')),
    sa.CheckConstraint("verification_status <> 'unverified' OR verified_by IS NULL", name=op.f('ck_analysis_results_unverified_has_no_verifier')),
    sa.CheckConstraint("verification_status = 'unverified' OR verified_at IS NOT NULL", name=op.f('ck_analysis_results_verdict_has_timestamp')),
    sa.CheckConstraint("verification_status NOT IN ('confirmed', 'rejected') OR verification_notes IS NOT NULL", name=op.f('ck_analysis_results_verdict_requires_notes')),
    sa.CheckConstraint('advisory_score IS NULL OR (score_confidence_low IS NOT NULL AND score_confidence_high IS NOT NULL)', name=op.f('ck_analysis_results_score_requires_confidence_interval')),
    sa.CheckConstraint('advisory_score IS NULL OR advisory_score BETWEEN 0 AND 100', name=op.f('ck_analysis_results_score_in_range')),
    sa.CheckConstraint('confidence IS NULL OR confidence BETWEEN 0 AND 1', name=op.f('ck_analysis_results_confidence_in_range')),
    sa.CheckConstraint('confidence IS NULL OR confidence_basis IS NOT NULL', name=op.f('ck_analysis_results_confidence_requires_basis')),
    sa.CheckConstraint('score_confidence_low IS NULL OR score_confidence_high IS NULL OR score_confidence_low <= score_confidence_high', name=op.f('ck_analysis_results_confidence_interval_is_ordered')),
    sa.CheckConstraint('verified_by IS NULL OR verified_at IS NOT NULL', name=op.f('ck_analysis_results_verifier_has_timestamp')),
    sa.ForeignKeyConstraint(['case_id', 'evidence_id'], ['evidence_items.case_id', 'evidence_items.id'], name='fk_analysis_results_case_evidence_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_analysis_results_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], name=op.f('fk_analysis_results_job_id_analysis_jobs'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['supersedes_id'], ['analysis_results.id'], name=op.f('fk_analysis_results_supersedes_id_analysis_results'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['verified_by'], ['users.id'], name=op.f('fk_analysis_results_verified_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_analysis_results'))
    )
    op.create_index('ix_analysis_results_case_kind_current', 'analysis_results', ['case_id', 'result_kind', 'is_current'], unique=False)
    op.create_index('ix_analysis_results_evidence_current', 'analysis_results', ['evidence_id', 'is_current'], unique=False)
    op.create_index('ix_analysis_results_indicators_gin', 'analysis_results', ['indicators'], unique=False, postgresql_using='gin')
    op.create_index('ix_analysis_results_job', 'analysis_results', ['job_id'], unique=False)
    op.create_index('ix_analysis_results_pipeline', 'analysis_results', ['pipeline', 'pipeline_version'], unique=False)
    op.create_index('ix_analysis_results_verification_backlog', 'analysis_results', ['case_id', 'created_at'], unique=False, postgresql_where=sa.text("verification_status = 'unverified' AND is_current"))
    op.create_table('derivatives',
    sa.Column('id', sa.Uuid(), server_default=sa.text('uuid_generate_v7()'), nullable=False),
    sa.Column('evidence_id', sa.Uuid(), nullable=True),
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.Enum('thumbnail', 'frame', 'heatmap', 'overlay', 'transcript', 'spectrogram', 'waveform', 'extracted_audio', 'extracted_file', 'report_pdf', 'graph_image', 'annotation', 'masked_preview', name='derivative_kind'), nullable=False),
    sa.Column('path', sa.Text(), nullable=False),
    sa.Column('sha256', sa.CHAR(length=64), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=True),
    sa.Column('mime', sa.Text(), nullable=True),
    sa.Column('produced_by_job_id', sa.Uuid(), nullable=True),
    sa.Column('engine_id', sa.Text(), nullable=True),
    sa.Column('engine_version', sa.Text(), nullable=False),
    sa.Column('params', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('params_hash', sa.CHAR(length=64), nullable=False),
    sa.Column('frame_index', sa.Integer(), nullable=True),
    sa.Column('pts_seconds', sa.Numeric(precision=12, scale=3), nullable=True),
    sa.Column('status', sa.Enum('available', 'stale', 'purged', 'failed', name='artifact_status'), server_default=sa.text("'available'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("params_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_derivatives_params_hash_is_lowercase_hex')),
    sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_derivatives_sha256_is_lowercase_hex')),
    sa.CheckConstraint('size_bytes IS NULL OR size_bytes >= 0', name=op.f('ck_derivatives_size_not_negative')),
    sa.ForeignKeyConstraint(['case_id', 'evidence_id'], ['evidence_items.case_id', 'evidence_items.id'], name='fk_derivatives_case_evidence_evidence_items', ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_derivatives_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['produced_by_job_id'], ['analysis_jobs.id'], name=op.f('fk_derivatives_produced_by_job_id_analysis_jobs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_derivatives')),
    sa.UniqueConstraint('evidence_id', 'case_id', 'kind', 'engine_version', 'params_hash', name='uq_derivatives_retry_safe', postgresql_nulls_not_distinct=True)
    )
    op.create_index('ix_derivatives_case_kind', 'derivatives', ['case_id', 'kind'], unique=False)
    op.create_index('ix_derivatives_evidence', 'derivatives', ['evidence_id', 'kind'], unique=False)
    op.create_index('ix_derivatives_job', 'derivatives', ['produced_by_job_id'], unique=False)
    op.create_index('ix_derivatives_stale', 'derivatives', ['case_id', 'kind'], unique=False, postgresql_where=sa.text("status = 'stale'"))
    op.create_table('report_versions',
    sa.Column('id', sa.Uuid(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('report_id', sa.Uuid(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('manifest', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('manifest_hash', sa.CHAR(length=64), nullable=False),
    sa.Column('watermark', sa.Text(), nullable=True),
    sa.Column('classification_banner', sa.Text(), nullable=True),
    sa.Column('pdf_derivative_id', sa.Uuid(), nullable=True),
    sa.Column('pdf_sha256', sa.CHAR(length=64), nullable=True),
    sa.Column('signature_block', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('crypto_signature', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('job_id', sa.Uuid(), nullable=True),
    sa.Column('engine_versions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('generated_by', sa.Uuid(), nullable=True),
    sa.Column('generated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('approved_by', sa.Uuid(), nullable=True),
    sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("jsonb_typeof(manifest) = 'object'", name=op.f('ck_report_versions_manifest_is_object')),
    sa.CheckConstraint("manifest_hash ~ '^[0-9a-f]{64}$'", name=op.f('ck_report_versions_manifest_hash_is_lowercase_hex')),
    sa.CheckConstraint("pdf_sha256 IS NULL OR pdf_sha256 ~ '^[0-9a-f]{64}$'", name=op.f('ck_report_versions_pdf_sha256_is_lowercase_hex')),
    sa.CheckConstraint('approved_at IS NULL OR (approved_by IS NOT NULL AND pdf_sha256 IS NOT NULL)', name=op.f('ck_report_versions_approval_requires_actor_and_artifact')),
    sa.CheckConstraint('generated_at IS NULL OR generated_by IS NOT NULL', name=op.f('ck_report_versions_generation_names_an_actor')),
    sa.CheckConstraint('version > 0', name=op.f('ck_report_versions_version_is_positive')),
    sa.ForeignKeyConstraint(['approved_by'], ['users.id'], name=op.f('fk_report_versions_approved_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['generated_by'], ['users.id'], name=op.f('fk_report_versions_generated_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], name=op.f('fk_report_versions_job_id_analysis_jobs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['pdf_derivative_id'], ['derivatives.id'], name=op.f('fk_report_versions_pdf_derivative_id_derivatives'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['report_id'], ['reports.id'], name=op.f('fk_report_versions_report_id_reports'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_report_versions')),
    sa.UniqueConstraint('report_id', 'version', name='uq_report_versions_report_version')
    )
    op.create_index('ix_report_versions_job', 'report_versions', ['job_id'], unique=False)
    op.create_index('ix_report_versions_manifest_hash', 'report_versions', ['manifest_hash'], unique=False)
    op.create_index('ix_report_versions_report', 'report_versions', ['report_id', 'version'], unique=False)

    # Write-once protection for stored originals (§4.1), after physical_objects exists.
    op.execute(WRITE_ONCE_FUNCTION)
    op.execute(WRITE_ONCE_TRIGGER_DROP)
    op.execute(WRITE_ONCE_TRIGGER_CREATE)

    # The ledgers become append-only at the database-role level (principle DB-3). A no-op where the
    # least-privilege roles do not exist — CI and test databases connect as the table owner.
    op.execute(APPEND_ONLY_REVOKES)

def downgrade() -> None:
    """Reverse the change, without silently destroying data.

    Dropping a table or column that holds evidence, custody history or audit records is not a
    downgrade — it is data loss wearing a downgrade's clothes. Where a reversal genuinely cannot
    preserve data, this function must raise and say what has to be done instead (§11, and
    ``migrations/README.md`` §"Downgrade strategy").
    """
    # Refuse before touching anything: every statement below is a DROP.
    _refuse_data_loss(op.get_bind())

    op.drop_index('ix_report_versions_report', table_name='report_versions')
    op.drop_index('ix_report_versions_manifest_hash', table_name='report_versions')
    op.drop_index('ix_report_versions_job', table_name='report_versions')
    op.drop_table('report_versions')
    op.drop_index('ix_derivatives_stale', table_name='derivatives', postgresql_where=sa.text("status = 'stale'"))
    op.drop_index('ix_derivatives_job', table_name='derivatives')
    op.drop_index('ix_derivatives_evidence', table_name='derivatives')
    op.drop_index('ix_derivatives_case_kind', table_name='derivatives')
    op.drop_table('derivatives')
    op.drop_index('ix_analysis_results_verification_backlog', table_name='analysis_results', postgresql_where=sa.text("verification_status = 'unverified' AND is_current"))
    op.drop_index('ix_analysis_results_pipeline', table_name='analysis_results')
    op.drop_index('ix_analysis_results_job', table_name='analysis_results')
    op.drop_index('ix_analysis_results_indicators_gin', table_name='analysis_results', postgresql_using='gin')
    op.drop_index('ix_analysis_results_evidence_current', table_name='analysis_results')
    op.drop_index('ix_analysis_results_case_kind_current', table_name='analysis_results')
    op.drop_table('analysis_results')
    op.drop_index('ix_custody_events_evidence', table_name='custody_events')
    op.drop_index('ix_custody_events_case_type', table_name='custody_events')
    op.drop_index('ix_custody_events_case_acted', table_name='custody_events')
    op.drop_index('ix_custody_events_actor', table_name='custody_events')
    op.drop_table('custody_events')
    op.drop_index('ix_case_notes_evidence', table_name='case_notes')
    op.drop_index('ix_case_notes_case_created', table_name='case_notes')
    op.drop_index('ix_case_notes_author', table_name='case_notes')
    op.drop_table('case_notes')
    op.drop_index('uq_analysis_jobs_idempotency_key', table_name='analysis_jobs')
    op.drop_index('ix_analysis_jobs_running', table_name='analysis_jobs', postgresql_where=sa.text("status = 'running'"))
    op.drop_index('ix_analysis_jobs_requested_by', table_name='analysis_jobs')
    op.drop_index('ix_analysis_jobs_queue_status_priority', table_name='analysis_jobs')
    op.drop_index('ix_analysis_jobs_evidence', table_name='analysis_jobs')
    op.drop_index('ix_analysis_jobs_case_status', table_name='analysis_jobs')
    op.drop_table('analysis_jobs')
    op.drop_index('ix_reports_created_by', table_name='reports')
    op.drop_index('ix_reports_case_status', table_name='reports')
    op.drop_index('ix_reports_case_created', table_name='reports')
    op.drop_table('reports')
    op.drop_index('ix_notifications_user_unread', table_name='notifications', postgresql_where=sa.text('read_at IS NULL'))
    op.drop_index('ix_notifications_kind', table_name='notifications')
    op.drop_index('ix_notifications_case', table_name='notifications')
    op.drop_table('notifications')
    op.drop_index('ix_evidence_items_tags_gin', table_name='evidence_items', postgresql_using='gin')
    op.drop_index('ix_evidence_items_physical_object', table_name='evidence_items')
    op.drop_index('ix_evidence_items_parent', table_name='evidence_items')
    op.drop_index('ix_evidence_items_integrity_exception', table_name='evidence_items', postgresql_where=sa.text("integrity_status IN ('mismatch', 'missing')"))
    op.drop_index('ix_evidence_items_case_type', table_name='evidence_items')
    op.drop_index('ix_evidence_items_case_status', table_name='evidence_items')
    op.drop_index('ix_evidence_items_case_created', table_name='evidence_items', postgresql_where=sa.text('deleted_at IS NULL'))
    op.drop_table('evidence_items')
    op.drop_index('ix_case_members_user_active', table_name='case_members', postgresql_where=sa.text('revoked_at IS NULL'))
    op.drop_index('ix_case_members_case_role', table_name='case_members')
    op.drop_table('case_members')
    op.drop_index('ix_audit_logs_resource', table_name='audit_logs')
    op.drop_index('ix_audit_logs_request', table_name='audit_logs')
    op.drop_index('ix_audit_logs_occurred_at', table_name='audit_logs')
    op.drop_index('ix_audit_logs_denied', table_name='audit_logs', postgresql_where=sa.text("result = 'denied'"))
    op.drop_index('ix_audit_logs_case_occurred', table_name='audit_logs')
    op.drop_index('ix_audit_logs_actor_occurred', table_name='audit_logs')
    op.drop_index('ix_audit_logs_action_occurred', table_name='audit_logs')
    op.drop_table('audit_logs')
    op.drop_index('ix_ai_provider_settings_enabled', table_name='ai_provider_settings')
    op.drop_table('ai_provider_settings')
    op.drop_index('uq_user_roles_user_role', table_name='user_roles')
    op.drop_index('uq_user_roles_primary_active', table_name='user_roles', postgresql_where=sa.text('is_primary AND revoked_at IS NULL'))
    op.drop_index(op.f('ix_user_roles_user_id'), table_name='user_roles')
    op.drop_index('ix_user_roles_user_active', table_name='user_roles', postgresql_where=sa.text('revoked_at IS NULL'))
    op.drop_table('user_roles')
    op.drop_table('role_permissions')
    op.drop_index('ix_physical_objects_written_at', table_name='physical_objects')
    op.drop_index('ix_physical_objects_unreferenced', table_name='physical_objects', postgresql_where=sa.text('reference_count = 0'))
    op.drop_table('physical_objects')
    op.drop_index('ix_cases_tags_gin', table_name='cases', postgresql_using='gin')
    op.drop_index('ix_cases_status', table_name='cases')
    op.drop_index('ix_cases_search_vector_gin', table_name='cases', postgresql_using='gin')
    op.drop_index('ix_cases_lead_investigator', table_name='cases')
    op.drop_index('ix_cases_created_at', table_name='cases')
    op.drop_table('cases')
    op.drop_index('uq_ai_models_default_per_family_task', table_name='ai_models', postgresql_where=sa.text("is_default AND status = 'active'"))
    op.drop_index('ix_ai_models_task_status', table_name='ai_models')
    op.drop_index('ix_ai_models_family', table_name='ai_models')
    op.drop_table('ai_models')
    op.drop_index('uq_users_username_lower', table_name='users', postgresql_where=sa.text('username IS NOT NULL'))
    op.drop_index('uq_users_email_lower', table_name='users')
    op.drop_index('ix_users_status', table_name='users')
    op.drop_index('ix_users_global_role', table_name='users')
    op.drop_index('ix_users_active_email', table_name='users', postgresql_where=sa.text('deleted_at IS NULL'))
    op.drop_table('users')
    op.drop_table('roles')
    op.drop_table('permissions')
    op.drop_table('organisations')

    # Objects a metadata diff cannot know about. IF EXISTS keeps the downgrade idempotent if an
    # earlier partial run already removed them.
    op.execute(sa.text('DROP TRIGGER IF EXISTS tlx_physical_objects_write_once ON physical_objects'))
    op.execute(sa.text('DROP FUNCTION IF EXISTS tlx_enforce_write_once_physical_objects()'))
    op.execute(sa.text('DROP SEQUENCE IF EXISTS case_number_seq'))
    op.execute(sa.text('DROP FUNCTION IF EXISTS tlx_array_to_text(text[])'))
    op.execute(sa.text('DROP FUNCTION IF EXISTS uuid_generate_v7()'))

    # Native enum types outlive the tables that used them; leaving them behind would make a second
    # `upgrade` fail on CREATE TYPE.
    op.execute(sa.text("DROP TYPE IF EXISTS global_role"))
    op.execute(sa.text("DROP TYPE IF EXISTS user_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS password_alg"))
    op.execute(sa.text("DROP TYPE IF EXISTS case_role"))
    op.execute(sa.text("DROP TYPE IF EXISTS case_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS sensitivity"))
    op.execute(sa.text("DROP TYPE IF EXISTS evidence_type"))
    op.execute(sa.text("DROP TYPE IF EXISTS evidence_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS integrity_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS source_type"))
    op.execute(sa.text("DROP TYPE IF EXISTS enc_state"))
    op.execute(sa.text("DROP TYPE IF EXISTS custody_event_type"))
    op.execute(sa.text("DROP TYPE IF EXISTS derivative_kind"))
    op.execute(sa.text("DROP TYPE IF EXISTS artifact_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS job_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS verification_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS model_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS report_status"))
    op.execute(sa.text("DROP TYPE IF EXISTS audit_result"))
