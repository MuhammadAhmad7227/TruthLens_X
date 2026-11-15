-- ═══════════════════════════════════════════════════════════════════════════════════════════════
-- Least-privilege database roles for TruthLens X.
--
-- WHAT THIS IS
--   DATABASE_DESIGN §11 names four roles and what each may do:
--
--       tlx_migrator   DDL — used only by `alembic upgrade`
--       tlx_app        DML only — the API's role, cannot CREATE
--       tlx_worker     DML for the async platform (Celery result backend, see CELERY_BROKER_URL)
--       tlx_auditor    read-only — the role an audit review connects with
--
--   The names are not this script's invention: `.env.example` documents them as TLX_DB_ROLE_APP,
--   TLX_DB_ROLE_MIGRATOR, TLX_DB_ROLE_WORKER and TLX_DB_ROLE_AUDITOR; `infra/compose/docker-compose.yml`
--   builds DATABASE_URL and CELERY_BROKER_URL out of tlx_app and tlx_worker; and
--   `backend/migrations/versions/0001_initial_schema.py` and `0003_…py` both carry a role-guarded
--   DO block that REVOKEs UPDATE/DELETE/TRUNCATE on the append-only ledgers from tlx_app,
--   tlx_worker and tlx_auditor. Those blocks test `pg_roles` first and no-op when the roles are
--   absent, which is why this script exists: without it the revokes protect nothing, and the stack
--   runs as the bootstrap superuser — which §11 says is acceptable for a supervised development
--   bring-up and is NOT acceptable in production.
--
-- WHEN IT RUNS, AND WHEN IT DOES NOT
--   Mounted at /docker-entrypoint-initdb.d (see the postgres service in docker-compose.yml), so the
--   container image's entrypoint executes it with psql once, as POSTGRES_USER, against POSTGRES_DB.
--   **Only on first initialisation, when the data directory is empty.** Adding a role here after the
--   volume exists does nothing at all — it is not re-run on restart. To apply a change to an existing
--   deployment, run the file by hand:
--
--       docker compose -f infra/compose/docker-compose.yml exec -T postgres \
--           psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" < infra/postgres/initdb/10-roles.sql
--
--   It is written to be safe to run that way: role creation is conditional, and an existing role's
--   password is deliberately NOT overwritten (see the WHERE on the CREATE ROLE query).
--
-- WHAT IT DOES NOT DO
--   * It creates no database. POSTGRES_DB is created by the entrypoint itself, before this runs.
--   * It creates no schema objects and grants no privileges on tables, because none exist yet — the
--     migration baseline creates them. Table access is arranged below with ALTER DEFAULT PRIVILEGES,
--     which is the mechanism that makes "the roles exist before the tables do" work at all.
--   * It sets no CONNECTION LIMIT, no VALID UNTIL and no per-role password rotation. Those are
--     operator policy for a deployment, not a property of the schema, and guessing a limit here would
--     be a guess about a pool size this file cannot see.
-- ═══════════════════════════════════════════════════════════════════════════════════════════════

\set ON_ERROR_STOP on

-- The container environment, read by psql rather than interpolated by Compose: the entrypoint passes
-- this file to psql, and psql is what can see POSTGRES_PASSWORD.
--
-- One password for all four roles, because that is what the stack already assumes:
-- docker-compose.yml builds DATABASE_URL as `tlx_app:${POSTGRES_PASSWORD}` and CELERY_BROKER_URL as
-- `tlx_worker:${POSTGRES_PASSWORD}`. Inventing four separate mandatory variables here would make the
-- documented Compose file unable to connect, and would break the .env.example-sufficiency gate in
-- .github/workflows/compose-config.yml. Giving the four roles distinct credentials is a hardening
-- step for a deployment (four ALTER ROLE statements and four Compose variables), not something this
-- bootstrap can decide on the operator's behalf.
\getenv bootstrap_password POSTGRES_PASSWORD

-- §11's four roles, created only if absent.
--
-- `\gexec` rather than a DO block, and the reason is a psql detail that would otherwise cost an hour:
-- psql substitutes variables in ordinary query text but NOT inside a dollar-quoted string, so
-- `:'bootstrap_password'` in a DO block body arrives at the server as a literal colon and fails with
-- a syntax error. `\gexec` runs each row of the result as a statement, which keeps the substitution
-- in ordinary query text where it works.
--
-- An existing role is left exactly as it is: the WHERE excludes it, so a re-run neither resets a
-- password the operator rotated nor fails on "role already exists".
SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
    role_specification.rolname,
    :'bootstrap_password'
)
FROM (
    VALUES ('tlx_migrator'), ('tlx_app'), ('tlx_worker'), ('tlx_auditor')
) AS role_specification(rolname)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_specification.rolname)
\gexec

DO $access$
DECLARE
    database_name text := current_database();
    owner_role    text;
BEGIN
    -- Connecting to this database at all. CONNECT is granted to PUBLIC by default, but a deployment
    -- that later revokes it — the ordinary hardening step — would otherwise break every role here.
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO tlx_migrator, tlx_app, tlx_worker, tlx_auditor',
        database_name
    );

    -- Reaching the schema, without the right to create in it. PostgreSQL 15 removed CREATE on
    -- schema public from PUBLIC; USAGE is still needed by every role that reads or writes a table.
    EXECUTE 'GRANT USAGE ON SCHEMA public TO tlx_migrator, tlx_app, tlx_worker, tlx_auditor';
    EXECUTE 'GRANT CREATE ON SCHEMA public TO tlx_migrator';

    -- ── Table access, arranged before the tables exist ─────────────────────────────────────────
    -- GRANT ... ON ALL TABLES would grant nothing here: this runs before the migration baseline
    -- creates a single table. ALTER DEFAULT PRIVILEGES is the mechanism that covers tables created
    -- *later*, which is the whole bootstrap ordering problem.
    --
    -- It is set for two owners because the migration may run as either. backend/migrations/README.md
    -- documents `tlx_migrator` as the role that owns the schema, while docker-compose.yml still runs
    -- the stack as its bootstrap superuser; default privileges are per-owner, so covering only one
    -- would leave the other's tables invisible to every application role.
    --
    -- Note what is granted and what is not: tlx_app and tlx_worker get DML (SELECT, INSERT, UPDATE,
    -- DELETE) and never CREATE; tlx_auditor gets SELECT and nothing else. UPDATE and DELETE on the
    -- append-only ledgers are then removed by the migration's own REVOKE, which runs after each
    -- CREATE TABLE — so the ordering is grant-by-default first, narrow afterwards, and the
    -- narrowing is enforced by the schema rather than remembered by an operator.
    FOREACH owner_role IN ARRAY ARRAY[current_user, 'tlx_migrator'] LOOP
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tlx_app, tlx_worker',
            owner_role
        );
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
            'GRANT SELECT ON TABLES TO tlx_auditor',
            owner_role
        );
        -- case_number_seq backs cases.case_number, so an INSERT into cases needs USAGE on a
        -- sequence. Without this the failure presents as "permission denied for sequence", which
        -- reads like a broken table grant and sends whoever hits it looking in the wrong place.
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public '
            'GRANT USAGE, SELECT ON SEQUENCES TO tlx_app, tlx_worker',
            owner_role
        );
    END LOOP;

    RAISE NOTICE 'granted access to % for tlx_migrator, tlx_app, tlx_worker, tlx_auditor',
        database_name;
END
$access$;
