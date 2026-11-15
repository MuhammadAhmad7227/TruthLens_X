# Migrations

The schema is built by these scripts and by nothing else. `DATABASE_DESIGN.md` §1 principle DB-7
states it as a rule — **no manual DDL, ever** — and the reason is not tidiness: a production database
whose shape cannot be reconstructed from this repository is a database nobody can reason about during
an incident, and a schema change applied by hand in one environment is a change that does not exist
in the next.

Everything here targets **PostgreSQL 16** (§11). The schema uses native enums, `JSONB`, generated
columns, partial and functional indexes, `NULLS NOT DISTINCT`, `INET`, `TSVECTOR` and a PL/pgSQL
UUIDv7 function. None of that is portable, and pretending otherwise would cost guarantees rather
than gain them.

---

## Running them

The connection string is **not** in `alembic.ini`. `env.py` resolves it through the application's own
Pydantic settings, so a migration cannot run against a database the API does not connect to:

```bash
cd backend
export DATABASE_URL='postgresql+psycopg://tlx_app:<password>@postgres:5432/truthlens'

alembic upgrade head      # apply everything pending
alembic current           # what this database believes it is
alembic history           # what this repository can build
alembic check             # would autogenerate change anything? (the §11 drift gate)
```

`alembic check` is the one to run after touching a model. It asks Alembic to autogenerate against a
migrated database and reports anything it would change; a non-empty answer means the models and the
migrations have diverged, and the divergence will reach production as a query against a column that
does not exist.

### Running as the migration role, not the application role

Least privilege (§11, and the grants in `infra/postgres/initdb/`): the application role `tlx_app`
cannot `CREATE`, and must not be able to. Migrations run as `tlx_migrator`, which owns the schema and
holds DDL rights — and which is *revoked* from `UPDATE`/`DELETE` on the two append-only ledgers, so
even the role that builds the schema cannot rewrite custody history.

```bash
# For the duration of the command only. Do not put this URL in the API's environment.
DATABASE_URL='postgresql+psycopg://tlx_migrator:<password>@postgres:5432/truthlens' \
    alembic upgrade head
```

A deployment runs this as a separate step, before the API starts, and the API then reports its own
schema state through `/readyz` (`app.db.migrations.verify_schema_head`). A server whose schema is
behind its code answers `503` rather than serving queries it cannot satisfy.

---

## Downgrade strategy

A downgrade is not an undo. By the time a revision has run, the rows it created may be referenced by
work that happened afterwards, and the difference between "roll back the schema" and "destroy the
evidence" is one foreign key.

So every revision in this directory follows the same three rules.

**1. A downgrade refuses by default.** Before removing anything, it asks whether anything depends on
what it is about to remove, and raises a `RuntimeError` naming the dependents if so. Revision `0001`
checks every table for rows; revision `0002` checks `user_roles`, `role_permissions` and `cases`. The
message says what has to be removed first, because "cannot downgrade" without a reason is not an
operator-facing message.

**2. Data loss is opt-in, explicit, and spelled the same way everywhere.**

```bash
alembic -x allow_data_loss=true downgrade base
```

The flag is read with `alembic.runtime.context.get_x_argument()`, so it works identically from a
shell and from a test (`tests/db/conftest.py` sets `config.cmd_opts` to drive it). There is no
environment-variable equivalent: an env var persists in a shell and in a container, and a flag that
is still set tomorrow is not a decision made today.

**3. Taking the schema down to `base` must leave nothing behind.** Tables are the obvious part; enum
types, functions, sequences and triggers are what a table-by-table drop forgets. Left behind, the next
`upgrade head` fails on a type that already exists, and the error says nothing about which revision
put it there. `tests/db/test_migrations.py::TestDowngradeLifecycle` asserts the empty result
explicitly — zero enums, zero functions, zero sequences, zero triggers — and then rebuilds from
nothing and re-runs `alembic check`.

What a downgrade is *for*: recovering a failed deployment on a database that has not yet taken
traffic, and local development. What it is not for: undoing a release on a database holding evidence.
§12 is explicit that custody and audit history outlive the case and are never deleted in v1, and a
schema rollback that removes those tables removes the record of who did what.

---

## The write-once object ledger, and its escape hatch

`physical_objects` is guarded by a trigger (`tlx_physical_objects_write_once`) that refuses any
`UPDATE` touching a digest, a size, a path, a MIME type or the write time, and refuses `DELETE`
outright. Bookkeeping columns — `reference_count`, `av_scan_status`, `av_scan_detail` — remain
writable, because a rule that blocks them gets switched off, and a switched-off rule protects nothing.

Correcting a genuine mistake (a mistyped storage path, a failed AV integration) requires:

```sql
BEGIN;
SET LOCAL app.maintenance = 'on';
UPDATE physical_objects SET storage_path = '/corrected/path' WHERE sha256 = '…';
COMMIT;
```

`SET LOCAL`, never `SET`: the setting is scoped to the transaction, so it cannot leak into the next
statement on a pooled connection and silently leave the ledger writable. `tests/db/test_session.py`
asserts exactly that boundary, with two real transactions on one connection — a savepoint release
does not end the transaction containing it, so testing it through the request-session fixture would
measure the fixture rather than the database.

**The obligation that comes with it.** Using this switch alters a record of what evidence existed and
where. It must therefore be: approved before the run, performed inside a transaction that also writes
an `audit_logs` row naming the actor, the reason and the before/after values, and reviewed afterwards
by somebody who did not perform it. The application roles cannot set it — `infra/postgres/initdb/`
grants `SET` on `app.maintenance` to the administrative role only, which is why the trigger can trust
the setting at all.

---

## Writing a new revision

```bash
alembic revision --autogenerate -m "add the thing"
```

Then **read the generated file**. Autogenerate is a draft, and four things it gets wrong are worth
naming because each has already happened here:

* **Enum type names.** It derives a type name from the column, so `password_alg` became
  `password_algorithm` — a second type with almost the same name. `app/models/enums.native_enum()`
  takes an explicit `name=` for exactly this reason. Check the generated `sa.Enum(..., name=…)`.
* **Generated columns must be immutable.** `to_tsvector('english', …)` binds the `STABLE` overload
  and PostgreSQL refuses it in a generated column with `generation expression is not immutable`. Cast
  the config (`'english'::regconfig`) and route arrays through the `IMMUTABLE` helper
  `tlx_array_to_text()`. Never declare a non-immutable function `IMMUTABLE` to get past this.
* **Server defaults do not round-trip.** PostgreSQL normalises a stored default
  (`'investigator'::global_role`) into a form that rarely matches the model's `text("…")`
  byte-for-byte, so `env.py` leaves `compare_server_default` off. It produces phantom drift, and a
  gate that cries phantom is a gate people learn to ignore. Consequence: **a changed default needs a
  hand-written `op.alter_column`.** Autogenerate will not see it.
* **Reserved words.** `CREATE FUNCTION tlx_array_to_text(values text[])` is a syntax error, because
  `values` is reserved. The parameter is named `elements`.

Conventions the rest of this directory follows:

* File names are `<sequence>_<slug>.py` (`file_template` in `alembic.ini`), so the order of the
  history is visible in a directory listing.
* Constraint and index names come from the naming convention in `app/db/base.py`, never from
  SQLAlchemy's hash-derived defaults (principle DB-7). A deterministic name is what makes
  `op.drop_constraint` mean the constraint you think it means.
* **Never edit a revision that has been applied somewhere.** Add a new one. The one exception is a
  revision on an unmerged branch that no environment has run — which is why `0001` and `0002` were
  still editable while M2 was in flight, and stop being editable the moment they are deployed.
* A revision that adds a column something reads must be **expand-and-contract** (§11): add the column
  nullable, backfill, add the constraint, and only then make it `NOT NULL` — across separate
  revisions, so a rollback mid-way leaves a schema the previous release can still run against.
* Seeds are idempotent (`ON CONFLICT DO NOTHING`). A migration that can only run exactly once cannot
  be retried after a partial failure, and a half-applied seed is recovered by running it again.

---

## Deliberate deviations from `DATABASE_DESIGN.md`

Recorded here because a reader comparing the schema to §3.1 will otherwise find them and wonder.

| §3.1 asks for | This schema does | Why |
|---|---|---|
| `citext` for `users.email`, `users.username` | `TEXT` + functional unique indexes on `lower(…)` | `citext` is a contrib extension, so it is a deployment dependency; and its comparison is implicit, which means a query planner choice can change whether two addresses are the same. An explicit `lower()` index is the same guarantee and is visible in the DDL. |
| `pgcrypto` for `gen_random_uuid()` | The built-in `gen_random_uuid()` | PostgreSQL 13+ provides it in core. §4.1's digests are computed by the application, not by SQL, so nothing else from `pgcrypto` is needed. |
| `uuid-ossp` for time-ordered ids | A PL/pgSQL `uuid_generate_v7()` in revision `0001` | PostgreSQL 16 has no built-in v7. The recipe uses `clock_timestamp()` and the server CSPRNG. |
| `roles`/`permissions` absent from the design | Present, plus `role_permissions` | `SECURITY_ARCHITECTURE` §4.2 requires named capabilities stored as data. The design document's `capabilities`/`rbac_matrix` tables are these. |
| `evidence`, `evidence_hashes`, `evidence_artifacts`, `model_registry` | `evidence_items`, `physical_objects`, `derivatives`, `ai_models` | The design document's own §4/§3.5 names, which supersede the earlier milestone vocabulary. |

`role_permissions` is seeded **empty** on purpose. Deciding which role holds which capability *is*
the authorization design, and that is milestone M3. An empty matrix denies everything, so a missing
decision fails closed; a seeded guess would be a plausible-looking matrix nobody ratified.
