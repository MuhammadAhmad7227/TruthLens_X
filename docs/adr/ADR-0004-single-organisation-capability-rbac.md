# ADR-0004 — Single-organisation v1 with capability-based RBAC; tenancy-ready schema, no tenant_id

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-004 |
| **Decided by** | Project owner, with 10 attached conditions |
| **Related** | [ADR-0010](./ADR-0010-no-row-level-security-in-v1.md) · [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) §4 · [DATABASE_DESIGN.md](../DATABASE_DESIGN.md) §3 |

## Context
The platform holds compartmented case data. Multi-tenancy would add `tenant_id` to ~20 tables,
Postgres RLS, per-tenant keys and quotas. The owner confirmed a single organisation for v1 but
required that **multi-tenancy be introducible later without a complete rewrite**, and that
`tenant_id`, RLS, per-tenant keys and tenant quotas **not** be implemented now.

## Decision
1. One organisation, many users. Authorisation is **two-layer**: a global role plus case membership.
2. Permissions are expressed as **named capabilities**, resolved from a seeded `rbac_matrix` table:
   `view_case`, `edit_case`, `upload_evidence`, `view_evidence`, `view_evidence_content`,
   `analyze_evidence`, `verify_finding`, `export_reports`, `manage_members`, `delete_evidence`,
   `manage_audit`, `manage_users`, `manage_models`, `manage_settings`, `break_glass`.
3. Authorisation is enforced on **every** backend API endpoint and on every evidence download, by a
   single dependency: `require_case_access(case_id, capability)`. Case id comes from the **path** and
   is re-asserted against the loaded resource.
4. **Frontend visibility is never a security control.** Hidden buttons are a UX affordance; the server
   re-evaluates every request.
5. Sensitive actions write immutable-style, hash-chained audit and custody records.
6. Access without the required membership **and** capability is denied, returning `404` (not `403`)
   for case-scoped resources so existence is not enumerable.
7. The authorisation matrix is documented and cross-case access is tested (route-enumeration test +
   negative matrix).

### Tenancy-readiness without `tenant_id` (condition 9)
- **`cases` is the isolation root.** Every case-scoped table already carries `case_id`, and every
  query is case-scoped by construction. A future tenant is therefore a *grouping of cases*, not a
  rewrite of the data model.
- A nullable `organisation_id` column is **designed into `cases` now but constrained to a single
  seeded row** (`org_default`) in v1. It is not read by any authorisation logic yet. Adding tenancy
  becomes: populate real organisations, backfill `organisation_id`, add the predicate to the single
  authorisation choke point, then enable RLS.
- The `StorageBackend` and `SecretProvider` interfaces are per-organisation-shaped (they take a scope
  argument), so per-tenant storage roots and keys are a wiring change, not a redesign.
- The hash chain is scoped per case, so per-tenant chains need no restructuring.

## Alternatives considered
| Option | Verdict |
|---|---|
| Multi-tenant from the first migration | **Rejected by the owner** for v1 — ~+15 days and significant complexity with no current need |
| Role checks scattered per endpoint | **Rejected** — unauditable, and the classic source of "one endpoint forgot the check" (threat T-03) |
| Frontend-only gating | **Rejected** — explicitly prohibited by condition 6 |
| `tenant_id` on every table now, unused | **Rejected** — dead columns invite inconsistent use and complicate the migration later; `organisation_id` on the isolation root (`cases`) achieves the same future-readiness |

## Rationale
A single choke point makes the security property *testable* rather than *hoped for*: one test walks
every registered route and asserts its required capability, so a missing check cannot be merged.
Naming permissions as capabilities (rather than inferring them from role strings inline) makes the
matrix data, reviewable and migratable.

## Consequences
**Positive:** least privilege is enforceable and verifiable; adding a new role is a data change;
tenancy later is additive.
**Negative / accepted costs:** two membership/role concepts to explain to users; an unused
`organisation_id` column in v1 (documented as intentionally inert); capability resolution adds one
cached query per request (mitigated by a per-request cache and a short Redis TTL).

## Licensing implications
None.

## Security implications
This is the primary access-control decision. It satisfies SO-4, mitigates T-03 and T-04, and makes
`admin` content access non-implicit (break-glass only, justified, time-bounded, notified, audited).
`admin` deliberately cannot set verification status (separation of duties). Residual: no RLS, so a
repository-layer bug could in principle cross cases — compensated by the repository lint rule, the
route-enumeration test, and the negative matrix (see ADR-0010).

## Reversal strategy
**To add tenancy:** populate `organisations`, backfill `organisation_id` from case→org mapping, add
the predicate inside `require_case_access` (one place), enable RLS policies, add per-tenant storage
roots and keys. Estimated ~10–15 days because the choke point already exists. **To change a
capability assignment:** a data migration against `rbac_matrix` — no code change.

## Verification
- `test_route_authorisation_matrix.py` — 100% of routes declare expected capabilities; CI-blocking.
- `test_negative_matrix.py` — every capability-matrix cell exercised, asserting the **specific** deny code.
- Cross-case UUID guessing returns `404` and writes a `FORBIDDEN_CASE_ACCESS` audit event.
- Expired time-bounded membership denies on the next request.
