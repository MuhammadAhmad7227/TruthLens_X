# ADR-0010 — PostgreSQL Row-Level Security is NOT implemented in v1

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-010 |
| **Decided by** | Owner instruction under D-004 condition: *"Do not implement tenant_id, PostgreSQL Row-Level Security, per-tenant encryption keys, or tenant quotas in v1."* |
| **Conflicts flagged** | ⚠️ My original proposal for D-010 was "defer to M20 as optional hardening". The D-004 approval **explicitly prohibits RLS in v1**, which includes M20. **The explicit instruction wins**; this ADR records the change. |
| **Related** | [ADR-0004](./ADR-0004-single-organisation-capability-rbac.md) · [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) §4.3 |

## Context
RLS would provide defence in depth: even a buggy query could not cross case boundaries. But the owner
excluded it from v1 scope, and RLS with a single shared application role adds per-request
`SET LOCAL` plumbing, policy maintenance across ~20 tables, and a real risk of subtly breaking
legitimate queries.

## Decision
1. **No RLS policies in v1**, at any milestone including M20.
2. Least privilege is enforced by four compensating controls:
   - **One authorisation choke point** — `require_case_access(case_id, capability)`, case id taken
     from the path and re-asserted against the loaded resource.
   - **Repository lint rule** — any query against a case-scoped table without a `case_id` predicate
     fails a static check.
   - **Route-enumeration test** — 100% of routes must declare expected capabilities (CI-blocking).
   - **Negative matrix test** — every forbidden action asserted with its specific deny code, including
     cross-case UUID guessing.
3. DB roles still separate DML (`tlx_app`), DDL (`tlx_migrator`), worker and read-only auditor
   access, and `UPDATE`/`DELETE` are revoked on append-only tables. That is role-level privilege
   separation, not RLS.
4. The schema stays **RLS-ready**: every case-scoped table has a non-null `case_id`, so policies can
   be added later without a data migration.

## Alternatives considered
| Option | Verdict |
|---|---|
| Implement RLS in M20 (my original proposal) | **Superseded by the owner's explicit exclusion** |
| RLS from M2 | Rejected — same instruction, plus cost |
| No RLS and no compensating controls | Rejected — unacceptable |

## Rationale
The compensating controls target the actual failure mode (a route or query that forgot the scope) with
tests that fail the build. RLS would add a second enforcement layer at meaningful complexity cost, and
the owner has judged that cost not worth it for a single-organisation v1.

## Consequences
**Positive:** simpler sessions and connection pooling (no per-request `SET LOCAL`), faster
development, no risk of RLS silently breaking admin or maintenance queries.
**Negative / accepted costs:** a repository-layer bug that omits the `case_id` predicate is caught by
tests rather than by the database. This is a **real residual risk** and is recorded as such in
SECURITY_ARCHITECTURE §4.3 point 6 and §9.7.

## Licensing implications
None.

## Security implications
Defence in depth is reduced by one layer. Compensated by the four controls above, all CI-enforced.
Residual risk accepted explicitly by the owner. Re-evaluate if multi-tenancy is introduced (then RLS
becomes materially more valuable, and ADR-0004's reversal path includes it).

## Reversal strategy
Additive and low-risk because the schema is RLS-ready: enable RLS per table, create policies keyed on
a session variable, set it in the session-acquisition hook, and run the existing negative matrix
against both layers. Estimated 4 days. Requires amending this ADR and the D-004 instruction.

## Verification
- Repository lint rule test: a deliberately unscoped query on `evidence_items` fails the static check.
- Route-enumeration test: zero routes without a declared capability.
- Negative matrix: cross-case access returns `404` and writes a `FORBIDDEN_CASE_ACCESS` audit event.
- A test asserts `pg_policies` is empty in v1, so accidental policy introduction is visible.
