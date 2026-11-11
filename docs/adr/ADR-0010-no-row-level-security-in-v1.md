# ADR-0010 — No PostgreSQL Row-Level Security in v1 (excluded entirely, including M20)

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-010 |
| **Refinement flagged ⚠️** | Yes — the proposal was "defer to M20"; the owner's ratification **excluded RLS from v1 entirely**. |
| **Related** | [ADR-0004](ADR-0004-single-organisation-tenancy-with-capability-rbac.md), [SECURITY_ARCHITECTURE §5](../SECURITY_ARCHITECTURE.md) |

## Context

The M0 proposal suggested deferring PostgreSQL Row-Level Security to M20 as defence-in-depth. The
owner's ratification went further: **do not implement `tenant_id`, PostgreSQL RLS, per-tenant
encryption keys or tenant quotas in v1 at all.** This ADR records the stronger position so the
roadmap is not silently re-widened.

## Decision

1. **No RLS policies are created in v1**, and none are scheduled in any milestone including M20.
2. **No `tenant_id` column exists on any table.** `cases.organisation_id` is inert (ADR-0004) and is
   not an RLS key.
3. Authorisation is enforced **exclusively in the application layer** at the single gate
   `require_case_access(case_id, capability)`, backed by `case_members` and `rbac_matrix`.
4. Database roles still provide meaningful separation, and this is **not** relaxed: `tlx_app`,
   `tlx_migrator`, `tlx_worker`, `tlx_auditor`; `UPDATE` and `DELETE` are **revoked** from `tlx_app`
   on `audit_logs` and `custody_events`, and a trigger blocks mutation of `physical_objects`.
5. Multi-tenancy in v2 must be designed deliberately — RLS may be chosen then, as defence-in-depth
   on top of application checks, never as the primary control.

## Alternatives considered

| Option | Verdict |
|---|---|
| RLS as the primary authorisation mechanism | Rejected — splits the authorisation model across two languages, and a missed `SET LOCAL` silently becomes a data-exposure bug that is hard to test for. |
| RLS as defence-in-depth in M20 | **Superseded by the owner's ratification** — excluded from v1 entirely. Re-proposable for v2. |
| No DB-level controls at all | Rejected — role grants and the immutability triggers are cheap, testable and independent of application correctness. |

## Rationale

With a single organisation and one enforcement point, RLS would add a second place for authorisation
to be wrong without adding a threat it mitigates. The immutability triggers and revoked DML give the
genuine database-side protections that matter for evidence integrity.

## Consequences

* **Application-layer correctness is load-bearing.** If `require_case_access` is bypassed, there is no
  second net. This raises the importance of the 100% `x-capability` coverage CI gate (ADR-0004).
* A single compromised application credential (`tlx_app`) can read across cases. Mitigated by
  network isolation, no egress from media workers, and audit alerting on cross-case access attempts.
* Residual risk is recorded in `SECURITY_ARCHITECTURE.md` §2.2 threat model rather than hidden.

## Licensing implications

None.

## Security implications

Explicit trade-off, documented not concealed: one enforcement layer instead of two, in exchange for a
single, fully testable authorisation model. Compensating controls: deny-by-default gate, non-enumerable
ids, immutable audit chain, cross-case-attempt alerting.

## Reversal strategy

v2: add policies keyed on a real tenancy column, keep the application gate, and enable
`row_security` enforcement for `tlx_app`. Additive — no rewrite, thanks to ADR-0004's inert
`organisation_id`.

## Verification

* Migration test asserts **zero** `pg_policies` rows exist after `upgrade head`.
* Migration test asserts `UPDATE`/`DELETE` are revoked from `tlx_app` on audit and custody tables.
* Trigger test asserts `physical_objects` mutation is rejected.
* CI gate asserts 100% of case-scoped routes declare `x-capability`.
