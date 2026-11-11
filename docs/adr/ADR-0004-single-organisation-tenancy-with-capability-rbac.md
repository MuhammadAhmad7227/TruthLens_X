# ADR-0004 — Single organisation in v1, capability-based RBAC, multi-tenancy-ready schema

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-004 |
| **Related** | [ADR-0010](ADR-0010-no-row-level-security-in-v1.md), [ADR-0018](ADR-0018-mandatory-mfa-for-privileged-roles.md), [DATABASE_DESIGN §3](../DATABASE_DESIGN.md), [SECURITY_ARCHITECTURE §5](../SECURITY_ARCHITECTURE.md) |

## Context

The owner directed: **one organisation, multiple users, RBAC, case-level access via membership.**
Authorisation must be enforced on every backend endpoint and on evidence download, never inferred
from frontend visibility. Sensitive actions go to immutable-style audit and custody logs. The schema
must allow multi-tenancy later **without a complete rewrite** — but v1 must **not** implement
`tenant_id`, PostgreSQL RLS, per-tenant encryption keys or tenant quotas.

## Decision

1. **Roles** (global): `admin`, `lead_investigator`, `investigator`, `analyst`, `reviewer`, `auditor`.
   Each case additionally carries a per-user `case_role`.
2. **30 named capabilities** are seeded in `capabilities` and mapped in `rbac_matrix`. The eight the
   owner named explicitly are: `view_case`, `edit_case`, `upload_evidence`, `view_evidence`,
   `analyze_evidence`, `export_reports`, `manage_members`, `delete_evidence`. The remaining 22 come
   from this ADR and include `view_evidence_content`, `verify_finding`, `hard_delete_evidence`,
   `enable_external_ai`, `break_glass`, `read_audit`, `verify_audit_chain`, `approve_report`,
   `use_assistant`, `manage_queues`, `close_case`, `reopen_case`, `create_comparison`,
   `create_graph_edge`, `verify_graph_edge`, `create_timeline_event`, `generate_report`,
   `edit_evidence_metadata`.
3. `case_members.capability_overrides text[]` permits per-case grants/revocations on top of the role
   matrix.
4. **One authorisation gate**: `require_case_access(case_id, capability)`. Every case-scoped route
   declares an `x-capability` extension in OpenAPI; CI fails if coverage is below 100%.
5. **A case the caller cannot access returns `404`, never `403`**, so existence is not enumerable.
   The denial reason `FORBIDDEN_CASE_ACCESS` is recorded **server-side in the audit log only**, never
   in the response body (see the refinement note below).
6. Evidence download uses HMAC-signed, short-lived URLs (TTL 120 s, hard max 900 s) with a
   **mandatory `purpose`** parameter; the signature covers the capability check.
7. `admin` has **no implicit access to evidence content.** Viewing content requires `break_glass`
   with a written justification, and `admin` can never set a finding's verification status.
8. **Tenancy readiness without tenancy**: `cases.organisation_id` exists as an **inert** foreign key
   to a single seeded row `org_default`. Application authorisation **never reads it** in v1. It is
   present so that adding real tenancy later is a data migration plus a predicate change, not a
   schema rewrite.
9. **Explicitly excluded from v1**: `tenant_id` columns, PostgreSQL Row-Level Security, per-tenant
   encryption keys, tenant quotas. See ADR-0010.
10. The authorisation matrix is published in `docs/SECURITY_ARCHITECTURE.md` §5 and cross-case access
    restriction is covered by dedicated tests.

> **Refinement flagged ⚠️ during ratification.** `docs/API_SPECIFICATION.md` originally listed
> `FORBIDDEN_CASE_ACCESS` as a **403** error code, which conflicts with the non-enumerability
> requirement in `SECURITY_ARCHITECTURE.md` §5.5 and with the alerting requirement in §9 that
> `FORBIDDEN_CASE_ACCESS` events be detectable. Resolved in favour of security: the **HTTP status is
> 404 and the client-visible `error_code` is `NOT_FOUND`**, while the server records
> `audit_reason = FORBIDDEN_CASE_ACCESS` for alerting. The API spec table is corrected accordingly.

## Alternatives considered

| Option | Verdict |
|---|---|
| Full multi-tenancy with RLS in v1 | Rejected by the owner — unnecessary complexity for a single-org deployment. |
| Role checks only, no capability layer | Rejected — cannot express "analyst may view but not export", and per-case overrides would need bespoke code. |
| Return 403 on case-access denial | Rejected — leaks case existence across an insider boundary. |
| Give `admin` implicit evidence access | Rejected — the highest-privilege account is the highest-value target; break-glass with justification is auditable. |

## Rationale

Capabilities compose; roles do not. A single gate makes "every endpoint is authorised" a checkable
property rather than a hope. The inert `organisation_id` buys future optionality at the cost of one
nullable column and one seeded row.

## Consequences

* Every route carries an explicit capability declaration — verbose but CI-verifiable.
* 404-for-denied means client code cannot distinguish "missing" from "forbidden"; the `request_id`
  lets support resolve it from logs.
* Frontend hiding of controls is **cosmetic only** and is documented as such; no security property
  depends on it.

## Licensing implications

None — all first-party code.

## Security implications

Deny-by-default at one choke point; non-enumerable denials; least privilege for `admin` over evidence
content; every grant, override and denial is audit-recorded. Cross-case access attempts are the
highest-signal insider indicator and raise an alert.

## Reversal strategy

Multi-tenancy later: populate `organisation_id` per tenant, add the predicate to
`require_case_access`, then (optionally, per ADR-0010) enable RLS as defence-in-depth. No column
renames, no table rebuilds.

## Verification

* CI asserts 100% of case-scoped routes declare `x-capability`.
* Tests: member/non-member/removed-member/override-granted/override-revoked per capability;
  cross-case access returns 404 and writes an audit row with `audit_reason=FORBIDDEN_CASE_ACCESS`.
* A test asserts `admin` without `break_glass` cannot read evidence content.
* A test asserts signed download URLs expire and reject a mismatched `purpose`.
