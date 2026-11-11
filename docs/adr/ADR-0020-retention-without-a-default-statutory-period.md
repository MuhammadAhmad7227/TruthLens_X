# ADR-0020 — Retention has no default statutory period; unset means delete nothing

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-020 |
| **Related** | [ADR-0004](ADR-0004-single-organisation-tenancy-with-capability-rbac.md), [ADR-0019](ADR-0019-report-manifest-hashing-with-optional-crypto-signing.md), [BACKUP_RECOVERY](../BACKUP_RECOVERY.md) |

## Context

Evidence retention periods are set by law, regulation or organisational policy, and they differ by
jurisdiction and case type. Choosing a default number would be a **legal assertion made by software**.
The owner directed that they specify the statutory period.

## Decision

1. **`RETENTION_STATUTORY_DAYS` has no default.** If unset, retention jobs **delete nothing** and the
   admin dashboard shows a persistent warning. An unset value is a safe, visible, non-destructive
   state — not an error and not an implicit "keep forever, silently".
2. **Audit and custody records are never deleted in v1.** They are archived after
   `AUDIT_ARCHIVE_AFTER_DAYS=730`, and archiving preserves verifiability of the hash chain.
3. **Hard deletion of an evidence original requires all of**: the `admin` role, a written
   justification, a **second approver**, a permanent audit record, and `reference_count = 0` on the
   underlying `physical_objects` row. No single person can destroy an original.
4. Derivatives are purged at `DERIVATIVE_RETENTION_DAYS=90`. Derivatives are reproducible from
   originals, so this is a storage decision, not an evidential one.
5. Superseded analysis results are **kept** with `is_current=false`; they are never deleted, because
   the fact that an earlier analysis said something different is itself evidentially relevant.
6. `legal_hold` overrides every retention and purge path. A held item is not deleted, purged or
   derivative-cleaned regardless of age.
7. Soft-delete is the default; hard delete is the exception described in requirement 3.

## Alternatives considered

| Option | Verdict |
|---|---|
| Default to a plausible period (e.g. 7 years) | **Rejected** — a software default becomes a legal position, and jurisdictions vary. |
| Refuse to start without a retention period | Rejected — would block deployment of an otherwise functional system and encourage setting an arbitrary number just to boot. |
| Delete audit records after the retention period | Rejected — the audit chain is the platform's integrity record; destroying it destroys provability. |
| Allow a single admin to hard-delete | Rejected — no separation of duties on the most destructive action available. |

## Rationale

The failure mode of no default is *nothing gets deleted and someone notices the warning*. The failure
mode of a wrong default is *evidence is destroyed on a schedule nobody chose*. Those are not
comparable risks.

## Consequences

* Storage grows until an operator sets a period. `BACKUP_RECOVERY.md` documents capacity planning for
  this state.
* The dashboard warning must be unmissable, or requirement 1 becomes silent indefinite retention.
* Two-person hard deletion needs an approval workflow and its UI, which is real work in M19.

## Licensing implications

None.

## Security implications

Two-person authorisation on destructive operations, permanent audit of every deletion, and legal-hold
supremacy together mean an insider cannot quietly destroy evidence — and if they somehow do, the audit
chain shows the gap.

## Reversal strategy

Setting `RETENTION_STATUTORY_DAYS` activates the jobs; no code change. Changing the two-person rule
would require a new ADR because it weakens a deliberate control.

## Verification

* Unit test: with `RETENTION_STATUTORY_DAYS` unset, the retention job deletes **zero** rows and emits
  a warning; `retention_configured` is false and `/api/v1/status` reports it.
* Unit test: setting a value clears the warning and enables the job.
* Test: hard deletion without a second approver is refused.
* Test: hard deletion with `reference_count > 0` is refused.
* Test: a `legal_hold` item survives retention, derivative purge and soft-delete cleanup.
* Test: audit and custody rows are never deleted by any job, only archived.
