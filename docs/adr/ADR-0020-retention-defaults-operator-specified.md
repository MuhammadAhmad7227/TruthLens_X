# ADR-0020 — Retention defaults: never delete audit; statutory period is operator-specified

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-020 |
| **Related** | [DATABASE_DESIGN.md](../DATABASE_DESIGN.md) §12 · [BACKUP_RECOVERY.md](../BACKUP_RECOVERY.md) §4 |

## Context
Retention periods for evidential material are legal requirements that vary by jurisdiction. Guessing a
statutory period would be fabricating a legal obligation — exactly the kind of unsupported claim this
project prohibits elsewhere.

## Decision
1. **`RETENTION_STATUTORY_DAYS` has no default and is intentionally empty.** The operator must set it
   on the advice of their own counsel. Until set, retention jobs **do not delete anything** — the safe
   direction.
2. **Audit and custody logs are never deleted in v1.** They are archived to cold storage after
   `AUDIT_ARCHIVE_AFTER_DAYS` (default 730) and outlive their cases.
3. Originals are retained for the case lifetime plus the operator-specified statutory period, and are
   protected by `legal_hold` (default `true`) which blocks hard deletion.
4. Hard deletion of an original requires `admin`, a written justification, a **second approver**, and
   a permanent audit record. Physical deletion proceeds only when `reference_count = 0`.
5. Derivatives are disposable: purged when `stale` or after `DERIVATIVE_RETENTION_DAYS` (default 90).
6. Superseded analysis results are retained with `is_current=false` — history is never rewritten.
7. Retention job executions are logged with the policy in force, so a deletion can be attributed to a
   specific, approved policy version.

## Alternatives considered
| Option | Verdict |
|---|---|
| Ship a sensible-looking default (e.g. 7 years) | **Rejected** — an unverified legal claim baked into configuration |
| Delete audit logs after N years | **Rejected** — custody continuity is the product's core value |
| Hard delete without a second approver | **Rejected** — single-person irreversible destruction of evidence |

## Rationale
Fail safe: absent a specified obligation, retain. Deletion is a privileged, dual-approved, audited act
rather than a background job with a guessed number.

## Consequences
**Positive:** no fabricated legal obligation; no accidental evidence destruction; retention behaviour
is attributable to an approved policy.
**Negative / accepted costs:** storage grows until the operator configures retention; an unset value
means the platform never auto-purges originals, which must be surfaced in the admin dashboard as an
explicit "retention not configured" warning rather than a silent default.

## Licensing implications
None.

## Security implications
Retention and legal hold are integrity controls, not just storage controls: they prevent both
accidental loss and unilateral destruction. Partitioning plus archival keeps audit query performance
stable as the tables grow (threat R-6).

## Reversal strategy
Retention is policy data. Setting `RETENTION_STATUTORY_DAYS` activates the existing jobs; changing it
later requires an approved policy version and applies only to future executions, never retroactively
without an explicit, audited migration.

## Verification
- Test: with `RETENTION_STATUTORY_DAYS` unset, a retention run deletes nothing and records a warning.
- Test: `legal_hold=true` blocks hard deletion; a second approver is required; both actions are audited.
- Test: a retention execution logs the policy version in force.
- Test: superseded results remain retrievable with `is_current=false`.
