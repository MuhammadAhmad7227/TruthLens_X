# ADR-0013 — ALPR ships no authoritative plate formats and no registry integration

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-013 |
| **Related** | [MASTER_PRD.md](../MASTER_PRD.md) Module 13 · [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §5 (W-13) |

## Context
Plate formats vary by jurisdiction and change over time. Asserting an authoritative format table for
any country — including Pakistan — without a verified official source would be fabrication, and a
wrong validator silently coerces or discards real readings.

## Decision
1. `plate_formats` ships **only** example rows marked `is_example=true`, clearly labelled as
   unverified illustrations.
2. A deployment must configure its own formats before ALPR results are treated as meaningful;
   `ALPR_JURISDICTION` has **no default**.
3. A plate that matches no configured format is reported as `unresolved_format` — **never** silently
   coerced to the nearest match, and never discarded.
4. Recognition returns **top-N candidates with per-character confidence**, not a single string.
5. **No integration with any vehicle-ownership or law-enforcement registry in v1**, and
   `ALPR_ALLOW_REGISTRY_LOOKUP=false` is a hard-disabled flag: no code path performs a lookup. Any
   future integration requires explicit legal authorisation, a new ADR, and its own audit trail.
6. No third-party ALPR-specific model weights are shipped (most are research-licensed); ALPR uses the
   general detector plus EasyOCR plus our own format validators.

## Alternatives considered
| Option | Verdict |
|---|---|
| Ship a "best guess" format table for common jurisdictions | **Rejected** — unverifiable, and a wrong validator corrupts readings silently |
| Ship a pretrained ALPR model | **Rejected** — licence status of published ALPR weights is typically research-only (L-5 pattern) |
| Registry lookup for convenience | **Rejected** — a legal/privacy boundary, not a feature |

## Rationale
A forensic tool must not manufacture authority it does not have. Reporting `unresolved_format` with
candidates is honest and actionable; a confident wrong string is neither.

## Consequences
**Positive:** no fabricated authority; the operator's configuration is explicit and versioned; no
privacy exposure from registry access.
**Negative / accepted costs:** ALPR is not useful until the operator configures formats — an
onboarding step that must be documented prominently; unmatched plates need human review.

## Licensing implications
Avoids restricted ALPR weights. EasyOCR (Apache-2.0 code) weights still require **L-3** verification
before use.

## Security implications
Plates are personal data. Access is case-scoped and audited; `display_value` can be masked for
lower-privilege roles; masked preview derivatives exist for shared contexts (ALPR-07). No registry
access means no query-pattern leakage about investigation targets.

## Reversal strategy
Formats are data — adding verified formats is a migration or an admin action, no code change. Registry
integration would be a new ADR plus a new capability, authorisation scope and audit trail; it is not a
flag flip.

## Verification
- Test: an unreadable plate yields `unresolved_format`, not a guessed string.
- Test: a readable plate yields top-N candidates with per-character confidences summing sanely.
- Test: `is_example=true` rows are never selected when `ALPR_JURISDICTION` is unset — the pipeline
  reports "no formats configured".
- Test: no HTTP client exists in the ALPR module (static assertion).
