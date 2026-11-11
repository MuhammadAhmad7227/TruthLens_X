# ADR-0013 — ALPR ships jurisdiction examples only; external registry lookup is hard-disabled

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-013 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [ADR-0012](ADR-0012-data-residency-no-default-egress.md), [ADR-0023](ADR-0023-weight-free-deepfake-indicators.md) |

## Context

Automatic licence-plate recognition produces candidate identifications that may be acted upon against
real people. Two distinct risks apply: **format correctness** (a plate format must match the
jurisdiction that issued it) and **identity resolution** (matching a plate to a registered owner).
The owner directed that format data be supplied as *examples only* for their review, and that no
vehicle-registry integration exist.

## Decision

1. Plate format definitions ship as **`is_example=true`** rows only. They demonstrate the schema and
   are **not** represented as authoritative for any jurisdiction. An operator must review and replace
   them; the UI labels example formats as unverified.
2. **`ALPR_JURISDICTION` has no default value.** Without an explicit operator setting, no format is
   selected and no plate is coerced into a jurisdiction.
3. A plate that matches no configured format is recorded as **`unresolved_format`** and is **never
   coerced** into the nearest match.
4. Output is **top-N per-character candidates with confidence**, not a single asserted string. The
   transcription is an investigative indicator requiring human verification.
5. **`ALPR_ALLOW_REGISTRY_LOOKUP` is hard-disabled: startup aborts if it is set to `true` in any
   environment, including development.** No flag value activates it.
6. **The ALPR module contains no HTTP client.** There is no code path capable of an outbound lookup,
   so requirement 5 is architectural rather than merely configured.
7. Entity rows use hedged types: `vehicle_plate_candidate`, `person_candidate` — never `vehicle` or
   `person` as an asserted fact.
8. **No third-party ALPR weights are shipped or downloaded.** Detection uses operator-supplied
   weights under ADR-0001.

## Alternatives considered

| Option | Verdict |
|---|---|
| Ship a comprehensive global plate-format database | Rejected — accuracy cannot be assured, stale formats produce confident wrong answers, and third-party dataset licences are unverified. |
| Registry lookup behind a disabled flag | Rejected — the capability should not exist in code; a disabled flag is one config error away from an identity check on a real person. |
| Emit a single best-guess plate string | Rejected — overstates certainty; per-character candidates let a human see where ambiguity actually lies. |
| Default `ALPR_JURISDICTION` to the deployment country | Rejected — infers jurisdiction from geography, which is exactly the wrong assumption for cross-border material. |

## Rationale

A confident wrong plate is worse than an admitted ambiguous one: it looks like evidence. Refusing to
coerce, refusing to resolve identity, and refusing to guess jurisdiction all push the judgement to the
human, which is where it belongs.

## Consequences

* Out of the box, ALPR produces candidates against no format until an operator configures one. That
  friction is intended.
* Report and UI text must say "candidate" and "requires verification"; AR-1..AR-8 honesty rules and
  the banned-phrase string-lint test apply.
* Example formats must be visibly marked, or they will be mistaken for real ones.

## Licensing implications

No third-party plate dataset is bundled, so no dataset licence is implicated. Operator-supplied format
data is the operator's own responsibility and is recorded with its provenance.

## Security implications

Eliminating the lookup capability removes a privacy-harm class entirely — no query can be made,
logged or leaked. It also removes an egress path that ADR-0012 would otherwise have to police.

## Reversal strategy

Registry integration is explicitly **v2 backlog** and would require a new ADR, a jurisdictional legal
review, its own audit event type and an authorisation capability. Requirement 5 cannot be satisfied by
a config change alone; the code must change too, and that change must be reviewed.

## Verification

* Unit test: `ALPR_ALLOW_REGISTRY_LOOKUP=true` aborts startup **in every environment** (parametrised
  over all four).
* Static test: no HTTP client import exists anywhere under the ALPR module (AST scan, CI-blocking).
* Unit test: an unmatched plate yields `unresolved_format` and is not coerced.
* Unit test: with `ALPR_JURISDICTION` unset, no format is applied.
* UI/report string-lint test: banned phrases such as "confirmed" and "100% accurate" never appear.
