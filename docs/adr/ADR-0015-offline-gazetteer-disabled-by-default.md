# ADR-0015 — Offline gazetteer subset, disabled by default pending licence verification

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-015 |
| **Refinement flagged ⚠️** | Yes — the proposal was "offline subset, enabled"; the owner's ratification makes it **disabled by default** pending licence finding **L-7**. |
| **Related** | [ADR-0012](ADR-0012-data-residency-no-default-egress.md), [THIRD_PARTY_LICENSE_AUDIT (finding L-7)](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

Location intelligence (M8/M16) benefits from reverse-geocoding coordinates to place names. Two
problems were identified. First, **online geocoding is egress** and would send GPS coordinates —
explicitly listed as never-transmittable data — to a third party. Second, the licence of the leading
free gazetteer dataset could **not be verified** from the hosts available during the audit; it is
recorded as open finding **L-7**. A wrong-repo probe returned ODbL for an unrelated dataset, and
**CC BY 4.0 must not be asserted as fact** for the gazetteer.

## Decision

1. **`GAZETTEER_ENABLED=false` by default.** No place-name resolution occurs until an operator
   enables it with a dataset they have licensed appropriately.
2. When enabled, resolution is **offline only**, against a locally provisioned subset.
   `ENABLE_ONLINE_GEOCODING` is a separate flag and additionally requires the master egress switch
   (ADR-0012); GPS coordinates are on the never-transmittable list regardless.
3. **`GAZETTEER_ENABLED=true` requires a non-empty `GAZETTEER_ATTRIBUTION`.** Startup aborts without
   it, because every plausible candidate licence for geographic data (CC BY, ODbL, GADM terms)
   requires attribution, and the exact terms are unverified.
4. The operator-supplied attribution string is displayed wherever resolved place names appear,
   including in exported PDF reports.
5. Unresolved coordinates are reported as **coordinates only**, with no place name and no inferred
   administrative area. Coordinates are never reverse-engineered into a plausible-sounding location.
6. The dataset is provisioned by the operator, recorded in `models.lock.json`-style provenance with
   its licence and verification date, and is **never fetched by the application**.

## Alternatives considered

| Option | Verdict |
|---|---|
| Ship a bundled gazetteer | Rejected — we cannot verify the licence (L-7), and bundling an unverified dataset is exactly what ADR-0001 forbids. |
| Online geocoding by default | Rejected — transmits GPS coordinates off-host, breaching ADR-0012 and the never-transmittable list. |
| Enable offline resolution by default with an empty dataset | Rejected — a no-op feature presented as available is a placeholder, which the owner forbids. |
| Assume CC BY 4.0 | Rejected explicitly — the owner instructed that unverified licences be treated conservatively. |

## Rationale

An unverified dataset licence is a legal exposure, and reverse-geocoding is a convenience, not a
forensic requirement. Defaulting off with a mandatory attribution field means the feature can only be
turned on by someone who has consciously dealt with both.

## Consequences

* Location intelligence in v1 shows coordinates and operator-supplied labels, not automatic place
  names. Reports must not imply a location was identified when it was not.
* An operator enabling this must source, licence and attribute a dataset themselves.
* L-7 stays open until counsel resolves it; the conservative path is the shipping path meanwhile.

## Licensing implications

Directly driven by an unresolved licence finding. The mandatory-attribution rule is a **deliberate
over-approximation**: it satisfies the attribution requirement of every plausible licence, so the
configuration cannot be compliant-by-accident or non-compliant-by-omission.

## Security implications

Offline-only resolution keeps GPS coordinates on-host. Because coordinates are investigative
sensitive data (they can identify a person's movements), they are also excluded from any external AI
transmission category (ADR-0021).

## Reversal strategy

Enabling is: source a licensed dataset, set `GAZETTEER_ENABLED=true`, set `GAZETTEER_ATTRIBUTION`,
provision the subset offline. No code or schema change.

## Verification

* Unit test: `GAZETTEER_ENABLED=true` with empty attribution aborts startup.
* Unit test: `ENABLE_ONLINE_GEOCODING=true` with the master egress switch off aborts startup.
* Unit test: default configuration reports coordinates only, with no place-name field populated.
* Report test: the attribution string appears whenever a resolved name is present.
