# ADR-0015 — Offline gazetteer supported; disabled by default pending licence verification (L-7)

| | |
|---|---|
| **Status** | Accepted with an open legal item — 2026-11-10 |
| **Decision ID** | D-015 |
| **Refinement flagged** | ⚠️ My original proposal was "offline GeoNames subset enabled by default". The licence could **not** be verified from an allowed host, so the default is changed to **disabled** until L-7 is answered. Shipping data whose licence we have not verified would contradict the licence-audit conditions. |
| **Related** | [ADR-0012](./ADR-0012-data-residency-no-egress-by-default.md) · [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §6 (DS-6), §10 (L-7) |

## Context
Reverse geocoding turns coordinates into place names, which materially helps location intelligence.
An online provider would send coordinates (personal data) to a third party — prohibited by default
under ADR-0012. An offline gazetteer avoids egress but requires bundling or fetching a dataset whose
licence we must verify.

## Decision
1. Location intelligence works **without** any gazetteer: coordinates, uncertainty radii, clustering,
   movement tracks and implausibility checks are all computed locally from the evidence itself.
2. An offline gazetteer loader is implemented behind `GAZEETTEER_ENABLED`, **defaulting to `false`**
   until L-7 confirms the dataset licence and the exact attribution text.
3. `GAZEETTEER_PATH` points into the operator-provisioned `/models`-style read-only mount; the data is
   fetched by the operator script, never at runtime.
4. When enabled, the attribution notice and dataset licence file are bundled and surfaced in
   `THIRD_PARTY_LICENSES.md`.
5. **Online geocoding stays disabled by default** (`ENABLE_ONLINE_GEOCODING=false`) and, if enabled,
   is rate-limited, logged, SSRF-guarded and treated as an egress event under ADR-0012.

## Alternatives considered
| Option | Verdict |
|---|---|
| Enable the offline gazetteer by default | **Rejected** — licence unverified (L-7) |
| Online geocoding by default | **Rejected** — coordinates are personal data; ADR-0012 |
| No gazetteer support at all | Rejected — the capability is genuinely useful once the licence is cleared |

## Rationale
Do not ship data whose licence we have not verified. The capability is fully functional without place
names, so nothing is lost by defaulting off.

## Consequences
**Positive:** no unverified dataset in the default deployment; no egress; location intelligence still
delivers coordinates, clustering, tracks and plausibility indicators.
**Negative / accepted costs:** no human-readable place names until the operator enables a verified
gazetteer; investigators must interpret coordinates themselves.

## Licensing implications
**Open item L-7**: confirm the GeoNames licence (commonly reported as CC BY 4.0) and the exact
attribution text; record the dataset version, SHA-256 and licence in `models.lock.json` (datasets are
audited as artifacts). If CC BY 4.0 applies, attribution is mandatory and must appear in the UI and
in generated reports that use place names.

## Security implications
Coordinates are personal data: access is case-scoped and audited, and `display_value` supports
coordinate truncation for lower-privilege roles (GEO-07). No egress by default.

## Reversal strategy
Operator downloads a verified gazetteer, sets `GAZEETTEER_ENABLED=true`, and the loader populates
`locations.gazetteer_match`. Reversal is a flag plus a data fetch; no schema change.

## Verification
- Test: with `GAZEETTEER_ENABLED=false`, no gazetteer file is read and `gazetteer_match` is null.
- Test: with a tiny synthetic gazetteer fixture, a coordinate resolves to the expected locality and
  the attribution string is present in the result.
- Test: enabling online geocoding without `ENABLE_EXTERNAL_ENRICHMENT` is refused at startup.
