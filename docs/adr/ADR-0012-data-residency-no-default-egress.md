# ADR-0012 — On-premises data residency with a single master egress switch

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-012 |
| **Related** | [ADR-0007](ADR-0007-local-default-ai-with-gated-external-providers.md), [ADR-0015](ADR-0015-offline-gazetteer-disabled-by-default.md), [ADR-0021](ADR-0021-external-ai-activation-and-egress-confirmation.md) |

## Context

Case material may be subject to jurisdictional constraints. The owner directed an on-premises
deployment with no default egress, and that **the model-download path be governed by the same master
switch as every other outbound call** so there is exactly one place to reason about data leaving the
host.

## Decision

1. **`ENABLE_EXTERNAL_ENRICHMENT=false`** is the master egress switch. When false, no outbound
   network call of any kind is made by application or worker code.
2. The master switch **governs every per-feature flag**: `ENABLE_ONLINE_GEOCODING` and
   `ALLOW_MODEL_DOWNLOAD` both require it to be true, and startup **aborts** if a feature flag is
   enabled while the master switch is off. There is no per-feature override.
3. Media analysis workers run on the `isolated` Docker network with **no egress route at all**,
   enforced by the network topology and by host nftables — not by application discipline.
4. Model artifacts are provisioned by an operator-run script (`infra/scripts/fetch-models.sh`) on a
   machine with network access, verified against `models.lock.json`, and copied in. `ALLOW_MODEL_DOWNLOAD`
   governs whether the *application* may fetch; it is off by default.
5. No analytics, telemetry, crash reporting or update-check call is made. There is no phone-home.
6. Time synchronisation is the one permitted outbound dependency and is a host-level concern (NTP),
   not an application call.

## Alternatives considered

| Option | Verdict |
|---|---|
| Per-feature egress flags only | Rejected — nine independent switches is nine chances to leak; a master switch makes the default provably closed. |
| Allow model download by default for convenience | Rejected — an unpinned download is both a supply-chain and a licensing risk (weights are audited separately, ADR-0001). |
| Application-level egress allowlist only | Rejected — application discipline is not a control; network topology is. |

## Rationale

A single master switch makes "does this deployment talk to the internet?" answerable with one
configuration read, and the network-level enforcement means the answer stays true even if
application code regresses.

## Consequences

* Everything is provisioned offline: models, gazetteer data, AV signatures, dependency packages.
  `DEPLOYMENT_GUIDE.md` documents the air-gapped install path.
* No automatic updates. `ENABLE_AV_UPDATES` requires `ENABLE_AV_SCAN` **and** the master switch.
* Deployment is more work up front and much more predictable in operation.

## Licensing implications

`ALLOW_MODEL_DOWNLOAD=false` by default is also a licensing control: it prevents an operator from
inadvertently pulling weights whose licence was never audited. The loader refuses any artifact whose
`weights_licence` is empty or whose `allow_fetch` is not `true` (fail closed, never fall back).

## Security implications

The strongest single control in the design: a malicious evidence file processed on the `isolated`
network has no route to exfiltrate through, regardless of what it manages to execute.

## Reversal strategy

Enabling egress is a deliberate operator act: set the master switch, then the specific feature, then
open the nftables rule. Each step is logged and each is independently revertible.

## Verification

* Unit tests: `ENABLE_ONLINE_GEOCODING=true` and `ALLOW_MODEL_DOWNLOAD=true` each abort startup when
  the master switch is false.
* Unit test: `ENABLE_AV_UPDATES=true` without `ENABLE_AV_SCAN=true` aborts startup.
* Network test in CI: a worker container on `isolated` cannot resolve or reach an external host.
* A test asserts the geocoding module contains no HTTP client import when the flag is off.
