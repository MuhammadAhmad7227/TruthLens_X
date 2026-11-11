# ADR-0014 — ClamAV present but disabled by default; signature updates gated behind scanning

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-014 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [ADR-0012](ADR-0012-data-residency-no-default-egress.md) |

## Context

Uploaded evidence may contain malware, and analysts will open derivative artifacts. ClamAV is
GPL-2.0 and requires outbound signature updates, which conflicts with the no-default-egress posture.
The owner directed it be **included but disabled**.

## Decision

1. The ClamAV service definition and client integration **exist** in the repository, so enabling it
   is a configuration change rather than a development task.
2. **`ENABLE_AV_SCAN=false`** by default. No scan is performed unless the operator enables it.
3. **`ENABLE_AV_UPDATES=true` requires `ENABLE_AV_SCAN=true`** — startup aborts otherwise. Updating
   signatures for a scanner that is not running is pointless egress.
4. Both flags additionally require the master egress switch `ENABLE_EXTERNAL_ENRICHMENT=true`
   (ADR-0012) before any update traffic is possible.
5. When enabled, scanning runs at ingest on the `isolated` network and marks the item `quarantined`
   on a positive result. Quarantine is a **state**, not a deletion: the original is preserved.
6. A scan failure or an unavailable daemon **fails closed** — the item is held, not passed.
   "Could not scan" is never reported as "clean".

## Alternatives considered

| Option | Verdict |
|---|---|
| Omit ClamAV entirely | Rejected — the owner wants it available; re-adding it later is more work than gating it now. |
| Enable by default | Rejected — signature updates are egress, contradicting ADR-0012's default-closed posture. |
| Bundle signatures in the image | Rejected — stale signatures create false confidence; worse than an honest "not scanned". |

## Rationale

GPL-2.0 as a separate daemon process imposes no obligation on platform code, so availability is free.
Defaulting off preserves the residency guarantee; the dependency between the two flags removes a
nonsensical and egress-producing configuration.

## Consequences

* Out of the box, evidence is **not** malware-scanned, and the UI must state that plainly rather than
  implying a clean result.
* Enabling requires three coordinated settings plus a firewall rule — deliberately non-accidental.
* A quarantine workflow and its tests must exist even though the feature ships disabled.

## Licensing implications

ClamAV is **GPL-2.0**. It is deployed as a separate container and contacted over its TCP protocol, so
the platform is not a derivative work and no GPL obligation reaches our code. Documented in
`THIRD_PARTY_LICENSE_AUDIT.md`; activation is recorded as a copyleft flag warning at startup.

## Security implications

Off by default is a real residual risk and is recorded as such in the threat model: a malicious file
may be opened by an analyst without prior scanning. Compensating controls: isolated workers, no egress
from the media network, read-only original mounts, and derivative artifacts generated only inside
sandboxed workers.

## Reversal strategy

Set `ENABLE_AV_SCAN=true`, `ENABLE_AV_UPDATES=true`, `ENABLE_EXTERNAL_ENRICHMENT=true`, open the
update egress rule, and start the `clamav` service. All reversible without code change.

## Verification

* Unit test: `ENABLE_AV_UPDATES=true` with `ENABLE_AV_SCAN=false` aborts startup.
* Unit test: `ENABLE_AV_SCAN=true` with the master egress switch off aborts startup.
* Unit test (mocked daemon): a positive result sets `quarantined` and preserves the original.
* Unit test: daemon unavailable ⇒ item held, status is "not scanned", **never** "clean".
