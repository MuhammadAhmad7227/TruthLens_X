# ADR-0014 — ClamAV is available but disabled by default

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-014 |
| **Related** | [ADR-0001](./ADR-0001-permissive-default-dependency-set.md) · [ADR-0012](./ADR-0012-data-residency-no-egress-by-default.md) |

## Context
TruthLens X ingests hostile files by design, so malware scanning is plausible. But ClamAV is
**GPL-2.0**, adds ~1 GB of image and a signature database requiring updates, and its detection value
for the media types we ingest (JPEG/MP4/PDF/WAV) is modest compared to our own structural validation.

## Decision
1. A `clamav` service is defined in the compose stack but **not started** in the default profile.
2. `ENABLE_AV_SCAN=false` by default. When enabled, scanning happens in the ingest worker via the
   ClamAV socket protocol (INSTREAM) — a separate process, never a linked library.
3. An infected or errored upload goes to `quarantine/`, is flagged in `physical_objects.av_scan_status`,
   and is never analysed or served.
4. Definition updates require outbound HTTPS and are gated separately by `ENABLE_AV_UPDATES`
   (ADR-0012 §6).
5. AV scanning is an **additional** control, never a replacement for magic-byte type validation, size
   limits, archive guards, or worker isolation.

## Alternatives considered
| Option | Verdict |
|---|---|
| Enable by default | **Rejected** — GPL component on by default contradicts ADR-0001; cost and latency for modest benefit on media types |
| Remove entirely | Rejected — some deployments (those ingesting documents from untrusted sources) genuinely want it |

## Rationale
Keep the capability, keep the default clean, let the operator decide with the trade-offs visible.

## Consequences
**Positive:** smaller default footprint; no GPL component active by default; quarantine path exists
regardless (it is also used for decode failures and integrity problems).
**Negative / accepted costs:** no malware screening by default; enabling adds a stateful service and
an egress requirement for definitions.

## Licensing implications
ClamAV GPL-2.0 is subprocess/socket-isolated and off by default, so it never enters the default
dependency set or SBOM. Definition files have their own terms and are recorded when enabled.

## Security implications
When enabled it adds a real control against weaponised documents. When disabled, the compensating
controls are: magic-byte validation, size/count/uncompressed-size limits on archives, worker
isolation (non-root, read-only root FS, `cap_drop`, seccomp, resource limits), and an `isolated`
network with no egress. Threat T-07 is mitigated primarily by isolation, not by AV.

## Reversal strategy
A flag plus starting the compose service. No code change — the scanner adapter already exists behind
the interface and is tested in both states with a stub daemon.

## Verification
- Test with a stub AV daemon returning `INFECTED`: the item is quarantined, never analysed, and the
  status is recorded.
- Test with `ENABLE_AV_SCAN=false`: no connection is attempted to the ClamAV host.
- Compose test: the default profile does not start the `clamav` service.
