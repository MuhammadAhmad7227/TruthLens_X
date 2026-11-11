# ADR-0012 — Evidence data stays on-premises; all external egress disabled by default

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-012 |
| **Related** | [ADR-0005](./ADR-0005-single-host-docker-compose.md) · [ADR-0007](./ADR-0007-local-first-ai-assistant.md) · [ADR-0015](./ADR-0015-offline-gazetteer-default-disabled.md) · [AI_ARCHITECTURE.md](../AI_ARCHITECTURE.md) |

## Context
Evidence, and data derived from it (faces, plates, GPS, transcripts), is personal and legally
sensitive. Any outbound call is a potential disclosure.

## Decision
1. **All external egress is disabled by default.** The master switch is
   `ENABLE_EXTERNAL_ENRICHMENT=false`, plus per-feature switches that are independently `false`:
   `ENABLE_ONLINE_GEOCODING`, `ENABLE_EXTERNAL_AI`, `ALLOW_MODEL_DOWNLOAD`, `ENABLE_AV_UPDATES`
   (virus-definition updates are a deliberate, separately-approved exception, see below).
2. Media workers run on an `isolated` Docker network with **no outbound route**.
3. Host firewall restricts API-container egress to explicitly configured provider hosts only.
4. Any URL accepted by the platform is admin-configurable only, resolved through an SSRF guard that
   blocks private, link-local, loopback and cloud-metadata ranges.
5. Every enabled egress path is individually logged with the data categories transmitted.
6. **Exception, explicitly approved:** virus-definition updates (`ENABLE_AV_UPDATES`) require outbound
   HTTPS to the distribution mirror. It is disabled by default, is a signature database rather than
   case data, and is logged. It never transmits evidence.
7. Model weights are fetched by an **operator-run script** (`fetch-models.sh`), never by the
   application at runtime (`ALLOW_MODEL_DOWNLOAD=false`), so the app process has no download path.

## Alternatives considered
| Option | Verdict |
|---|---|
| Allow online geocoding and external AI by default for convenience | **Rejected** — silent disclosure of case-derived personal data |
| Fully air-gapped, no egress ever | Rejected as the *only* mode — some deployments legitimately need governed enrichment; it stays available behind flags |

## Rationale
Egress should be a deliberate, audited, reversible decision by an administrator who understands what
is leaving — not a default a developer enabled for convenience.

## Consequences
**Positive:** the default deployment cannot leak case data externally; data-residency questions are
answered by configuration inspection; the SSRF surface is nearly eliminated.
**Negative / accepted costs:** location intelligence is limited to coordinates and an offline
gazetteer (if enabled); the assistant is local-only by default; operators must run the model-fetch
script manually.

## Licensing implications
Supports ADR-0008's optionality: with no external service dependency, the platform's licence choice is
unconstrained by third-party service terms.

## Security implications
Mitigates T-10 (SSRF) and T-16 (assistant exfiltration) at the network layer rather than relying only
on application checks — defence in depth. Residual: an administrator can enable egress; that act is
audited, justified, time-bounded and notified (ADR-0007 §4.2).

## Reversal strategy
Per-feature, by flag, each audited. Reversing does not require code changes because every egress path
already exists behind its flag and is tested in both states.

## Verification
- Startup test: with defaults, no provider client is instantiated.
- Network test: from inside a worker container, an outbound connection attempt fails.
- SSRF test: an admin-configured URL resolving to `169.254.169.254`, `127.0.0.1`, `10.0.0.0/8` or
  `::1` is refused before connecting.
- Audit test: enabling any egress flag writes a `config.changed` record with before/after.
