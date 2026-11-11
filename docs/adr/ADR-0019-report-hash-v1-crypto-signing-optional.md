# ADR-0019 — Report integrity by manifest and PDF hash in v1; cryptographic signing optional

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-019 |
| **Related** | [MASTER_PRD.md](../MASTER_PRD.md) Module 19 · [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §7 (fonts), §10 (L-11) |

## Context
A report may be challenged years after generation. What must be provable is (a) exactly which case
data it was built from, and (b) that the PDF has not changed since. Cryptographic signing adds
non-repudiation but requires procuring and managing a signing certificate — an organisational
dependency, not a technical one.

## Decision
1. **v1 guarantees, always on:** a report **manifest** (every source entity id plus its content hash,
   the selected sections and filters), a `manifest_hash`, the generated PDF's SHA-256, immutable
   version lineage, and an examiner attestation block recorded on approval.
2. Deterministic generation: stable ordering, **embedded** fonts, no gratuitous run-to-run diffs, so
   regenerating from an unchanged manifest yields equivalent output.
3. **Cryptographic PDF signing is optional**, off by default (`REPORT_ENABLE_CRYPTO_SIGNING=false`),
   because it requires a certificate the operator must procure and protect.
4. When enabled, the signing key is a server-side secret with the same custody rules as other
   critical secrets — never in git, images, or ordinary env files.
5. Report fonts must be **embeddable and redistributable** (DejaVu BSD-style, Liberation/Noto SIL OFL).
   No proprietary fonts. Font licences are recorded in `fonts/LICENCES.md` (L-11).
6. Unverified findings are visually distinct in the report, and every AI indicator carries its
   limitation text and verification status. The report builder **cannot** read assistant tables
   (AI_ARCHITECTURE §10).

## Alternatives considered
| Option | Verdict |
|---|---|
| Require cryptographic signing in v1 | Rejected — blocks deployment on a procurement dependency |
| Hash only, no manifest | **Rejected** — proves the PDF is unchanged but not *what it was built from*, which is the more important property |
| Timestamping authority (RFC 3161) | Deferred to v2 — a good complement to signing, but an external service dependency (conflicts with ADR-0012 by default) |

## Rationale
The manifest plus content hashes is the property that actually survives challenge: it ties the report
to a reproducible slice of the case. Signing adds non-repudiation of *authorship*, which is valuable
but organisationally gated, so it is optional and additive.

## Consequences
**Positive:** no external dependency for trustworthy reports; reproducibility is a first-class
property; signing can be enabled later without redesign.
**Negative / accepted costs:** without signing, a party could dispute authorship (mitigated by the
attestation block, the audit chain, and optional signing); deterministic output requires embedded
fonts, which increases PDF size slightly.

## Licensing implications
ReportLab is BSD ✅. **Fonts must be verified as embeddable and redistributable (L-11)** — this is the
one licence risk in report generation and is easy to overlook. DejaVu (BSD-style), Liberation and Noto
(SIL OFL) are the proposed set.

## Security implications
Mitigates T-20 (report contents disputed). Report generation is audited; downloads use short-lived
signed URLs with a mandatory purpose; prior versions are never deleted. The signing key, if enabled,
is a critical secret under the same canary tests as other keys.

## Reversal strategy
Enable signing by flag plus certificate provisioning — additive. Adding RFC 3161 timestamping later is
a new egress path requiring an ADR amendment and an ADR-0012 exception.

## Verification
- Test: regenerating from an unchanged manifest produces the same `manifest_hash` and a PDF whose
  differing bytes are limited to the documented signature/timestamp fields.
- Test: tampering with a generated PDF is detected against its stored SHA-256.
- Test: a report containing an unverified deepfake advisory includes the disclaimer and the
  verification status.
- Test: the report builder's data sources exclude `ai_messages` (static assertion).
- Test: no proprietary font file exists under `reporting/fonts` without a licence entry.
