# ADR-0019 — Deterministic reports with manifest hashing; cryptographic signing optional and off

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-019 |
| **Related** | [ADR-0020](ADR-0020-retention-without-a-default-statutory-period.md), [MASTER_PRD (module 18)](../MASTER_PRD.md), [THIRD_PARTY_LICENSE_AUDIT (finding L-11)](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

Exported PDF reports may be tendered as work product. What must be provable is **which evidence and
which analysis results a report was built from**, and that the document has not changed since the
examiner attested to it. Full cryptographic signing with a trusted certificate is a procurement and
key-custody commitment the owner has not made.

## Decision

1. Every report carries a **manifest**: the source entity ids and the content hashes of everything it
   was built from, plus a `manifest_hash` over that manifest and the **SHA-256 of the generated PDF**.
2. Reports are generated **deterministically** — same inputs produce byte-identical output — so the
   hash is reproducible and independently verifiable.
3. **Fonts are embedded**, and must be both embeddable and redistributable: DejaVu (BSD-style) or
   Liberation/Noto (SIL OFL). Recorded as finding **L-11**.
4. Reports are **immutable with version lineage**: a correction produces a new version referencing its
   predecessor; prior versions are never overwritten or deleted.
5. An **examiner attestation is always present** — the human who approved the report, when, and under
   which capability (`approve_report`).
6. **Cryptographic signing (PKCS#7 / RFC 3161 timestamping) is optional and off by default.** RFC 3161
   timestamping is v2 backlog.
7. The report builder **cannot read assistant tables.** AI conversation content is architecturally
   excluded from reports so that unverified assistant output cannot become work product.
8. Honesty rules AR-1..AR-8 apply to report text, enforced by a string-lint test banning phrases such
   as "confirmed fake", "proven authentic", "is a deepfake", "guilty", "100% accurate" and
   "guaranteed detection".

## Alternatives considered

| Option | Verdict |
|---|---|
| Mandatory PKCS#7 signing with a purchased certificate | Rejected for v1 — key custody, renewal and CA procurement are an organisational commitment, and an expired or self-signed certificate can undermine rather than support credibility. |
| ReportLab as the PDF generator | Rejected on licence grounds: the audit found ReportLab's packaging acceptable but the **default** PDF stack is pikepdf-based (ADR-0002); generation uses a deterministic writer chosen for reproducibility, with fonts embedded. |
| Allow assistant summaries in reports | Rejected — assistant output is explicitly "investigative indicator, not confirmed fact" and must not be laundered into an attested document. |
| Mutable reports (edit in place) | Rejected — destroys the ability to show what an examiner actually approved. |

## Rationale

A reproducible hash over a complete manifest gives most of the evidential value of signing without the
key-management burden, and it can be verified by anyone with the document and the manifest. Making
signing optional means an owner who later obtains a certificate can add it without changing the report
format.

## Consequences

* Determinism constrains generation: no timestamps-of-generation inside the byte stream except in
  declared manifest fields, no randomised layout, fixed font subsetting.
* Verifying a report requires the manifest, which is stored alongside it and included in the export.
* Report generation is slower than a naive writer because of the determinism constraints.

## Licensing implications

Fonts are the live item (**L-11**): only embeddable, redistributable families are used, and their
notices are reproduced in `THIRD_PARTY_LICENSES.md`. SIL OFL and DejaVu's BSD-style licence both
permit embedding and redistribution.

## Security implications

`manifest_hash` plus the PDF digest make post-hoc alteration detectable. Immutable version lineage
means a superseded report cannot be quietly replaced. Excluding assistant tables removes a path by
which unverified AI output could reach an attested document.

## Reversal strategy

Adding signing is additive: sign the already-deterministic bytes and store the signature alongside.
No format change, no regeneration of existing reports.

## Verification

* Test: generating the same report twice yields **byte-identical** PDFs and an identical SHA-256.
* Test: altering one byte of a generated PDF invalidates its recorded digest.
* Test: the report builder raises if asked to include assistant content (no code path exists to read
  those tables).
* Test: a corrected report creates a new version row referencing its predecessor; the predecessor is
  unchanged.
* String-lint test: banned overclaiming phrases fail CI in report templates and UI copy.
* Test: embedded fonts are present in the output and are from the approved families.
