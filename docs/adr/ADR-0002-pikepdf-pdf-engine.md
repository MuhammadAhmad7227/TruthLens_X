# ADR-0002 — pikepdf (MPL-2.0) is the default PDF engine; PyMuPDF is flag-gated

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-002 |
| **Decided by** | Project owner ("Use pikepdf for PDF processing initially") |
| **Related** | [ADR-0001](./ADR-0001-permissive-default-dependency-set.md) · [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §1.2, §8.3 |

## Context
The brief names PyMuPDF. Verified: `PyMuPDF` 2.1 is **AGPL-3.0 or Artifex commercial**. Document
forensics needs PDF *structural* detail — incremental saves, XRef layout, object streams, per-revision
object diffs (requirement DOC-02) — more than it needs rendering speed.

## Decision
Default PDF stack: **`pikepdf` 10.18.0 (MPL-2.0, wrapping Apache-2.0 QPDF)** for structure, plus
`pdfminer.six` (MIT) and `pdfplumber` (MIT) for text/layout/tables, and `pypdf` (BSD-3) for `Info`
dictionary and encryption flags. `PyMuPDF` is available only behind `ENABLE_AGPL_PYMuPDF=false`.

## Alternatives considered
| Option | Verdict |
|---|---|
| PyMuPDF as primary | **Rejected** — AGPL exposure (ADR-0001) |
| PyMuPDF under an Artifex commercial licence | Rejected for v1 (cost) |
| `pypdf` alone | Rejected — insufficient structural fidelity for revision forensics |
| `pdfminer.six` alone | Rejected — no reliable access to incremental-update structure |

## Rationale
MPL-2.0 is *file-level* copyleft: obligations attach to modifications of MPL-covered files, and we
modify none. QPDF is the industry reference for PDF structure and exposes exactly what DOC-02 needs —
revision enumeration and object-level diffs — which PyMuPDF does not surface as precisely.

## Consequences
**Positive:** cleared licence; superior revision forensics; no AGPL flag needed for the core document
module.
**Negative / accepted costs:** **page rasterisation is the one gap.** pikepdf does not render pages to
images. Options, in order: (a) extract embedded page images with pikepdf and OCR those — covers most
scanned PDFs; (b) `ENABLE_POPPLER=true` (GPL subprocess, `pdftoppm`); (c) `ENABLE_AGPL_PYMuPDF=true`.
Text extraction on very large PDFs is slower than PyMuPDF.

## Licensing implications
pikepdf MPL-2.0 (📋 file-level), QPDF Apache-2.0, pdfminer.six MIT, pdfplumber MIT, pypdf BSD-3,
poppler GPL-2.0+ (flag-gated, subprocess only). No open legal item.

## Security implications
pikepdf/QPDF are memory-safe-ish C++ with a strong fuzzing history and are invoked in the worker
container only. All PDF parsing is treated as hostile input (T-07): worker isolation, resource limits,
no shell, argument lists only, timeouts.

## Reversal strategy
Swap the adapter implementation behind the `DocumentEngine` interface; services, result contract,
API and tests are unaffected. Reversal cost: one adapter module plus golden-file regeneration.

## Verification
- Golden tests on the `multi_revision.pdf` fixture pass with **both** the pikepdf path and the
  PyMuPDF path (flag toggled), proving contract equivalence.
- Test asserts the default install does not import `fitz`.
