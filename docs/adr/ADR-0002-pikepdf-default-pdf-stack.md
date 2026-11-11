# ADR-0002 — pikepdf (MPL-2.0) as the default PDF stack; PyMuPDF behind a flag

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-002 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [THIRD_PARTY_LICENSE_AUDIT §4](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

Document forensics needs PDF structure parsing, object-stream inspection, embedded-file extraction
and incremental-update detection. `PyMuPDF` is the most capable option but is **dual licensed
AGPL-3.0 / Artifex commercial**. `pikepdf` (MPL-2.0, a Python binding to QPDF) is file-level
copyleft: obligations attach to modified MPL files, not to the platform.

## Decision

1. Default PDF stack: **`pikepdf`** for structural access, **`pdfminer.six`** for text/layout
   extraction, **`pdfplumber`** for table geometry, **`pypdf`** for metadata and encryption handling.
2. `PyMuPDF` is importable only behind `ENABLE_AGPL_PYMuPDF=true`, which defaults to `false` and is
   **never activated by default**.
3. `poppler-utils` (GPL-2.0+) is available behind `ENABLE_POPPLER=true`, invoked as a subprocess only.
4. The document engine exposes one interface so the backend can be swapped without touching callers.
5. Rendering PDF pages to images for visual comparison is the one capability pikepdf cannot provide;
   that path is disabled unless `ENABLE_POPPLER` or `ENABLE_AGPL_PYMuPDF` is set, and the UI states
   the capability is unavailable rather than silently degrading.

## Alternatives considered

| Option | Verdict |
|---|---|
| PyMuPDF as default | Rejected — AGPL network copyleft (ADR-0001). |
| Commercial Artifex licence | Viable, deferred; out of v1 budget scope. |
| pypdf alone | Rejected — insufficient for object-stream and incremental-update analysis. |

## Rationale

MPL-2.0's file-level scope gives near-AGPL capability for structural work with no obligation on
proprietary platform code. Combining four permissive/weak-copyleft libraries covers the M10
requirement set except rasterisation, which is honestly flagged as gated.

## Consequences

* M10 must implement extraction via pikepdf's object model rather than PyMuPDF's higher-level API —
  more code, more tests.
* Page rasterisation is a gated feature; the UI must say so explicitly (never imply it failed).
* Four libraries instead of one means four CVE feeds to watch.

## Licensing implications

MPL-2.0 requires source availability for modifications to MPL-covered files. We do not modify
pikepdf; if we ever fork it, the fork is published under MPL-2.0. QPDF is Apache-2.0.

## Security implications

PDF parsing is a classic exploit surface. pikepdf delegates to QPDF, which has a strong fuzzing
record. Parsers run in the isolated `analysis.cpu` worker with no network egress, so a malicious PDF
cannot reach the API or exfiltrate.

## Reversal strategy

Flip `ENABLE_AGPL_PYMuPDF=true` after accepting AGPL terms or buying a
commercial licence, then register the alternative engine implementation. No schema change.

## Verification

* Default image contains no `PyMuPDF` / `fitz` import path.
* Unit tests parse a structurally adversarial PDF fixture (nested object streams, incremental
  updates) with pikepdf only.
* A test asserts the rasterisation endpoint returns an honest "capability disabled" error, not a
  fabricated empty result.
