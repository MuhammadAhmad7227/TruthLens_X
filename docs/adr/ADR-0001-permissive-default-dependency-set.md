# ADR-0001 — Permissive-by-default dependency set, copyleft behind explicit flags

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-001 (+ D-002, D-003, D-014, D-017 licence aspects) |
| **Related** | [ADR-0002](ADR-0002-pikepdf-default-pdf-stack.md), [ADR-0003](ADR-0003-exiftool-optional-subprocess.md), [ADR-0022](ADR-0022-redis-7-2-pin.md), [ADR-0023](ADR-0023-weight-free-deepfake-indicators.md), [THIRD_PARTY_LICENSE_AUDIT](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

The platform needs object detection, tracking, OCR, ASR and PDF parsing. The most ergonomic
implementations of several of these are copyleft: `ultralytics` 8.4.208 is **AGPL-3.0** and
`PyMuPDF` is **dual AGPL-3.0 / Artifex commercial**. AGPL §13 extends copyleft to *network* use, so
operating TruthLens X as a service could obligate the owner to publish the entire platform source.
The owner's instruction was: permissive defaults, audited flags, and no silent substitutions.

## Decision

1. The **default install contains no AGPL, SSPL or RSAL component.**
2. Object detection defaults to `torchvision` (BSD-3) with **operator-supplied weights**; the
   platform ships none. `Megvii-BaseDetection/YOLOX` (Apache-2.0) is the documented fallback.
3. PDF parsing defaults to `pikepdf` (MPL-2.0, file-level copyleft) + `pdfminer.six` + `pdfplumber`
   + `pypdf`. See ADR-0002.
4. ByteTrack's association logic is **ported from the MIT reference implementation** into
   `ai_services/engines/detection/tracker.py`; their checkpoints are never shipped (MOT17/MOT20 are
   CC BY-NC-SA 3.0, non-commercial).
5. ASR defaults to `faster-whisper` (MIT); `openai-whisper` selectable — both code **and** weights MIT.
6. Every copyleft or egress-capable integration sits behind an `ENABLE_*` flag defaulting to `false`:
   `ENABLE_ULTRALYTICS`, `ENABLE_AGPL_PYMuPDF`, `ENABLE_POPPLER`, `ENABLE_AV_SCAN`,
   `ENABLE_AV_UPDATES`, `ENABLE_EXTERNAL_ENRICHMENT`, `ENABLE_ONLINE_GEOCODING`,
   `ALLOW_MODEL_DOWNLOAD`, `GAZETTEER_ENABLED`, `ENABLE_EXTERNAL_AI`.
7. `ENABLE_EXIFTOOL=true` is the sole exception (see ADR-0003) — subprocess-isolated and removable.
8. A dependency is **never silently replaced.** Any substitution records its technical and licensing
   trade-offs in `docs/THIRD_PARTY_LICENSE_AUDIT.md` and gets its own ADR.
9. **Model weights, datasets, pretrained checkpoints and downloaded binaries are audited separately
   from their Python packages.** A permissive package does not make its weights permissive.

## Alternatives considered

| Option | Verdict |
|---|---|
| Use Ultralytics YOLO directly | Rejected — AGPL network copyleft would reach the whole service. |
| Buy an Ultralytics Enterprise licence | Rejected for v1 — recurring cost and procurement dependency; remains available via the flag. |
| Ship COCO/ImageNet-pretrained weights for convenience | Rejected — ImageNet weights carry non-commercial research terms; see finding **L-2**. |

## Rationale

Detection ergonomics are recoverable with engineering effort; an AGPL obligation on a forensic
platform is not recoverable after deployment. Flag-gating keeps every option available to an owner
who accepts the terms, while the default build stays clean.

## Consequences

* More adapter work in M13 and slightly lower out-of-the-box mAP than YOLOv8/11.
* `tools/license-check/` becomes a **CI-blocking** gate: the default graph must contain no
  AGPL/SSPL/RSAL, and `redis:8*` / `redis:7.3*` must not appear (ADR-0022).
* An SBOM and `THIRD_PARTY_LICENSES.md` are generated per release.
* `import-linter` boundaries prevent a flagged module from being imported by default-path code.

## Licensing implications

Default graph is permissive or file-level copyleft only (BSD-3, MIT, Apache-2.0, MPL-2.0, LGPL-2.1+
for ffmpeg/poppler-adjacent tooling used as separate processes). Copyleft activation is an explicit,
audited operator act, warned about at startup and recorded in `/api/v1/status`.

## Security implications

Fewer default binaries means a smaller attack surface and a shorter CVE response path. Flagged
components are subprocess-isolated where possible so a compromise does not reach the API process.

## Reversal strategy

Set `ENABLE_ULTRALYTICS=true` (or purchase an Enterprise licence) and add the adapter. Reversible
without schema change; the detector interface is already provider-agnostic.

## Verification

* `tools/license-check/check.py` passes in CI and fails on an injected AGPL dependency (negative test).
* `pip list` of the default image contains no `ultralytics` or `PyMuPDF`.
* Startup logs a warning naming any copyleft flag that is enabled.
