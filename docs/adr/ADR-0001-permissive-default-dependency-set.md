# ADR-0001 — Permissive-by-default dependency set; copyleft behind audited flags

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-001 |
| **Decided by** | Project owner, with 12 attached conditions |
| **Related** | [ADR-0002](./ADR-0002-pikepdf-pdf-engine.md) · [ADR-0003](./ADR-0003-exiftool-optional-subprocess.md) · [ADR-0008](./ADR-0008-repository-remains-unlicensed.md) · [ADR-0022](./ADR-0022-redis-72-version-pin.md) · [ADR-0023](./ADR-0023-weight-free-deepfake-indicators.md) · [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context
The project brief names Ultralytics YOLO, PyMuPDF and ExifTool. Verified on 2026-11-10:
`ultralytics` 8.4.208 is **AGPL-3.0** (LICENSE file = "GNU AFFERO GENERAL PUBLIC LICENSE Version 3");
`PyMuPDF` 2.1 is **"Dual Licensed - GNU AFFERO GPL 3.0 or Artifex Commercial License"**. AGPL §13
extends copyleft to *network* use, so hosting the platform could obligate publishing all of it.

## Decision
1. **Ultralytics YOLO and PyMuPDF are NOT added to the default dependency set.**
2. Detection uses `torchvision` (BSD-3 code) or another **individually verified** permissive CV
   implementation. Fallback candidate: `YOLOX` (Apache-2.0, verified from repo LICENSE).
3. Every AGPL-dependent integration sits behind an explicit `ENABLE_*` flag defaulting to `false`.
4. No AGPL component is ever activated by default.
5. No dependency is silently substituted — substitutions and trade-offs are recorded in
   THIRD_PARTY_LICENSE_AUDIT §3.
6. Model weights, checkpoints, datasets and downloaded binaries are audited **separately** from
   packages (THIRD_PARTY_LICENSE_AUDIT §5–§7).
7. No legal-compliance claim is made without a completed audit; open items L-1…L-11 remain with counsel.

## Alternatives considered
| Option | Verdict |
|---|---|
| Use Ultralytics directly (best DX, built-in tracking) | **Rejected** — AGPL §13 network clause reaches hosted use; would force whole-platform disclosure or a paid Enterprise licence |
| Purchase Ultralytics Enterprise | **Rejected for v1** — recurring commercial cost and a procurement dependency before product validation |
| Open-source the whole project under AGPL-3.0 | Deferred — see ADR-0008; would make this moot but is the owner's call |
| Zero copyleft anywhere, ever | **Rejected** — would force dropping ExifTool, materially degrading metadata forensics (the brief requires it) |

## Rationale
The permissive default keeps the *distribution decision* with the owner rather than letting the
dependency graph make it. Capability is preserved because every copyleft component has a cleared
equivalent behind the same engine interface, and the original remains one flag away.

## Consequences
**Positive:** no AGPL in the default tree; a future permissive licence choice (ADR-0008 option D)
stays available; the CI licence gate can be strict; the SBOM is small and clean.
**Negative / accepted costs:** more adapter code in M13; torchvision detection ergonomics are worse
than YOLO's; we must port the MIT ByteTrack association logic ourselves (~300 lines) rather than call
`ultralytics.track()`; M13 requires a detector evaluation to confirm torchvision is adequate, with
YOLOX as the documented fallback.

## Licensing implications
See THIRD_PARTY_LICENSE_AUDIT §1.2, §2, §3, §5. Outstanding legal items: **L-2** (COCO-pretrained
weight terms), **L-5** (face models), **L-8** (is process isolation sufficient for AGPL §13?),
**L-9** (CUDA runtime redistribution). **Recommended mitigation for L-2, adopted:** TruthLens X ships
**no detection weights**; the operator registers weights they are licensed for via the model registry
(THIRD_PARTY_LICENSE_AUDIT §8.1 option b).

## Security implications
Fewer dependencies = smaller attack surface and SBOM. Flag-gated imports are confined to single
adapter modules and enforced by `import-linter`, which also prevents accidental activation.
Flag changes are audited (`config.changed`).

## Reversal strategy
Reversible at low cost. Enabling a copyleft component is a configuration change plus an ADR amendment
recording the legal basis. Removing our permissive adapters afterwards is a deletion. The engine
interface is identical across implementations, so services, tests and API contracts are unaffected
either way. **Irreversible only if** the platform is publicly hosted while an AGPL flag is on without
counsel clearance — hence the flag-change audit trail.

## Verification
- CI licence gate fails on any AGPL/SSPL/RSAL entry in the resolved default dependency graph.
- Test asserts every `ENABLE_*` copyleft flag defaults to `false` in both `.env.example` and `Settings`.
- Test asserts no module outside the designated adapters imports `ultralytics` or `fitz`.
