# TruthLens X — Third-Party Licence Audit

| | |
|---|---|
| **Document ID** | TLX-DOC-010 |
| **Version** | 1.0.0 |
| **Status** | ACTIVE — governs dependency selection. Required by decision **D-001/D-002/D-003/D-008** and **ADR-0001…0003, ADR-0008**. |
| **Verification date** | **2026-11-10** |
| **Verification method** | Live queries to the PyPI JSON API, the npm registry, and the GitHub REST API. Commands reproduced in [Appendix A](#appendix-a--verification-commands). |
| **Owner** | Lead Software Architect |
| **Review cadence** | Re-verified on every dependency-add PR; full re-audit each release |

---

## 0. Read this first

> **This document is an engineering audit, not a legal opinion.** It records what the upstream
> projects *say* about their own licensing, where that was verified, on what date, and what remains
> uncertain. Requirement: **"Do not claim legal compliance without a proper licence audit."**
> Accordingly, nothing here asserts compliance. Items marked ⚖️ require review by qualified legal
> counsel before distribution or commercial hosting.

### 0.1 The rule that generated this document

> *"Check model weights, datasets, pretrained checkpoints, and downloaded binaries separately. A
> permissive Python package does not automatically make its model weights permissively licensed."*
> — approval condition on D-001, 2026-11-10

This is not a hypothetical concern for this project. It is a **live, verified finding**:

- `torchvision` is BSD-3-Clause. Its own documentation states: *"The pre-trained models provided in
  this library may have their own licenses or terms and conditions derived from the dataset used for
  training. It is your responsibility to determine whether you have permission to use the models for
  your use case."* → the **code** is permissive; the **weights** are not necessarily.
- `ByteTrack` code is MIT. Its released checkpoints are trained/evaluated on **MOT17/MOT20**, whose
  terms are non-commercial. → permissive algorithm, restricted artifacts.
- `openai-whisper` is MIT **and** its README explicitly states *"Whisper's code **and model weights**
  are released under the MIT License."* → permissive code **and** permissive weights, verified.

Therefore this audit is split into **two independent registers**: [§1–§4 software](#1-software-register)
and [§5–§7 artifacts](#5-artifact-register-weights--datasets--binaries--bundled-data). A component is
only cleared when **both** registers clear it.

### 0.2 Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Verified permissive; cleared for the default dependency set |
| 🟡 | Permissive code but **artifact-level terms unresolved** (weights/dataset); cleared only with conditions |
| 📋 | File-level copyleft (MPL-2.0 / LGPL): usable; modifications to *that file/library* must be shared |
| ⚠️ | **Copyleft (AGPL/GPL)** — excluded from the default set; only behind an `ENABLE_*` flag, never on by default |
| ⚖️ | Requires legal review before distribution or commercial hosting |
| ❓ | Not verifiable from an allowed host; must be verified at fetch time and recorded in `models.lock.json` |
| 🚫 | Prohibited in v1 |

### 0.3 Default-set policy (from the approved decision)

1. **Ultralytics YOLO and PyMuPDF are NOT in the default dependency set.**
2. Detection uses `torchvision` or another **individually verified** permissively licensed CV implementation.
3. PDF processing uses **`pikepdf`** initially.
4. **ExifTool integration is optional** (`ENABLE_EXIFTOOL`, and see §4.1 for its dual-licence nuance).
5. AGPL-dependent integrations sit behind explicit `ENABLE_*` flags.
6. **No AGPL component is ever activated by default.**
7. No dependency is silently substituted — every substitution is recorded with trade-offs (§8).
8. No `LICENSE` file is added; the repository remains **unlicensed** pending a deliberate decision.

---

## 1. Software register

### 1.1 Backend — `backend/` (Python 3.11)

| Package | Version verified | Licence (verified) | Purpose | Distribution | Status |
|---|---|---|---|---|---|
| `fastapi` | 0.162.3 | MIT | HTTP framework, OpenAPI generation | PyPI wheel | ✅ |
| `pydantic` | 2.14.3 | MIT | Schema validation — the honesty-policy enforcement point | PyPI wheel | ✅ |
| `pydantic-settings` | 2.16.2 | MIT | Typed env configuration, fail-closed startup | PyPI wheel | ✅ |
| `sqlalchemy` | 2.1.8 | MIT | ORM (typed 2.0 style) | PyPI wheel | ✅ |
| `alembic` | 1.20.1 | MIT | Schema migrations | PyPI wheel | ✅ |
| `psycopg[binary]` | 3.x | LGPL-3.0 **with** explicit permission to link | Postgres driver | PyPI wheel | 📋 ⚖️ see §1.5 |
| `celery` | 5.7.0 | BSD-3-Clause | Background task orchestration | PyPI wheel | ✅ |
| `redis` | 8.1.0 | MIT | Broker/cache client | PyPI wheel | ✅ |
| `pyjwt` | 2.15.1 | MIT | JWT issue/verify (EdDSA) | PyPI wheel | ✅ |
| `argon2-cffi` | 25.1.0 | MIT | argon2id password hashing | PyPI wheel | ✅ |
| `bcrypt` | 4.x | Apache-2.0 | Legacy hash verification only | PyPI wheel | ✅ |
| `python-multipart` | 0.0.33 | Apache-2.0 | Streaming multipart upload parsing | PyPI wheel | ✅ |
| `structlog` | 24.x | MIT/Apache-2.0 | Structured JSON logging | PyPI wheel | ✅ |
| `reportlab` | 5.1.0 | BSD | PDF investigation reports | PyPI wheel | ✅ |
| `python-magic` | 0.4.27 | MIT (wrapper) | Magic-byte type detection — **requires `libmagic` binary, see §4.3** | PyPI wheel | ✅ + 📋 |
| `networkx` | 3.7 | BSD-3-Clause | Graph analytics (paths, neighbourhoods) | PyPI wheel | ✅ |
| `imagehash` | 4.3.2 | BSD-2-Clause | Perceptual hashing (pHash/dHash/aHash/wHash) | PyPI wheel | ✅ |
| `pillow` | 13.0.0 | MIT-CMU | Image decode/encode for working copies | PyPI wheel | ✅ |
| `passlib` | 1.7.4 | BSD | **REJECTED — not used.** Unmaintained (last release 2020), incompatible with `bcrypt ≥ 4.1` | — | 🚫 |
| `pytest`, `pytest-asyncio`, `pytest-cov` | 9.2.0 / — | MIT | Test harness | PyPI wheel (dev extra) | ✅ |
| `hypothesis` | 6.x | MPL-2.0 | Property-based tests (path containment, canonicalisation) | PyPI wheel (dev extra) | 📋 dev-only |
| `ruff`, `mypy`, `bandit`, `pip-audit` | current | MIT / MIT / Apache-2.0 / Apache-2.0 | Lint, types, security scan | PyPI wheel (dev extra) | ✅ |
| `httpx` | 0.28.1 | BSD-3 | HTTP client; used by the gated-egress test harness | PyPI wheel (dev extra) | ✅ |
| `httpx2` | 2.16.0 | BSD-3 | **Required, not optional.** Starlette ≥ 1.x `TestClient` rejects plain `httpx` with a
  deprecation warning, and the backend's `filterwarnings = ["error"]` turns that into a test
  failure. Same lineage and licence as `httpx`. Verified against PyPI metadata 2026-11-10 | PyPI wheel (dev extra) | ✅ |
| `types-Pygments` | 2.19.0.20250809 | MIT | Type stubs for mypy | PyPI wheel (dev extra) | ✅ |

**Not in the default set:** `ultralytics` (⚠️ AGPL-3.0), `PyMuPDF` (⚠️ AGPL-3.0/commercial),
`pyexiftool` (see §4.1), `poppler-utils` python bindings (see §4.4).

### 1.2 `ai_services/` — forensic engines

| Package | Version verified | Licence | Purpose | Status |
|---|---|---|---|---|
| `opencv-python-headless` | 5.0.0.93 | Apache-2.0 | CV primitives: decode, DCT, filtering, feature matching | ✅ (headless avoids GUI/X11 deps) |
| `numpy` / `scipy` | 2.x / 1.x | BSD-3 / BSD-3 | Numerics, spectral analysis | ✅ |
| `torch` | 2.15.0 | `Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND ISC AND MIT AND Zlib` (per PyPI `license_expression`) | DL runtime | ✅ all components permissive |
| `torchvision` | 0.29.2 | **BSD-3-Clause (code)** | Detection backbones (RetinaNet/FCOS/SSD) | 🟡 **code cleared; pretrained WEIGHTS are a separate question — see §5.1** |
| `pikepdf` | 10.18.0 | **MPL-2.0** | PDF structural forensics via QPDF: revisions, XRef, object streams | 📋 **approved default for PDF (D-002)** |
| `qpdf` (bundled in pikepdf wheels) | — | Apache-2.0 | PDF transformation library pikepdf wraps | ✅ |
| `pdfminer.six` | 20260107 | MIT | PDF text/layout extraction | ✅ |
| `pypdf` | 7.0.1 | BSD-3-Clause | PDF metadata (`Info`), encryption flags | ✅ |
| `pdfplumber` | 0.11.10 | MIT | Table/word extraction with coordinates | ✅ |
| `easyocr` | 1.7.2 | Apache-2.0 (code) | OCR for documents and ALPR stage 2 | 🟡 code cleared; **model weights hosted separately — §5.3** |
| `faster-whisper` | 1.2.1 | MIT | Default ASR engine (CTranslate2) | ✅ **weights explicitly MIT — §5.2** |
| `openai-whisper` | 20250625 | MIT | Optional alternate ASR engine | ✅ **README states code *and* weights are MIT — §5.2** |
| `ctranslate2` | 4.x | MIT | Inference runtime for faster-whisper | ✅ |
| `librosa` / `soundfile` | 0.10.x / 0.12.x | ISC / BSD-3 | Audio loading and spectral features | ✅ |
| `numpy`-based ELA/DCT/copy-move engines | in-repo | (repo licence, pending D-008) | Classical image forensics — **our own code, no third-party weights** | ✅ |
| ByteTrack association logic | **ported into `ai_services/engines/detection/tracker.py`** | MIT (derived from `FoundationVision/ByteTrack`) | Multi-object tracking association | ✅ code · 🚫 **we do NOT ship their checkpoints — §5.4** |
| `ultralytics` | 8.4.208 | **AGPL-3.0** | Detection + `.track()` wrapper | ⚠️ **excluded from default; `ENABLE_ULTRALYTICS=false`** |
| `PyMuPDF` | 2.1 | **AGPL-3.0 or Artifex commercial** | Fast PDF text/rendering | ⚠️ **excluded from default; `ENABLE_AGPL_PYMuPDF=false`** |
| `Megvii-BaseDetection/YOLOX` | — | **Apache-2.0** (verified from repo LICENSE) | Candidate permissive detector if torchvision proves insufficient | ✅ candidate — see §8.2 |
| `open-mmlab/mmdetection` | — | **Apache-2.0** (verified) | Candidate permissive detector zoo | ✅ candidate — weights still need §5 review |
| `openai/CLIP` | — | MIT (code) | Candidate image/text embeddings for similarity search | 🟡 weights = MIT per repo; **verify at fetch — §5.5** |

### 1.3 Frontend — `frontend/` (npm, verified 2026-11-10)

| Package | Version | Licence | Purpose | Status |
|---|---|---|---|---|
| `next` | 16.4.6 | MIT | App Router framework | ✅ |
| `react` / `react-dom` | 19.3.1 | MIT | UI runtime | ✅ |
| `typescript` | 7.0.2 | Apache-2.0 | Language | ✅ |
| `tailwindcss` | 4.3.5 | MIT | Styling | ✅ |
| `@tanstack/react-query` | 5.107.1 | MIT | Server-state cache | ✅ |
| `zustand` | 5.1.0 | MIT | Client state | ✅ |
| `cytoscape` | 3.34.4 | MIT | Evidence relationship graph rendering | ✅ |
| `wavesurfer.js` | 8.0.5 | BSD-3-Clause | Audio waveform/spectrogram viewer | ✅ |
| `playwright` | 1.65.0 | Apache-2.0 | E2E tests (dev) | ✅ |
| `vitest` | 5.1.0 | MIT | Unit/component tests (dev) | ✅ |
| Radix UI primitives | current | MIT | Accessible component primitives (**vendored into `components/ui`**, not installed as a dependency, so the code is auditable in-tree) | ✅ |
| Map tiles / tile provider | — | — | **🚫 No third-party tile provider in v1.** Self-hosted tiles only (GEO-03) | 🚫 |

Frontend total: **zero copyleft dependencies.** Enforced by the CI licence gate (§9).

### 1.4 Infrastructure images

| Image | Licence | Note | Status |
|---|---|---|---|
| `python:3.11-slim` | PSF + Debian components | Debian base carries mixed permissive licences; standard for container use | ✅ |
| `node:22-alpine` | MIT + Alpine components | | ✅ |
| `nginx:1.27-alpine` | BSD-2 | Digest-pinned | ✅ |
| `pgvector/pgvector:pg16` | PostgreSQL Licence (permissive) + Postgres (PostgreSQL Licence) | Verified `NOASSERTION` on GitHub = the PostgreSQL Licence text | ✅ |
| `redis:7-alpine` | MIT (redis-py) / **Redis 7 = RSALv2/SSPLv1 for Redis 8+; Redis 7.2 and earlier are BSD-3** | ⚖️ **We pin Redis 7.2.x (BSD-3).** Do not upgrade to Redis 8 without re-auditing — Redis 8 reverted to a tri-license including AGPLv3, which would be ⚠️. See §8.4. | ✅ with a pin |
| `nvidia/cuda:12.x-runtime` | NVIDIA EULA (proprietary, redistributable runtime) | ⚖️ NVIDIA driver licence is proprietary; permitted for internal deployment, but **redistribution of images containing CUDA runtime is subject to the NVIDIA EULA** | ⚖️ |
| `clamav/clamav` | GPL-2.0 | Optional, disabled by default, runs as a **separate process** over a socket | ⚠️ flag-gated |

> **Redis is the single most important infrastructure pin in this document.** Redis 7.2 and earlier
> are BSD-3-Clause. Redis 8 re-licensed under RSALv2/SSPLv1 and later added AGPLv3 as an option.
> We pin **`redis:7.2-alpine`** and the CI licence gate fails on any `redis:8*` reference.

### 1.5 Note on `psycopg` (LGPL with linking permission)

`psycopg 3` is LGPL-3.0 **with an explicit exception permitting linking from non-free programs** (the
same model as libpq itself, which is PostgreSQL-Licensed). Practically this is permissive for our use.
It is recorded as 📋/⚖️ rather than ✅ because it is the one non-permissive SPDX identifier in the
default backend set, and honesty requires flagging it. Alternative if counsel objects: `asyncpg`
(Apache-2.0).

---

## 2. Copyleft components — register and containment

Every component below is **excluded from the default dependency set** and reachable only through an
explicit, audited `ENABLE_*` flag that defaults to `false`. Requirement: *"Never activate an AGPL
component by default."*

| ID | Component | Licence | Flag | Default | Verified licence text | Containment |
|---|---|---|---|---|---|---|
| C-1 | `ultralytics` (YOLO) | **AGPL-3.0** | `ENABLE_ULTRALYTICS` | `false` | LICENSE file = "GNU AFFERO GENERAL PUBLIC LICENSE Version 3" | Adapter module only; `import-linter` forbids imports elsewhere |
| C-2 | `PyMuPDF` | **AGPL-3.0** / Artifex commercial | `ENABLE_AGPL_PYMuPDF` | `false` | PyPI: "Dual Licensed - GNU AFFERO GPL 3.0 or Artifex Commercial License" | Adapter module only |
| C-3 | ExifTool binary | **GPL-3.0 file, dual Artistic/GPL grant** — see §4.1 | `ENABLE_EXIFTOOL` | `true` but **optional & removable**; see §4.1 | LICENSE = GPLv3 text; README = Perl dual licence | **Separate process**, JSON over a pipe, no linking |
| C-4 | `poppler-utils` (`pdftoppm`, `pdftotext`) | **GPL-2.0+** | `ENABLE_POPPLER` | `false` | Debian package metadata | Separate process |
| C-5 | ClamAV | **GPL-2.0** | `ENABLE_AV_SCAN` | `false` | Debian/upstream | Separate container, socket protocol |
| C-6 | `ffmpeg`/`ffprobe` | **LGPL-2.1+** by default; **GPL** if built with `--enable-gpl` (x264/x265) | always required | LGPL build only | Debian `ffmpeg` package licence | Separate process; **we do not enable GPL codecs** — no x264/x265 encoding is required (we never re-encode evidence) |
| C-7 | Redis 8.x | RSALv2/SSPLv1 (+ AGPLv3 option) | n/a | **pinned to 7.2 (BSD-3)** | — | Version pin + CI gate |

### 2.1 Containment mechanisms (all four, per SYSTEM_ARCHITECTURE §8)

1. **Process isolation** — C-3, C-4, C-5, C-6 are invoked as subprocesses/sockets with argument
   lists (never `shell=True`) and structured output. No linking, no shared address space.
2. **Flag-gated imports** — C-1, C-2 imports live behind `if settings.ENABLE_*:` in a single adapter
   module each. `import-linter` fails the build if any other module imports them.
3. **Permissive default implementation of the same interface** — every capability has a cleared
   implementation (torchvision/YOLOX for detection, pikepdf+pdfminer for PDF, pure-Python EXIF/XMP
   for metadata) so flipping a flag swaps implementations without touching services or tests.
4. **CI licence gate** — `tools/license-check/` (§9) fails on any unexpected copyleft entry.

> ⚖️ **This is engineering containment, not legal advice.** Whether process isolation is sufficient
> for AGPL §13 in a hosted-service context, and whether ExifTool's Artistic election is available to
> us, are legal questions. See §10.

---

## 3. Substitution register (requirement: never silently replace a dependency)

The brief named specific technologies. Where the approved licensing decision required a different
package, the substitution and its trade-offs are recorded here — **no capability is dropped**.

| Capability named in brief | Package named | Default substitute | Licence of substitute | Technical trade-off | Flag to use the named package |
|---|---|---|---|---|---|
| YOLO object detection | `ultralytics` | `torchvision` detection models (RetinaNet/FCOS/SSD) | BSD-3 code · 🟡 weights (§5.1) | Less convenient API; no bundled tracking; mAP-per-effort is lower than YOLOv8/11 for the same tuning time; **weights need a licence decision** | `ENABLE_ULTRALYTICS=true` (AGPL) |
| Object detection (fallback) | — | `YOLOX` (Apache-2.0) | Apache-2.0 | Extra repo dependency; checkpoints still need §5 review | n/a |
| Multi-object tracking | ByteTrack | **Ported MIT association logic** in `ai_services/engines/detection/tracker.py` | MIT | We maintain the port ourselves (~300 lines); we must NOT import `ultralytics.track()` (AGPL) and must NOT ship ByteTrack's MOT-trained checkpoints (§5.4) | n/a |
| PDF parsing | `PyMuPDF` | **`pikepdf` (MPL-2.0) + `pdfminer.six` (MIT) + `pypdf` (BSD-3)** | MPL/MIT/BSD | **Better** for forensic revision/XRef analysis (QPDF exposes incremental saves precisely). **Worse** for rasterising pages to images — needs `pdftoppm` (C-4) or the AGPL flag. Slower text extraction on very large PDFs. | `ENABLE_AGPL_PYMuPDF=true` |
| Metadata extraction | ExifTool | ExifTool **kept** (optional) + pure-Python fallback (Pillow/pikepdf/ffprobe + a small EXIF/XMP reader) | see §4.1 | Fallback covers common tags only; **materially worse** on obscure formats. This is why ExifTool stays enabled by default *as an option* rather than being removed. | `ENABLE_EXIFTOOL=false` disables it |
| ASR | Whisper | `faster-whisper` (MIT) default, `openai-whisper` (MIT) optional | MIT both | faster-whisper is quicker on CPU; openai-whisper matches the original reference implementation more closely | both available |
| OCR | EasyOCR | `easyocr` (Apache-2.0) | Apache-2.0 | No substitution needed | n/a |
| Report PDF | ReportLab | `reportlab` (BSD) | BSD | No substitution needed | n/a |
| Vector search | pgvector | `pgvector` (PostgreSQL Licence) | permissive | No substitution needed | n/a |

**Requirement satisfied:** nothing was silently replaced. Each row names the trade-off, and each
copyleft original remains available behind a flag.

---

## 4. System binaries (downloaded/installed separately from Python packages)

### 4.1 ExifTool — dual-licence nuance ⚖️ *(important, corrected during this audit)*

Two upstream sources disagree, and both were retrieved on 2026-11-10:

| Source | Content |
|---|---|
| `api.github.com/repos/exiftool/exiftool` licence detection | **GPL-3.0** |
| `LICENSE` file in the repository | Full text of the **GNU General Public License v3** |
| `README` → "COPYRIGHT AND LICENSE" | *"Copyright 2003-2026, Phil Harvey. This is free software; you can redistribute it and/or modify it under the same terms as Perl itself (**either the Perl Artistic License or GPL**)."* |

**Interpretation:** ExifTool appears to be **dual-licensed** in the standard Perl manner — the
licensee may elect **either** the Artistic License **or** the GPL. The repository ships the GPL-3
text (which is what GitHub's detector reads), while the author's own README grants the Artistic
alternative. The Perl Artistic License 1.0 is a weak-copyleft/permissive-style licence far closer to
our needs than GPL-3.

**Why this matters:** if the Artistic election is available to us, the GPL-3 exposure documented in
D-003 may be **substantially reduced or eliminated** for ExifTool use.

**Action required (⚖️ legal review, item L-1):** confirm the Artistic election is available and
record the elected licence in this audit before distribution. Until confirmed, we treat ExifTool
conservatively as GPL-3 and keep it (a) optional, (b) subprocess-isolated, (c) removable via
`ENABLE_EXIFTOOL=false` with a tested pure-Python fallback.

**Distribution requirements if ExifTool is bundled in an image:**
- Ship the ExifTool licence text and copyright notice inside the image (`/usr/share/doc/exiftool/`).
- State in `THIRD_PARTY_LICENSES.md` (generated, §9) that ExifTool is a separate program invoked as a
  subprocess, and name the elected licence.
- Pin the ExifTool version and record its SHA-256 in `models.lock.json` (binaries are audited as
  artifacts, §7).
- Prefer installing from the **distribution package** (`apt install libimage-exiftool-perl`) over
  vendoring the tarball, so the distro's licence metadata and updates apply.

**Deployment considerations:** ExifTool parses hostile input by design. It runs in the media worker
container only, on a read-only working copy, with `--` argument termination, a hard timeout, resource
limits, no shell, and no network egress.

### 4.2 ffmpeg / ffprobe
LGPL-2.1+ in standard distribution builds; becomes GPL if built with `--enable-gpl` (x264/x265).
**We use the LGPL build and never enable GPL codecs** — TruthLens X never re-encodes evidence
(AP-1), so no GPL encoder is needed. We use `ffprobe` for stream metadata and `ffmpeg` only for
audio-track **extraction** (stream copy, no transcode). Record the installed build's
`--enable-*` flags at image build time (`ffmpeg -buildconf` output stored in the image SBOM).

### 4.3 libmagic (`file`)
BSD-2-Clause-ish (the `file` utility). `python-magic` is an MIT wrapper requiring the shared library.
Install `libmagic1` from the distro. ✅

### 4.4 poppler-utils
GPL-2.0+. Only needed to rasterise PDF pages to images. `ENABLE_POPPLER=false` by default; when
disabled, page rasterisation is unavailable and OCR of scanned pages falls back to extracting
embedded images with pikepdf (which covers most scanned-PDF cases). ⚠️ flag-gated.

### 4.5 NVIDIA driver / CUDA runtime ⚖️
Proprietary NVIDIA EULA, redistributable under its terms. Required only for the GPU worker. Record
the exact driver and CUDA runtime versions in the deployment manifest; **do not redistribute** images
containing CUDA outside the EULA's terms. Internal on-prem deployment (our chosen target, D-005) is
the least problematic case.

---

## 5. Artifact register: weights, checkpoints, models

> **Audited separately from packages, per requirement #9.**

| ID | Artifact | Upstream code licence | **Weight licence (verified statement)** | Training data | Our use | Status |
|---|---|---|---|---|---|---|
| W-1 | Whisper ASR checkpoints (`tiny`…`large-v3`) | MIT | **MIT — explicitly stated**: *"Whisper's code and model weights are released under the MIT License"* (openai/whisper README, verified 2026-11-10) | 680k h of web audio (not released) | Default ASR | ✅ **cleared — code AND weights** |
| W-2 | faster-whisper / CTranslate2 conversions | MIT | MIT conversions of W-1 | as W-1 | Default ASR runtime | ✅ inherits W-1 |
| W-3 | `torchvision` **classification** weights (ResNet, etc.) | BSD-3 | **Not separately licensed.** torchvision docs: pretrained models *"may have their own licenses or terms and conditions derived from the dataset used for training… your responsibility to determine whether you have permission"* | **ImageNet (ILSVRC)** — Terms of Access are **non-commercial research** | **🚫 NOT USED.** No classification weights in TruthLens X | 🚫 excluded |
| W-4 | `torchvision` **detection** weights (RetinaNet/FCOS/SSD) | BSD-3 | Same warning as W-3 | **COCO** — annotations CC BY 4.0; images are Flickr-sourced with mixed CC licences (some NC) | Candidate default detector | 🟡 ⚖️ **L-2: legal review required before shipping these weights.** Mitigation in §5.6 |
| W-5 | `YOLOX` checkpoints | Apache-2.0 | Apache-2.0 (repo states weights under the same licence) | COCO | Fallback detector | 🟡 ⚖️ same COCO question as W-4 (L-2) |
| W-6 | `mmdetection` checkpoints | Apache-2.0 | Per-model; **many are COCO-pretrained** | COCO | Candidate | 🟡 ⚖️ L-2 |
| W-7 | EasyOCR detection + recognition models | Apache-2.0 (code) | ❓ **Hosted separately** (JaidedAI release assets). Licence not stated in the README retrieved. | Mixed scene-text corpora | OCR / ALPR stage 2 | ❓ **must be verified at fetch time**; recorded in `models.lock.json` with `licence`, `licence_source_url`, `licence_verified_at`. **Do not fetch until verified** (L-3) |
| W-8 | `openai/CLIP` weights | MIT | MIT per repo; trained on **WIT-400M** (not released) | WIT-400M | Candidate image/text embeddings for similarity search | 🟡 verify at fetch (L-4) |
| W-9 | ByteTrack released checkpoints | MIT (code) | Code MIT; **checkpoints trained/evaluated on MOT17/MOT20** | **MOT Challenge = CC BY-NC-SA 3.0 (non-commercial)** | **🚫 NOT SHIPPED.** We port the *association algorithm* and feed it detections from our own detector | 🚫 excluded |
| W-10 | Face detection / landmark models (candidate: `insightface`, `facenet-pytorch`, MediaPipe) | varies | ⚠️ **`insightface` models are explicitly non-commercial** (MIT code, non-commercial model licence); MediaPipe is Apache-2.0 with model terms; `facenet-pytorch` MIT code, VGGFace2 dataset is **research-only** | VGGFace2 etc. | Face region detection for `person_candidate` clustering | ❓ ⚖️ **prefer a permissive option (MediaPipe Apache-2.0 / `retinaface` MIT / torchvision SSD-faces).** **L-5: no face-recognition model may be added without a written licence check**, and face *identification* remains out of scope regardless (PRD §1.2) |
| W-11 | Deepfake/synthetic-media detection checkpoints (any third-party) | varies | ⚠️ Frequently **research-only / non-commercial** (e.g. many published detectors ship weights restricted to academic use) | FaceForensics++ (**non-commercial research**), Celeb-DF, DFDC (**CC BY-NC 4.0**) | Deepfake indicators (M14) | 🚫 **v1 policy: ship NO third-party deepfake weights.** M14 implements **classical signal-processing indicators** (DCT/FFT spectral analysis, boundary/blending statistics, temporal flicker) that require **no trained weights at all**. Any learned detector added later requires L-5 review and its own ADR |
| W-12 | Speaker diarisation models (`pyannote.audio`) | MIT (code) | ⚠️ **pyannote pretrained models require accepting conditions and are gated**; several are research-oriented | DIHARD/VoxConverse etc. | Diarisation (AUD-03, `Should`) | ❓ ⚖️ L-6 — if it cannot be cleared, diarisation ships with a simpler energy/embedding clustering implementation of our own, or is deferred |
| W-13 | ALPR-specific detection/OCR weights | varies | ⚠️ Many published ALPR models are research-only | OpenALPR-era data, CRPD (**research**) | ALPR (M13) | 🟡 **Plan: general detector (W-4/W-5) + EasyOCR (W-7) + our own format validators. No third-party ALPR-specific weights in v1.** |

### 5.1 Why W-3 and W-9 are hard exclusions

These are the two cases where a permissive package would have silently dragged in restricted
artifacts:

- **W-3 (ImageNet classification weights):** we have no need for image classification, so we simply
  never load them. Recorded so a future contributor does not "helpfully" add one.
- **W-9 (ByteTrack MOT checkpoints):** the *algorithm* is what we want, and it is MIT. The
  *checkpoints* are MOT-trained and MOT is non-commercial. We port the algorithm and supply our own
  detections. This is the single clearest illustration of the requirement that artifacts be audited
  separately from code.

### 5.2 The M14 consequence (this changed the roadmap)

Because published deepfake detectors are overwhelmingly research-licensed and their evaluation
datasets are non-commercial (W-11), **milestone M14 is specified to use classical, weight-free
signal-processing indicators** rather than a pretrained deepfake classifier. This is *also* the more
honest design: a classical indicator's behaviour can be explained and its limits stated precisely,
whereas a black-box classifier trained on FaceForensics++ generalises poorly to real casework and
cannot support a defensible limitations statement. Recorded in **ADR-0023** and PRD **DF-01…DF-09**.

### 5.3 `models.lock.json` — the artifact contract

Every artifact in the store must be described by a lock entry **before** it may be fetched or loaded:

```jsonc
{
  "schema_version": "1.0",
  "artifacts": [
    {
      "id": "whisper-large-v3",
      "family": "whisper", "version": "large-v3", "task": "asr",
      "source_url": "https://…",
      "sha256": "<64 hex>",
      "size_bytes": 3095042018,
      "code_licence": "MIT",
      "weights_licence": "MIT",
      "weights_licence_source": "https://github.com/openai/whisper#license",
      "weights_licence_verified_at": "2026-11-10",
      "weights_licence_verified_by": "architect",
      "training_datasets": [{"name": "OpenAI web audio corpus", "licence": "not released", "note": "weights granted MIT by author"}],
      "commercial_use_cleared": true,
      "legal_review_id": null,
      "allow_fetch": true
    }
  ]
}
```

Enforcement (M13/M19): the loader refuses any artifact with `allow_fetch != true`,
`weights_licence` empty, or a SHA-256 mismatch — **fail closed, never fall back** (AR-7). The CI
licence gate parses this file and fails if any entry has `commercial_use_cleared: false` while the
deployment profile is commercial.

### 5.4 Rule: no artifact enters the tree without a lock entry

`models/` is git-ignored. A new weight file requires: a lock entry with both licence fields and a
verification date, a legal-review ID if ⚖️, an ADR if it changes capability, and an entry in this
audit. This is a **pull-request checklist item**, not a convention.

---

## 6. Dataset register

| ID | Dataset | Licence / terms | Used for | In v1? | Status |
|---|---|---|---|---|---|
| DS-1 | **COCO** | Annotations CC BY 4.0; images Flickr-sourced, mixed CC (incl. NC) | Pretrained detection weights (W-4/5/6) | Indirectly, via weights | ⚖️ L-2 |
| DS-2 | **ImageNet / ILSVRC** | Non-commercial research Terms of Access | torchvision classification weights | **No** | 🚫 excluded |
| DS-3 | **MOT17 / MOT20** | CC BY-NC-SA 3.0 | ByteTrack checkpoints | **No** | 🚫 excluded |
| DS-4 | **FaceForensics++ / Celeb-DF / DFDC** | Non-commercial research / CC BY-NC | Deepfake detector training | **No** (see §5.2) | 🚫 excluded |
| DS-5 | **VGGFace2** | Research-only, non-commercial | Face-recognition weights | **No** (face *identification* is out of scope) | 🚫 excluded |
| DS-6 | **GeoNames** gazetteer | CC BY 4.0 (attribution required) — ❓ not verifiable from an allowed host | Offline reverse geocoding (GEO-05) | Optional, flag-gated | ❓ **L-7: verify licence and attribution requirement at download; if bundled, include the CC BY attribution notice and the data's own licence file** |
| DS-7 | **Our internal evaluation set** | Ours; synthetic where possible | Measuring our own TPR/FPR (AR-6) | Yes | ✅ must contain **no** third-party-copyrighted media and **no** real personal data (TESTING_STRATEGY §12) |
| DS-8 | JPEG **quantisation-table reference signatures** | Facts derived from public encoder behaviour; some tables are documented in vendor SDK docs | DQT fingerprinting (IMG-03) | Yes | 🟡 record provenance per row in `dqt_signatures` (`source`, `source_url`, `retrieved_at`). Tables are short numeric arrays — treat as factual data, but document provenance |
| DS-9 | Synthetic test fixtures (`tools/fixtures/`) | Ours, generated deterministically | All CI testing | Yes | ✅ no third-party media, no real personal data |

---

## 7. Bundled binaries & data register

| Item | Source | Licence | Verification |
|---|---|---|---|
| ExifTool binary | distro package `libimage-exiftool-perl` (preferred) | see §4.1 ⚖️ | pin version; record package SHA-256 in the image SBOM |
| ffmpeg / ffprobe | distro package | LGPL-2.1+ (§4.2) | record `-buildconf` in the SBOM; assert no `--enable-gpl` |
| libmagic | distro package | BSD-2-style | pin |
| poppler-utils | distro package | GPL-2.0+ | **only when `ENABLE_POPPLER=true`** |
| ClamAV + virus definitions | distro/upstream | GPL-2.0 (code); definitions under their own terms | **only when `ENABLE_AV_SCAN=true`**; definitions are updated data — record their licence too |
| Report fonts | bundled in `backend/app/reporting/fonts` | ⚖️ **must be an embeddable, redistributable licence** (e.g. DejaVu — BSD-style, Liberation — SIL OFL, Noto — OFL). **No proprietary fonts.** | record per-font licence in `fonts/LICENCES.md` (M18) |
| GeoNames subset | DS-6 | ❓ L-7 | record at download |

---

## 8. Notable decisions taken during this audit

### 8.1 Detection strategy (feeds ADR-0001)
Default: **`torchvision` detection models**, with the weight-licence question (W-4/L-2) resolved by
one of: (a) counsel clears COCO-pretrained weights for our use; (b) we **train/fine-tune nothing** and
ship detection as an *operator-supplied* model (the deployment provides weights it is licensed for);
or (c) use YOLOX (W-5, Apache-2.0, same COCO question). **Recommended: (b) as the shipped default** —
TruthLens X ships *no* detection weights; the operator installs and registers them via the model
registry, accepting the weight licence at that point. This removes the entire COCO question from our
distribution while keeping full functionality. Recorded as **ADR-0001**, consequence C-1b.

### 8.2 Fallback detector
If torchvision detection proves inadequate in M13 evaluation, the fallback is **YOLOX (Apache-2.0)**,
not Ultralytics. The switch is an adapter change; the engine interface is identical.

### 8.3 PDF strategy (feeds ADR-0002)
`pikepdf` (MPL-2.0) is the primary structural engine. MPL is file-level copyleft: our obligations
extend only to modifications of MPL-covered files, and we modify none. Page rasterisation is the one
gap → `ENABLE_POPPLER` (GPL subprocess) or `ENABLE_AGPL_PYMuPDF`, both off by default, with
embedded-image extraction as the cleared fallback for scanned-PDF OCR.

### 8.4 Redis pin (feeds ADR-0022)
`redis:7.2-alpine` (BSD-3), pinned. The CI licence gate fails on `redis:8*` and `redis:7.3*`.
Upgrading Redis is a **licence event**, not a routine patch bump, and requires an ADR amendment plus a
re-audit of this document. See **ADR-0022** for the full decision, the Valkey fallback path, and the
verification tests.

---

## 9. Enforcement — how this document stays true

| Gate | Where | Behaviour |
|---|---|---|
| `tools/license-check/` | CI, every PR | Parses the resolved dependency graph (Python + npm), compares each SPDX id against an allowlist (permissive + MPL + LGPL-with-exception), and **fails** on any unexpected AGPL/GPL/SSPL/RSAL entry in the default set |
| Flag audit | CI | Asserts every `ENABLE_*` copyleft flag defaults to `false` in `.env.example` and `Settings` |
| `import-linter` | CI | Fails if any module outside the designated adapters imports a copyleft package |
| `models.lock.json` validation | CI + runtime loader | Fails on a missing `weights_licence`, missing verification date, `allow_fetch=false`, or SHA-256 mismatch |
| SBOM | Release CI | CycloneDX SBOM published as a build artifact for every image; includes system binaries |
| `THIRD_PARTY_LICENSES.md` | Generated at build | Full licence texts for everything in the image, including subprocess-invoked binaries |
| Redis version pin | CI | Fails on any `redis:8*` image reference |
| Image digest pinning | CI | No `latest` tags; base images pinned by digest |
| Secret scanner | CI | `gitleaks` — blocks committed credentials |

---

## 10. Open items requiring legal review ⚖️

| ID | Question | Blocks | Owner |
|---|---|---|---|
| **L-1** | Is the **Perl Artistic License election** available to us for ExifTool, given the README grant versus the GPL-3 LICENSE file? Which licence do we elect and record? | Distribution of images containing ExifTool (M8) | Counsel |
| **L-2** | Are **COCO-pretrained detection weights** (torchvision/YOLOX/mmdetection) usable in a commercial/internal forensic deployment? Does §8.1 option (b) — operator-supplied weights — fully resolve it? | Shipping detection weights (M13) | Counsel |
| **L-3** | What licence applies to **EasyOCR model weights** (distributed separately from the Apache-2.0 code)? | ALPR/document OCR (M10/M13) | Counsel + upstream inquiry |
| **L-4** | Confirm **CLIP weights** are MIT and usable, given WIT-400M was never released. | Similarity search embeddings (M15) | Counsel |
| **L-5** | Establish the standing rule for **face-related models** (many are non-commercial). Which permissive face *detector* (not recognizer) may we use? | Face region detection (M9) | Counsel + architect |
| **L-6** | Are **pyannote.audio** pretrained diarisation models usable? If not, diarisation is deferred or reimplemented. | Audio diarisation (M11, `Should`) | Counsel |
| **L-7** | Confirm **GeoNames** licence (CC BY 4.0?) and the exact attribution text required if bundled. | Offline reverse geocoding (M8, optional) | Counsel |
| **L-8** | Is **process isolation sufficient** to avoid AGPL §13 obligations for the flag-gated components (C-1, C-2) if the platform is hosted for third parties? | Any decision to enable the flags | Counsel |
| **L-9** | Does bundling the **NVIDIA CUDA runtime** in a distributed image comply with the NVIDIA EULA for our intended deployment? | GPU worker image distribution (M13) | Counsel |
| **L-10** | Which **project licence** will TruthLens X itself use? (D-008: deliberately unlicensed for now; no `LICENSE` file added.) | Any external distribution | Owner |
| **L-11** | Which **fonts** may be embedded in generated reports (must be redistributable + embeddable)? | Report generation (M18) | Counsel |

**No item above may be closed by an engineer alone.** Until L-1…L-11 are answered, the platform
defaults to the most conservative configuration: no detection weights shipped, no deepfake weights,
no face-recognition model, no ImageNet weights, no MOT checkpoints, Redis 7.2, ExifTool treated as
GPL-3 and subprocess-isolated, and all copyleft flags off.

---

## 11. Change control

- Adding, removing, or upgrading any dependency requires updating this document **in the same PR**.
- A licence *change* upstream (as with Redis 7→8) is treated as a breaking change requiring an ADR.
- The `Verification date` at the top must be updated whenever a row is re-checked.
- This document is regenerated-in-part by `tools/license-check/` (the package/version/licence
  columns), but the ⚖️ analysis, substitutions register, and artifact register are hand-maintained —
  a tool cannot make a licensing judgement.

---

## Appendix A — verification commands

All commands were run on **2026-11-10** from a network restricted to `pypi.org`, `registry.npmjs.org`
and `api.github.com`. Reproduce with:

```bash
# Python package licence (PyPI metadata)
curl -s https://pypi.org/pypi/ultralytics/json | \
  python3 -c 'import sys,json;i=json.load(sys.stdin)["info"];print(i["version"], i.get("license") or i.get("license_expression"))'

# npm package licence
curl -s https://registry.npmjs.org/next | \
  python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["dist-tags"]["latest"], d.get("license"))'

# GitHub repository licence detection
curl -s -H 'Accept: application/vnd.github+json' \
  https://api.github.com/repos/FoundationVision/ByteTrack | \
  python3 -c 'import sys,json;print(json.load(sys.stdin)["license"]["spdx_id"])'

# Actual licence TEXT (authoritative over detection)
curl -s -H 'Accept: application/vnd.github.raw+json' \
  https://api.github.com/repos/exiftool/exiftool/contents/LICENSE | head -3

# Author's own licence statement (the ExifTool dual-licence discovery)
curl -s -H 'Accept: application/vnd.github.raw+json' \
  https://api.github.com/repos/exiftool/exiftool/contents/README | grep -A5 -i 'copyright and license'

# Upstream warning about weight licensing (the torchvision discovery)
curl -s -H 'Accept: application/vnd.github.raw+json' \
  https://api.github.com/repos/pytorch/vision/contents/docs/source/models.rst | grep -B2 -A6 -i licens

# Whisper weights licence statement
curl -s -H 'Accept: application/vnd.github.raw+json' \
  https://api.github.com/repos/openai/whisper/contents/README.md | grep -A3 -i '## License'
```

**Lesson encoded in these commands:** licence *detection* (SPDX ids, GitHub badges, PyPI classifiers)
is not licence *verification*. Three of the four most consequential findings in this document — the
ExifTool dual licence, the torchvision weights warning, and the Whisper weights grant — were only
visible by reading the upstream text, not the metadata.

---

*End of THIRD_PARTY_LICENSE_AUDIT.md v1.0.0. Re-verify before every release.*
