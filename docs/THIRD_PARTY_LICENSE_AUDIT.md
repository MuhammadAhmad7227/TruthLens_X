# TruthLens X — Third-Party Licence Audit

| | |
|---|---|
| **Document ID** | TLX-DOC-010 |
| **Version** | 1.0.0 |
| **Last updated** | 2026-11-10 |
| **Status** | Current — governs the default dependency set |
| **Related** | [ADR-0001](adr/ADR-0001-permissive-default-dependency-set.md) · [ADR-0002](adr/ADR-0002-pikepdf-default-pdf-stack.md) · [ADR-0003](adr/ADR-0003-exiftool-optional-subprocess.md) · [ADR-0022](adr/ADR-0022-redis-7-2-pin.md) · [ADR-0023](adr/ADR-0023-weight-free-deepfake-indicators.md) |

> ## ⚠️ This document is not legal advice
>
> It records what was **verified from upstream sources** on 2026-11-10, what could **not** be
> verified, and what the engineering consequences are. It does **not** assert that any deployment of
> TruthLens X is legally compliant. Compliance requires review by qualified counsel against the
> owner's actual jurisdiction, use case and distribution method. The owner's standing instruction —
> *do not claim legal compliance without a proper licence audit* — applies to this document itself.
>
> Every finding below states **how it was verified**, so a reviewer can check the work rather than
> trust it.

---

## 1. Why this document exists

Two of the most convenient libraries for this platform's core features are copyleft in a way that
reaches a hosted service:

* `ultralytics` 8.4.208 — **AGPL-3.0**
* `PyMuPDF` — **dual AGPL-3.0 / Artifex commercial**

AGPL §13 extends copyleft to *network* use. Operating TruthLens X as a service for others could
obligate the owner to publish the entire platform source under AGPL. [ADR-0001](adr/ADR-0001-permissive-default-dependency-set.md)
therefore establishes a permissive-by-default dependency graph with copyleft components behind
explicit, audited flags.

The audit produced three findings that were **not** anticipated and that changed design decisions:

1. **A permissive Python package does not make its weights permissive.** torchvision's own
   documentation disclaims any licence for its pretrained models (§5.1). This drove
   [ADR-0023](adr/ADR-0023-weight-free-deepfake-indicators.md).
2. **Redis 7.2 → 8 is a licence change, not a version bump** (§8.4). This drove
   [ADR-0022](adr/ADR-0022-redis-7-2-pin.md).
3. **ExifTool's licence is genuinely ambiguous**, and the ambiguity may favour us (§3.1). This shaped
   [ADR-0003](adr/ADR-0003-exiftool-optional-subprocess.md).

---

## 2. Method

| Source | Used for | Access |
|---|---|---|
| PyPI JSON API (`pypi.org/pypi/<pkg>/json`) | Version, declared licence, classifiers | Direct |
| npm registry (`registry.npmjs.org`) | Frontend package versions and licences | Direct |
| GitHub REST API (`api.github.com`) | Detected licence, `LICENSE` file contents, README text | Direct |
| Upstream `LICENSE`, `README`, `docs/` **text** | The actual terms — metadata alone is unreliable | Direct |

**Metadata was never treated as sufficient.** GitHub's licence detection and PyPI classifiers are
heuristics; several findings below were only discoverable by reading upstream prose. Where a source
could not be reached from the audit environment, the item is recorded as **unverified** and gates the
affected artifact rather than being assumed favourable.

---

## 3. System and tooling dependencies

### 3.1 ExifTool — finding **L-1**, dual licence, ambiguity disclosed

| | |
|---|---|
| **Package** | ExifTool (Perl distribution, not a PyPI package) |
| **Version audited** | current upstream, 2026-11-10 |
| **Purpose** | Camera, GPS, device and maker-note metadata extraction (M8) |
| **Distribution** | Installed as a binary in the `worker-cpu` image only; invoked as a subprocess |
| **Flag** | `ENABLE_EXIFTOOL=true` (default **on**, but removable — see [ADR-0003](adr/ADR-0003-exiftool-optional-subprocess.md)) |

**What was verified, and the contradiction:**

* The distribution `LICENSE` file contains the **full GPLv3 text**, and GitHub's detector reports
  `GPL-3.0` for the repository.
* The README's *COPYRIGHT AND LICENSE* section states verbatim: *"Copyright 2003-2026, Phil Harvey.
  This is free software; you can redistribute it and/or modify it under the same terms as Perl itself
  (either the Perl Artistic License or GPL)."*

A Perl-style dual licence lets the **recipient elect** the Artistic License, which is materially less
restrictive than GPL and imposes no copyleft on separate programs. **The election may therefore
substantially reduce exposure.** That is a legal judgement this document does not make.

> **Note on a dead end:** there is **no PyPI package named `ExifTool`.** `pypi.org/pypi/ExifTool/json`
> returns no `info` key. The related `pyexiftool` binding is separately licensed (GPLv3+/BSD depending
> on version) and is **not used** — we invoke the binary directly, which avoids the binding entirely.

**Engineering consequences (these hold under either licence reading):**

1. Invoked strictly as an **external subprocess** with an argument vector — never `shell=True`, never
   imported, never linked. The platform is not a derivative work.
2. Present in the `worker-cpu` image only, **never in `api`**.
3. A **pure-Python fallback** (Pillow + pikepdf + a minimal EXIF/XMP/ICC reader) is always available
   and used automatically when the binary is absent. M8 never hard-fails because of a licensing choice.
4. Running **without** ExifTool is a documented, supported configuration — not a degraded mode.
5. Timeout, output-size caps and resource limits apply to every invocation; it parses untrusted input
   and has had CVEs.

**Redistribution requirements.** If ExifTool is redistributed inside a published image, the applicable
licence text must accompany it. Under the GPL reading this means providing the GPLv3 text and
corresponding-source information for ExifTool itself (not for the platform, which is a separate
program). Under the Artistic reading the obligations are lighter. **The image build includes the
upstream licence text either way**, which satisfies both readings.

### 3.2 ffmpeg

| | |
|---|---|
| **Licence** | **LGPL-2.1+** as distributed, *unless* built `--enable-gpl` |
| **Purpose** | Container demuxing, frame and audio extraction (M11, M12) |
| **Distribution** | System package in `worker-cpu` / `worker-gpu`; separate process |

**Critical constraint:** we **never re-encode evidence**. Frame extraction and stream demuxing are
LGPL operations. Because no re-encoding occurs, **no GPL-licensed codec (e.g. x264) is required**, and
the `--enable-gpl` build is avoided. This keeps ffmpeg at LGPL-2.1+ and is a deliberate design
constraint, not an accident — re-encoding evidence would also be forensically wrong.

### 3.3 Other system tooling

| Tool | Licence | Use | Notes |
|---|---|---|---|
| `libmagic` / `file` | BSD-2-style | MIME detection at ingest | Permissive, no obligation |
| `poppler-utils` | **GPL-2.0+** | PDF rasterisation | Behind `ENABLE_POPPLER=true`, subprocess only — see [ADR-0002](adr/ADR-0002-pikepdf-default-pdf-stack.md) |
| ClamAV | **GPL-2.0** | Malware scanning | Separate daemon over TCP, not a derivative work; behind `ENABLE_AV_SCAN=true` — see [ADR-0014](adr/ADR-0014-clamav-included-but-disabled-by-default.md) |
| NVIDIA CUDA runtime | **Proprietary EULA** — finding **L-9** | GPU inference | `worker-gpu` only. Redistribution is permitted under NVIDIA's terms but the EULA must be surfaced to the operator; it is **not** open source and must never appear in the default (CPU) image |

---

## 4. Backend Python dependencies — default graph

All versions verified on PyPI, 2026-11-10. **Nothing below is AGPL, SSPL or RSAL.**

| Package | Version | Licence | Purpose | Milestone |
|---|---|---|---|---|
| `fastapi` | 0.162.3 | MIT | HTTP API | M1 |
| `pydantic` | 2.14.3 | MIT | Validation, schemas | M1 |
| `pydantic-settings` | 2.16.2 | MIT | Typed configuration | M1 |
| `uvicorn` | 0.40.0 | BSD-3 | ASGI server | M1 |
| `structlog` | 25.5.0 | MIT/Apache-2.0 | Structured logging + redaction | M1 |
| `sqlalchemy` | 2.1.8 | MIT | ORM / Core | M2 |
| `alembic` | 1.20.1 | MIT | Migrations | M2 |
| `psycopg` (3) | current | **LGPL-3.0 with explicit linking permission** | PostgreSQL driver | M2 |
| `celery` | 5.7.0 | BSD-3 | Background processing | M7 |
| `redis-py` | 8.1.0 | MIT | Broker client, locks, denylist | M7 |
| `pyjwt` | 2.15.1 | MIT | JWT | M3 |
| `argon2-cffi` | 25.1.0 | MIT/Apache-2.0 | Password hashing (argon2id) | M3 |
| `python-multipart` | 0.0.33 | Apache-2.0 | Upload parsing | M5 |
| `httpx` | 0.28.1 | BSD-3 | Gated outbound calls only | M17 |
| `httpx2` | 2.16.0 | BSD-3 | **Dev/test only** — required by starlette ≥1.x `TestClient` | M1 |
| `pikepdf` | 10.18.0 | **MPL-2.0** | PDF structure (QPDF binding) | M10 |
| `pdfminer.six` | 20260107 | MIT | PDF text/layout | M10 |
| `pdfplumber` | 0.11.10 | MIT | PDF tables | M10 |
| `pypdf` | 7.0.1 | BSD-3 | PDF metadata, encryption | M10 |
| `Pillow` | 13.0.0 | MIT-CMU (HPND) | Image handling | M9 |
| `opencv-python-headless` | 5.0.0.93 | Apache-2.0 | Image/video processing | M9, M12 |
| `numpy` / `scipy` | current | BSD-3 | Signal processing, indicators | M14 |
| `imagehash` | 4.3.2 | BSD-3 | Perceptual hashing | M15 |
| `networkx` | 3.7 | BSD-3 | Relationship graph | M16 |
| `python-magic` | 0.4.27 | MIT | MIME via libmagic | M5 |
| `reportlab` | 5.1.0 | BSD-3 | PDF report generation | M18 |
| `faster-whisper` | 1.2.1 | MIT | Default ASR (CTranslate2) | M11 |
| `openai-whisper` | 20250625 | MIT | Optional ASR | M11 |
| `torch` | 2.15.0 | BSD-3 | Inference runtime (**not in `api`**) | M9+ |
| `torchvision` | 0.29.2 | BSD-3 | Detection operators — **code only, no weights shipped** | M13 |
| `pytest` / `pytest-asyncio` | 9.2.0 / 1.3.0 | MIT | Testing | M1 |
| `ruff` | 0.14.10 | MIT | Lint + format | M1 |
| `playwright` | 1.65.0 | Apache-2.0 | E2E | M21 |

### 4.1 Rejected dependencies

| Package | Licence | Why rejected |
|---|---|---|
| `ultralytics` 8.4.208 | **AGPL-3.0** — verified: `LICENSE` reads *"GNU AFFERO GENERAL PUBLIC LICENSE Version 3"* | Network copyleft would reach the whole service. Available only behind `ENABLE_ULTRALYTICS=true`. |
| `PyMuPDF` 2.1 | **Dual AGPL-3.0 / Artifex commercial** — verified from PyPI metadata | Behind `ENABLE_AGPL_PYMuPDF=true` only; [ADR-0002](adr/ADR-0002-pikepdf-default-pdf-stack.md) |
| `passlib` 1.7.4 | BSD, **but unmaintained** — last release 2020, breaks against `bcrypt>=4.1` | Rejected on maintenance grounds, not licence. `argon2-cffi` + direct `bcrypt` used instead. |

### 4.2 Database driver — a note on `psycopg`

`psycopg` 3 is **LGPL-3.0**, but LGPL's linking permission explicitly covers use as a library from a
non-LGPL program — the same model as `libpq` itself, which every PostgreSQL client uses. No copyleft
reaches platform code. **If counsel objects to any LGPL in the graph, `asyncpg` (Apache-2.0) is the
documented drop-in alternative.** This substitution is recorded here rather than made silently, per
[ADR-0001](adr/ADR-0001-permissive-default-dependency-set.md) §8.

---

## 5. Model weights and datasets — audited **separately**

> **The central rule of this section** ([ADR-0001](adr/ADR-0001-permissive-default-dependency-set.md) §9):
> a permissive Python package does **not** make its weights permissive. Weights, datasets, pretrained
> checkpoints and downloaded binaries are each audited on their own terms.

### 5.1 torchvision pretrained weights — finding **L-2**, **not clearly BSD**

`torchvision` code is BSD-3. Its **weights are not covered by that licence.** Verified by reading
`docs/source/models.rst` in the upstream repository, which states:

> *"The pre-trained models provided in this library may have their own licenses or terms and
> conditions derived from the dataset used for training. It is your responsibility to determine
> whether you have permission to use the models for your use case."*

Consequences, by weight family:

| Weight family | Trained on | Terms | Decision |
|---|---|---|---|
| Classification | ImageNet | **Non-commercial research terms** | **Excluded entirely.** Never shipped, never downloaded, never used. |
| Detection | COCO | Dataset terms require review — **L-2 open** | **Not shipped.** Detection uses **operator-supplied weights**; the platform provides the code path and the operator provides artifacts they have cleared. |

> **Dead end recorded:** `pytorch/vision/contents/torchvision/models/README.md` and
> `references/README.md` both return **404**. The disclaimer lives in `docs/source/models.rst`. A
> reviewer re-checking this finding must look there.

### 5.2 Deepfake detection weights — **none shipped**, by decision

No third-party deepfake detector weights are shipped or downloaded. Published detectors are typically
trained on datasets with research-only or unstated terms, and a black-box classifier score invites
exactly the overclaiming the owner forbids. M14 therefore implements **classical weight-free
indicators** — see [ADR-0023](adr/ADR-0023-weight-free-deepfake-indicators.md) for the full list and
rationale.

### 5.3 Whisper weights — **MIT, cleared**

Verified from the `openai/whisper` README, verbatim: *"Whisper's code and model weights are released
under the MIT License."* Both `openai-whisper` and `faster-whisper` consume these weights. This is
unusually explicit for a model family and was a decisive factor in [ADR-0017](adr/ADR-0017-faster-whisper-default-asr.md).

### 5.4 ByteTrack — MIT code, **non-commercial checkpoints**

| Artifact | Source | Licence | Decision |
|---|---|---|---|
| Algorithm / reference code | `FoundationVision/ByteTrack` (moved from `ifzhang/ByteTrack`) | **MIT** — verified from `LICENSE` | **Ported** into `ai_services/engines/detection/tracker.py` |
| Released checkpoints | Benchmarked on MOT17 / MOT20 | **CC BY-NC-SA 3.0 — non-commercial** | **Never shipped, never downloaded** |

Porting MIT code and refusing NC checkpoints gives full tracking capability with no licence exposure.
Note that `ultralytics`' convenient `.track()` wrapper is AGPL and is not used.

> **Dead end recorded:** `api.github.com/repos/ifzhang/ByteTrack` returns **301**. Use
> `FoundationVision/ByteTrack`, `api.github.com/repositories/400476704`, or `curl -sL`.

### 5.5 Face detection / recognition weights — finding **L-5**

**No face-recognition model is used anywhere in the platform.** This avoids both an unverified weights
licence and the substantially heavier legal questions raised by biometric identification of people.
Face *detection* (locating a face region, not identifying a person) is used in M9 for crop and
landmark work; candidate weights could not be licence-verified from the audit environment, so **L-5 is
open** and M9 ships with operator-supplied artifacts only.

### 5.6 Other weight/dataset findings

| Finding | Subject | Status | Consequence |
|---|---|---|---|
| **L-3** | EasyOCR model weights | **Unverified** | OCR ships gated; weights operator-provisioned with recorded provenance |
| **L-6** | `pyannote` diarisation models | **Unverified** — known to require acceptance of gated terms | Diarisation **disabled** in v1; enabling needs its own flag and verification |
| **L-7** | Gazetteer dataset (GeoNames or equivalent) | **Unverified** | [ADR-0015](adr/ADR-0015-offline-gazetteer-disabled-by-default.md): **disabled by default**, attribution mandatory if enabled |
| **L-9** | NVIDIA CUDA runtime | Proprietary EULA, terms known | `worker-gpu` only; EULA surfaced to the operator; never in the default CPU image |
| **L-11** | Report fonts | Embeddability + redistributability required | DejaVu (BSD-style) or Liberation/Noto (SIL OFL) only — [ADR-0019](adr/ADR-0019-report-manifest-hashing-with-optional-crypto-signing.md) |

> **Dead end recorded — do not repeat:** `api.github.com/repos/dr5hn/countries-states-cities-database`
> returns **ODbL**, but that was a **wrong-repo probe**. It is *not* the gazetteer under consideration
> and its licence says nothing about **L-7**. In particular, **CC BY 4.0 must not be asserted as fact**
> for the gazetteer dataset.

### 5.7 Permissively licensed alternatives that were verified

Confirmed during the audit and available as documented fallbacks:

| Project | Licence | Verified |
|---|---|---|
| `Megvii-BaseDetection/YOLOX` | **Apache-2.0** | Yes — the documented permissive YOLO fallback |
| `open-mmlab/mmdetection` | **Apache-2.0** | Yes |
| `openai/CLIP` | **MIT** | Yes — code only; weights separately audited |
| `SYSTRAN/faster-whisper` | **MIT** | Yes |

---

## 6. Frontend dependencies

All verified on the npm registry, 2026-11-10. **Zero copyleft in the frontend graph.**

| Package | Version | Licence | Purpose |
|---|---|---|---|
| `next` | 16.4.6 | MIT | Framework (App Router, standalone output) |
| `react` / `react-dom` | 19.3.1 | MIT | UI |
| `typescript` | 7.0.2 | Apache-2.0 | Language |
| `tailwindcss` | 4.3.5 | MIT | Styling |
| Radix UI primitives | current | MIT | Accessible headless components |
| `@tanstack/react-query` | 5.107.1 | MIT | Server state |
| `@tanstack/react-table` | current | MIT | Tables |
| `zustand` | 5.1.0 | MIT | Client state |
| `cytoscape` | 3.34.4 | MIT | Relationship graph |
| `wavesurfer.js` | 8.0.5 | BSD-3 | Audio waveform |
| `vitest` | 5.1.0 | MIT | Unit tests |
| `@axe-core/playwright` | current | MPL-2.0 | Accessibility testing (**dev only**, file-level copyleft, no distribution impact) |

Vendored `shadcn`-style components retain upstream MIT copyright notices in file headers, as MIT
requires — see [ADR-0016](adr/ADR-0016-radix-primitives-with-vendored-ui-components.md).

---

## 7. Feature flags and their licence meaning

Every flag below defaults to `false`. **A copyleft component is never activated by default, and
activation is logged as a warning at startup and reported by `/api/v1/status`.**

| Flag | Default | Licence consequence when enabled |
|---|---|---|
| `ENABLE_ULTRALYTICS` | `false` | Introduces **AGPL-3.0** into the graph — network copyleft on the service |
| `ENABLE_AGPL_PYMuPDF` | `false` | Introduces **AGPL-3.0** (or requires an Artifex commercial licence) |
| `ENABLE_POPPLER` | `false` | Introduces **GPL-2.0+** as a subprocess; no derivative-work effect |
| `ENABLE_AV_SCAN` | `false` | Introduces **GPL-2.0** ClamAV as a separate daemon; no derivative-work effect |
| `ENABLE_AV_UPDATES` | `false` | Egress; additionally requires `ENABLE_AV_SCAN` |
| `ENABLE_EXIFTOOL` | **`true`** | Dual Artistic/GPL — see **L-1**; subprocess-isolated and removable |
| `GAZETTEER_ENABLED` | `false` | Dataset licence **unverified (L-7)**; attribution mandatory |
| `ENABLE_ONLINE_GEOCODING` | `false` | Egress of location data; requires the master switch |
| `ENABLE_EXTERNAL_ENRICHMENT` | `false` | **Master egress switch** ([ADR-0012](adr/ADR-0012-data-residency-no-default-egress.md)) |
| `ALLOW_MODEL_DOWNLOAD` | `false` | Unpinned weight download — licensing **and** supply-chain risk |
| `ENABLE_EXTERNAL_AI` | `false` | A *service* relationship, not a dependency; provider ToS must be reviewed ([ADR-0021](adr/ADR-0021-external-ai-activation-and-egress-confirmation.md)) |

---

## 8. Infrastructure

### 8.1 Base images

| Image | Licence | Used for |
|---|---|---|
| `python:3.11-slim` | PSF + Debian components | `api`, `worker-cpu`, `beat` |
| `node` / Next standalone runtime | MIT | `frontend` |
| CUDA 12.x base | **NVIDIA proprietary EULA (L-9)** | `worker-gpu` only |

### 8.2 PostgreSQL

`pgvector/pgvector:pg16` — PostgreSQL License (permissive, MIT-like); `pgvector` extension is
PostgreSQL License. No copyleft.

### 8.3 nginx

`nginx:1.27-alpine` — BSD-2-Clause. Permissive.

### 8.4 Redis — **the licensing trap**, finding driving [ADR-0022](adr/ADR-0022-redis-7-2-pin.md)

| Version | Licence | Status |
|---|---|---|
| **Redis ≤ 7.2** | **BSD-3-Clause** | ✅ **Pinned: `redis:7.2-alpine`, by digest** |
| Redis 7.3 | transitional | ❌ Excluded by CI gate |
| **Redis 8** | **RSALv2 / SSPLv1**, later adding an **AGPLv3** option | ❌ **Excluded by CI gate** |

RSALv2 and SSPLv1 are **not** open-source licences and restrict offering the software as a service;
the AGPLv3 option would introduce network copyleft. A routine `redis:latest` bump would silently
change the platform's licensing posture.

**Mitigations:** digest pinning; a CI gate that fails on any `redis:8*` or `redis:7.3*` reference
anywhere in the repository (compose, Dockerfiles, docs, fixtures); and — most importantly — Redis
holds only **ephemeral** data in v1. The Celery **result backend is PostgreSQL**, so nothing
evidentially significant lives in Redis and losing it is recoverable. **Valkey** (BSD-3, Linux
Foundation fork) is the documented upgrade path if 7.2 ever reaches end of support.

---

## 9. Enforcement — how this audit is kept true

An audit that is not mechanically enforced decays within one dependency bump. These gates are
CI-blocking:

1. **`tools/license-check/`** — resolves the default dependency graph and **fails on AGPL, SSPL or
   RSAL**. A negative test injects an AGPL dependency and asserts the gate fails.
2. **`tools/license-check/policy.toml`** — the allowlist, denylist and per-package overrides, so an
   exception is a reviewed file change rather than a code edit.
3. **Redis image gate** — fails on `redis:8*` / `redis:7.3*` (§8.4).
4. **`models.lock.json`** — every model artifact records `code_licence`, `weights_licence`,
   `weights_licence_source`, `weights_licence_verified_at`, `commercial_use_cleared`,
   `legal_review_id` and `allow_fetch`. **The loader refuses any artifact whose `allow_fetch` is not
   `true`, whose `weights_licence` is empty, or whose SHA-256 does not match — fail closed, never
   fall back.**
5. **SBOM + `THIRD_PARTY_LICENSES.md`** generated per release, so downstream obligations are met
   regardless of our own licensing position ([ADR-0008](adr/ADR-0008-repository-remains-unlicensed.md)).
6. **Frontend bundle grep** — no `NEXT_PUBLIC_*` variable may hold a provider API key.
7. **`import-linter` boundaries** — a flag-gated copyleft module cannot be imported by default-path code.
8. **No LICENSE file assertion** — CI fails if a `LICENSE`/`COPYING` file appears while ADR-0008 is
   `Accepted`, forcing a conscious decision rather than an accidental one.

---

## 10. Open findings summary

| ID | Subject | Severity | Gates | Resolution path |
|---|---|---|---|---|
| **L-1** | ExifTool Artistic-vs-GPL election | Medium | M8 metadata | Counsel reviews the dual-licence election. Engineering controls hold under either reading. |
| **L-2** | torchvision COCO detection weights | Medium | M13 detection | Operator supplies cleared weights; platform ships none. |
| **L-3** | EasyOCR weights | Medium | M10/M13 OCR | Verify upstream terms, or operator-provision with recorded provenance. |
| **L-5** | Face-detector weights | Medium | M9 image | Operator-supplied only. No face **recognition** anywhere. |
| **L-6** | `pyannote` diarisation weights | Low | M11 audio | Diarisation disabled in v1; gated acceptance required to enable. |
| **L-7** | Gazetteer dataset licence | Medium | M8/M16 location | Disabled by default; counsel verifies, then operator provisions with attribution. |
| **L-9** | NVIDIA CUDA EULA | Low | `worker-gpu` | Proprietary but redistributable under NVIDIA terms; surfaced to the operator; never in the CPU image. |
| **L-11** | Report font embedding/redistribution | Low | M18 reports | Use DejaVu (BSD-style) or Liberation/Noto (SIL OFL) only; reproduce notices. |

**Rule for every open finding:** ship the conservative path, gate the capability behind a flag, and
**never ship an unverified artifact**. An unresolved finding delays a feature; it never results in a
guess.

---

## 11. What this document deliberately does not say

* It does **not** say TruthLens X is legally compliant in any jurisdiction.
* It does **not** resolve **L-1**; it reports a contradiction in upstream licensing text and leaves the
  election to counsel.
* It does **not** assert CC BY 4.0 (or any licence) for the gazetteer dataset — **L-7 is unverified**.
* It does **not** treat a permissive package licence as covering that package's weights.
* It does **not** license the platform itself — see [ADR-0008](adr/ADR-0008-repository-remains-unlicensed.md).
  The repository is deliberately unlicensed, which means default copyright and all rights reserved.
  **That decision must be revisited before the repository is made public.**
