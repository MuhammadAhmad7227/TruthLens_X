# TruthLens_X

**TruthLens X** — an AI-powered digital forensics and evidence intelligence platform.

> ## ✅ Project status: **ARCHITECTURE RATIFIED — M1 APPROVED — NO APPLICATION CODE YET**
>
> Milestone **M0** (architecture & documentation) is complete and merged. Milestone **M0.5**
> (decision ratification) is complete: **all 20 architectural decisions were approved by the project
> owner on 2026-11-10** and each is now a binding Architecture Decision Record in
> [`docs/adr/`](./docs/adr/README.md) — 23 in total, including three that emerged from the licence
> and AI audit.
>
> Milestone **M1** (repository foundation) is **approved and in progress**. Milestones **M2–M21** have
> not been started.
>
> 👉 **Read [docs/DECISIONS.md](./docs/DECISIONS.md) first** — the ratified decision register,
> including the four conflicts found during ratification and how each was resolved.
>
> **Nothing in this repository is functional yet.** There is no backend, no frontend, no database and
> no Docker stack — only the ratified specification for them. M1 delivers the scaffold; no forensic
> capability exists until M5 onward.

---

## What this platform does

TruthLens X accepts digital media (images, video, audio, documents), **preserves the originals
immutably**, runs classical and machine-learning forensic analyses over them, and presents the
results as *weighted investigative indicators* that a qualified human examiner reviews, confirms or
rejects.

It does **not** decide guilt, authenticity, or truth. It narrows the search space for an examiner and
produces a defensible, reproducible record of how each conclusion was reached.

### The three rules that shape the whole system

1. **Originals are sacred.** Evidence is written once into a content-addressed store keyed by its
   SHA-256, mounted read-only everywhere except the ingest worker, re-verified before every analysis
   and on a nightly sweep. All derived output (thumbnails, heat-maps, frames, transcripts, reports)
   lives in a separate tree and is disposable.
2. **AI output is an indicator, never a fact.** Every result must carry the model name and version,
   weights checksum, parameters, execution device, a confidence *with a stated basis*, an interval
   for any score, a versioned limitations statement, and a human verification state. These are
   enforced by database `CHECK` constraints and by the result contract — a result missing them cannot
   be persisted. **There is no verdict field anywhere in the schema.**
3. **Everything is attributable and tamper-evident.** Chain-of-custody and audit records are
   append-only and SHA-256 hash-chained, with `UPDATE`/`DELETE` revoked at the database-role level
   and a verifier that can locate any broken link.

Full policy: [docs/MASTER_PRD.md §5](./docs/MASTER_PRD.md#5-ai-responsibility-policy-binding).

---

## Documentation

| Document | What it answers |
|---|---|
| **[docs/DECISIONS.md](./docs/DECISIONS.md)** | **v2.0.0 RATIFIED — all 20 decisions approved; start here.** |
| [docs/adr/README.md](./docs/adr/README.md) | **23 Architecture Decision Records** — context, alternatives, consequences, licensing and security implications, reversal strategy, and the verification that proves each is enforced |
| [docs/README.md](./docs/README.md) | Index + suggested reading order by role (including Legal and Operator/SRE paths) |
| [docs/MASTER_PRD.md](./docs/MASTER_PRD.md) | All 22 modules as testable requirements, AI-responsibility policy, NFRs, user journeys |
| [docs/SYSTEM_ARCHITECTURE.md](./docs/SYSTEM_ARCHITECTURE.md) | Containers, full folder structure, data flows, storage layout, verified licence table, copyleft containment |
| [docs/DATABASE_DESIGN.md](./docs/DATABASE_DESIGN.md) | Every table, column, constraint, index and enum; hash-chain design; pgvector; migration & retention strategy |
| [docs/API_SPECIFICATION.md](./docs/API_SPECIFICATION.md) | Conventions, error model, pagination, complete endpoint map, SSE/WebSocket progress, rate limits |
| [docs/SECURITY_ARCHITECTURE.md](./docs/SECURITY_ARCHITECTURE.md) | STRIDE threat register, cryptographic design, authorisation model + capability matrix, stated limitations |
| [docs/IMPLEMENTATION_ROADMAP.md](./docs/IMPLEMENTATION_ROADMAP.md) | 22 milestones with tasks, exit criteria, dependencies, approval gates, delivery risks |
| [docs/TESTING_STRATEGY.md](./docs/TESTING_STRATEGY.md) | Test pyramid, synthetic evidence fixtures with ground truth, golden-file & determinism policy, honesty tests |
| [docs/DEPLOYMENT_GUIDE.md](./docs/DEPLOYMENT_GUIDE.md) | Topology, host sizing, first-time install, upgrades, backup/restore, hardening checklist, monitoring |
| **[docs/THIRD_PARTY_LICENSE_AUDIT.md](./docs/THIRD_PARTY_LICENSE_AUDIT.md)** | **What may we ship?** Every dependency, model weight, dataset and base image with its licence and distribution method; rejected dependencies; open findings L-1…L-11; the CI gates that keep it true. **Not legal advice — asserts no compliance.** |
| **[docs/AI_ARCHITECTURE.md](./docs/AI_ARCHITECTURE.md)** | **How does AI work here?** Provider protocol, why the provider is fixed at startup, the external-AI activation and egress-confirmation protocol, model registry and `models.lock.json`, and how honesty is enforced by database constraints |
| **[docs/BACKUP_RECOVERY.md](./docs/BACKUP_RECOVERY.md)** | **What happens when it breaks?** Recovery priorities, why volume encryption does *not* encrypt backups, LUKS2 key custody and escrow, restore procedures with mandatory verification gates, honest RTO/RPO for a single host |

---

## Planned technology stack

| Layer | Choice |
|---|---|
| Frontend | Next.js 16 · React 19 · TypeScript · Tailwind CSS 4 · TanStack Query · Cytoscape · WaveSurfer.js |
| Backend | Python 3.11 · FastAPI · Pydantic v2 · SQLAlchemy 2.x · Alembic |
| Database | PostgreSQL 16 + `pgvector` |
| Background processing | Celery · Redis (broker/cache) · Postgres (result backend) |
| Forensic & AI engines | OpenCV (headless) · Pillow · ExifTool (subprocess) · PyTorch · ByteTrack (MIT) · EasyOCR · Whisper / faster-whisper · pikepdf + pdfminer.six · ReportLab |
| Testing | pytest · hypothesis · Vitest · Playwright · k6 |
| Infrastructure | Docker · Docker Compose · nginx · GitHub Actions |

### ✅ Licensing — resolved and audited

Three components named in the project brief carry copyleft licences that reach hosted/networked use.
Verified against PyPI, the npm registry and GitHub on 2026-11-10:

| Component | Package | Licence | Resolution |
|---|---|---|---|
| YOLO | `ultralytics` 8.4.208 | **AGPL-3.0** | Excluded from the default graph; behind `ENABLE_ULTRALYTICS=false` — [ADR-0001](./docs/adr/ADR-0001-permissive-default-dependency-set.md) |
| PDF | `PyMuPDF` 2.1 | **AGPL-3.0** or Artifex commercial | `pikepdf` (MPL-2.0) is the default; PyMuPDF behind `ENABLE_AGPL_PYMuPDF=false` — [ADR-0002](./docs/adr/ADR-0002-pikepdf-default-pdf-stack.md) |
| Metadata | ExifTool binary | **Contradictory: GPLv3 `LICENSE` file vs an Artistic-or-GPL election in the README** | Subprocess-isolated, worker image only, pure-Python fallback always present, removable as a supported configuration — [ADR-0003](./docs/adr/ADR-0003-exiftool-optional-subprocess.md), finding **L-1** |

**Two further findings changed the design** and were not anticipated by the original brief:

* **A permissive Python package does not make its weights permissive.** `torchvision`'s own
  documentation disclaims any licence for its pretrained models; the ImageNet-pretrained weights carry
  **non-commercial research terms** and are excluded entirely. Detection therefore ships **no weights**
  and uses operator-supplied artifacts. Deepfake analysis (M14) uses **classical weight-free indicators**
  instead of a trained classifier — [ADR-0023](./docs/adr/ADR-0023-weight-free-deepfake-indicators.md).
* **Redis ≤7.2 is BSD-3; Redis 8 moved to RSALv2/SSPLv1.** A routine `redis:latest` bump would
  silently change the platform's licensing posture, so the image is **digest-pinned to
  `redis:7.2-alpine`** and a CI gate fails on any `redis:8*` or `redis:7.3*` reference —
  [ADR-0022](./docs/adr/ADR-0022-redis-7-2-pin.md).

ByteTrack's reference implementation is MIT and is **ported** into
`ai_services/engines/detection/tracker.py` rather than reached through the AGPL `ultralytics` tracking
wrapper; their MOT17/MOT20 checkpoints are **CC BY-NC-SA (non-commercial)** and are never shipped.

Full inventory, rejected dependencies, and the eight open findings (L-1…L-11) that gate specific
artifacts: **[docs/THIRD_PARTY_LICENSE_AUDIT.md](./docs/THIRD_PARTY_LICENSE_AUDIT.md)**. That document
is **not legal advice and asserts no compliance** — it records what was verified, what could not be,
and the engineering consequence of each.

---

## Planned capabilities (22 modules)

<details>
<summary>Expand the full module list</summary>

1. Authentication & authorization — argon2id, JWT with refresh rotation and reuse detection, TOTP MFA, two-layer RBAC + case-level ACL
2. Case management — lifecycle state machine, membership with time-bounded grants, sensitivity classification, legal hold
3. Evidence management — chunked upload, streaming SHA-256, magic-byte type detection, content-addressed dedup
4. Chain of custody — append-only hash-chained ledger, transfer/accept flow, exportable custody report
5. Image forensics — ELA, JPEG quantisation-table fingerprinting, copy-move, noise/CFA maps, perceptual hashing, annotations
6. Video forensics — stream probing without re-encoding, deterministic keyframes, shot segmentation, temporal-consistency indicators
7. Audio forensics — Whisper ASR with word timings, diarisation (anonymous labels), splice/clipping/bandwidth/vocoder indicators
8. Document forensics — PDF **incremental-revision detection and diff**, XMP, embedded-file extraction, OOXML analysis, OCR fallback
9. Metadata extraction — ExifTool isolation, normalised schema, timestamp provenance classification, stripping-signal detection
10. Location intelligence — GPS parsing with uncertainty, clustering, movement tracks, offline gazetteer, implausibility checks
11. Deepfake analysis — frequency/face/temporal/audio **indicator ensemble** with an advisory score, interval, and a mandatory disclaimer. Never a verdict.
12. Object detection & tracking — pluggable detectors, ByteTrack association, stable track IDs, queryable detections
13. Licence-plate recognition — two-stage detect→OCR, jurisdiction-aware format validators, top-N ambiguous-character reporting, no external registry lookups
14. Evidence comparison — exact/perceptual hash, feature matching with RANSAC, histograms, embeddings, metadata diff, audio cross-correlation, text diff
15. Evidence relationship graph — typed edges (`manual`/`inferred`), confidence and rule versioning, analyst promotion/rejection, interactive view
16. Investigation timeline — multi-source events with derivation, reliability, corroboration, and **conflict groups that are never merged**
17. AI investigation assistant — case-scoped RAG with mandatory citations, guardrailed prompts, local-model default, no mutation powers
18. Evidence similarity search — pgvector HNSW, versioned vector sets, hybrid search, near-duplicate review queue
19. PDF investigation reports — ReportLab templates, reproducible manifest + hashes, versioning, approval and attestation
20. Audit logs — append-only hash-chained, partitioned, searchable, exportable, with chain verification
21. Administration dashboard — users, model registry, queue/worker monitoring, storage, integrity sweeps, licence flags
22. Security & monitoring — hardening controls, metrics, detection alerts, scanning gates, SBOM

</details>

Explicit non-goals for v1 (disk-image carving, memory forensics, mobile acquisition, password
cracking, speaker identification, external registry lookups) are listed in
[docs/MASTER_PRD.md §1.2](./docs/MASTER_PRD.md).

---

## Repository layout

Currently only documentation exists. The full planned tree — `backend/`, `ai_services/`,
`frontend/`, `infra/`, `tools/` — is specified in
[docs/SYSTEM_ARCHITECTURE.md §4](./docs/SYSTEM_ARCHITECTURE.md#4-repository-structure) and will be
scaffolded in milestone M1.

```
TruthLens_X/
├── README.md          ← you are here
├── .env.example       ← every environment variable, documented, no real values
├── .gitignore         ← evidence files and model weights are excluded by design
└── docs/              ← the ratified specification set (12 documents)
    └── adr/           ← 23 Architecture Decision Records + index
```

---

## Roadmap at a glance

`M0 ✅ docs` → `M0.5 ✅ decisions ratified (23 ADRs)` → `M1 foundation ← approved, in progress` →
`M2 database` → `M3 auth/RBAC` → `M4 cases` →
**`M5 evidence ingest & integrity`** → **`M6 chain of custody`** → `M7 async platform` →
`M8 metadata` → `M9 image` → `M10 document` → `M11 audio` → `M12 video` → `M13 detection/ALPR` →
`M14 deepfake indicators` → `M15 comparison/similarity` → `M16 graph/timeline` → `M17 AI assistant` →
`M18 reports` → `M19 admin` → `M20 security hardening` → `M21 E2E & release`

≈ 165 engineering days. The integrity spine (M5→M6) and the async spine (M7) are deliberately
front-loaded. Details, exit criteria and approval gates:
[docs/IMPLEMENTATION_ROADMAP.md](./docs/IMPLEMENTATION_ROADMAP.md).

---

## Legal & ethical notice

TruthLens X is engineering tooling. It is **not** legal advice, and the admissibility of its output
depends on jurisdiction, examiner qualification, and procedure. Its AI components produce
**investigative indicators** that require human verification; no deepfake, splicing, ALPR, or audio
detector is reliable in the wild, and this platform will never claim otherwise. Owners of a
deployment are responsible for obtaining local legal counsel on the handling, retention, and
presentation of digital evidence.

---

## Licence

**This repository is deliberately unlicensed.** There is no `LICENSE` file, and that is a ratified
decision, not an oversight — see [ADR-0008](./docs/adr/ADR-0008-repository-remains-unlicensed.md).

In practice this means **default copyright: all rights reserved.** Nobody may legally copy, modify,
redistribute or contribute to this code until a licence is chosen. ADR-0008 records the alternatives
considered (Apache-2.0 was the strongest candidate; AGPL-3.0 was rejected because the project takes
care to keep AGPL *out* of its dependency graph) and notes that adding a licence later does not
retroactively clarify the terms for anyone who obtained the code before then.

> ⚠️ **ADR-0008 requires this decision to be revisited before the repository is made public.**

Third-party obligations are unaffected by our own licensing position and are still met: an SBOM and a
generated `THIRD_PARTY_LICENSES.md` ship with each release, and copyleft notices for MPL-2.0, LGPL and
GPL tooling are reproduced as those licences require — see
[docs/THIRD_PARTY_LICENSE_AUDIT.md §9](./docs/THIRD_PARTY_LICENSE_AUDIT.md).
