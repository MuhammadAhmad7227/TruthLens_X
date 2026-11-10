# TruthLens X — Decisions & Assumptions Register

| | |
|---|---|
| **Document ID** | TLX-DOC-009 |
| **Version** | 0.1.0 |
| **Last updated** | 2026-11-10 |
| **Purpose** | Every architectural assumption made while writing the M0 documentation set, listed for **explicit approval**. Nothing below is implemented yet. |

This is the document to read if you only read one. Each entry states what I assumed, why, what
changes if you disagree, and which milestones it blocks.

**How to respond:** reply with the decision IDs and your choice, e.g.
`D-001: B, D-002: A, D-006: off, D-007: local, everything else as proposed`.
Unanswered items default to the **proposed** column at the start of M1, and each default is
recorded in an ADR so it can be reversed later with a paper trail.

Legend: 🔴 blocks a milestone · 🟡 affects design but not blocking · 🟢 informational

---

## 🔴 Blocking decisions

### D-001 — Object detector: AGPL Ultralytics YOLO, or a permissive alternative?

**Verified fact (PyPI/GitHub, 2026-11-10):** `ultralytics` 8.4.208 is licensed **AGPL-3.0**.
AGPL §13 extends copyleft to *network* use — hosting TruthLens X as a service for others could
obligate you to publish the source of the whole platform under AGPL.

| Option | Description | Consequence |
|---|---|---|
| **A (proposed)** | Permissive default: `torchvision` (BSD) RetinaNet/FCOS or `mmdetection` (Apache-2.0). Ultralytics available behind `ENABLE_ULTRALYTICS=true`. | Default build has no AGPL. Slightly lower out-of-the-box mAP convenience than YOLOv8/11; more adapter work in M13. |
| B | Use Ultralytics YOLO directly (AGPL) | Best detection ergonomics + built-in tracking. **You must accept AGPL obligations** for the whole service, or buy an Ultralytics Enterprise licence. |
| C | Use Ultralytics under a purchased Enterprise licence | Clean, but a recurring commercial cost and a procurement dependency. |

**Note on ByteTrack:** the algorithm's reference implementation (`FoundationVision/ByteTrack`,
moved from `ifzhang/ByteTrack`) is **MIT** — fine. But `ultralytics`' convenient `.track()` wrapper
is AGPL. Proposal A ports the MIT association logic into `ai_services/engines/detection/tracker.py`
instead of importing ultralytics. **Blocks M1 (dependency set) and M13.**

---

### D-002 — PDF library: AGPL PyMuPDF, or permissive/MPL alternatives?

**Verified fact:** `PyMuPDF` 2.1 is **AGPL-3.0 or Artifex commercial** (dual-licensed).

| Option | Description | Consequence |
|---|---|---|
| **A (proposed)** | `pikepdf` 10.18 (**MPL-2.0**, wraps QPDF) as the primary structural engine + `pdfminer.six` (MIT) / `pypdf` (BSD-3) / `pdfplumber` (MIT) for text & layout. PyMuPDF behind `ENABLE_AGPL_PYMuPDF=true`. | MPL is file-level copyleft — modifications to *pikepdf itself* must be shared, but our code stays closed. Arguably **better for forensics**: QPDF exposes XRef structure, object streams, and incremental revisions precisely, which is what DOC-02 needs. Some speed loss on very large PDFs; rendering pages to images needs `pdftoppm`/poppler (GPL binary, subprocess-isolated) or a flag. |
| B | PyMuPDF as primary (AGPL) | Fastest, best rendering, excellent text extraction. **AGPL obligations** as in D-001, or an Artifex commercial licence. |
| C | PyMuPDF under an Artifex commercial licence | Clean, recurring cost. |

**Blocks M1 and M10.**

---

### D-003 — ExifTool (GPL-3.0 binary): subprocess invocation acceptable?

**Verified fact:** `exiftool/exiftool` is **GPL-3.0**; the `pyexiftool` wrapper is `GPLv3+/BSD`.
Nothing on PyPI provides ExifTool itself — it is a Perl binary that must be installed into the image.

| Option | Description | Consequence |
|---|---|---|
| **A (proposed)** | Invoke the ExifTool **binary as a separate process** (`-j` JSON over a pipe), never linking it. Provide a permissive pure-Python fallback (Pillow/pikepdf/ffprobe + a small EXIF/XMP reader) behind the same engine interface, used when `ENABLE_EXIFTOOL=false`. | Under the standard reading, a separate program communicating at arm's length does not make our code a derivative work — but **bundling and distribution obligations still need your sign-off**, especially if you distribute images. Unmatched tag coverage (ExifTool reads formats nothing else does). |
| B | Skip ExifTool entirely; pure-Python permissive readers only | Zero GPL exposure. **Materially worse forensics** — you lose the deepest tag coverage in the industry (META-01 is the brief's explicit requirement, so this contradicts the spec). |
| C | ExifTool only, no fallback | Simplest, maximum capability, maximum licence exposure. |

**Blocks M1 and M8.** My recommendation is A: it satisfies the stated requirement (ExifTool is in
your technology list) while keeping a documented, tested exit path.

---

### D-004 — Multi-tenancy: confirm single-organisation v1

**Assumed:** one organisation, users belong to it, isolation is at the **case** level (case
membership + capability bits). No tenant_id column, no per-tenant keys, no tenant quotas.

| Option | Description | Consequence |
|---|---|---|
| **A (proposed)** | Single-org v1; case-level ACL | Simpler schema and authorisation; ships faster. Adding tenancy later means a `tenant_id` on ~20 tables plus a data migration — painful but tractable, and the ACL gate is already a single choke point. |
| B | Multi-tenant from M2 | Adds `tenant_id` everywhere, Postgres RLS, per-tenant encryption keys, tenant-scoped quotas and audit chains. ~+15 engineering days and significant complexity, worth it only if multiple independent organisations will share one deployment. |

**Blocks M2** (it is far cheaper to decide before the first migration). Please confirm.

---

### D-005 — Deployment target

**Assumed:** Docker Compose on a **single on-prem Linux host**, optional GPU; `filesystem` storage
backend; Kubernetes scaffolded but not the v1 delivery target.

| Option | Description | Consequence |
|---|---|---|
| **A (proposed)** | Single-host compose, filesystem store | Simplest to audit and to describe to a court; no cloud dependency; matches forensic units that cannot put evidence in third-party cloud. HA is limited — documented honestly (NFR-03/04). |
| B | Cloud-hosted compose/VM + S3-compatible object store | Elastic storage, managed backups, easier DR. **Evidence leaves your host** — may conflict with data-residency or evidentiary rules (see D-012). |
| C | Kubernetes from day one | Best scaling/HA; materially more operational complexity and a control plane to secure. Recommended only if you already run K8s. |

**Blocks M1** (compose files, storage adapter, backup scripts) and shapes M20/M21.

---

### D-006 — Encryption at rest for original evidence

**Assumed:** **off by default** in v1 — rely on host/disk (LUKS) or volume-level encryption, with
the option implemented but disabled.

| Option | Description | Consequence |
|---|---|---|
| **A (proposed)** | Disk/volume encryption only | No key-loss risk inside the app; ops-managed. A host compromise with the disk unlocked exposes plaintext (same as B in practice, unless keys are in an HSM). |
| B | Application-level AES-256-GCM envelope encryption per object (DEK wrapped by a KEK) | Protects against stolen disks/backups and gives per-object key revocation. **Adds a catastrophic failure mode: losing the KEK destroys the evidence permanently.** Requires a key backup/escrow procedure and rotation runbooks before enabling. ~+6 days. |

**Blocks M5.** If you choose B, I will also require a decision on escrow (split-key, offline copy,
or KMS) — I will not ship B without one.

---

### D-007 — AI assistant: local model vs external API

**Assumed:** **local/self-hosted** (Ollama or vLLM endpoint) by default; external API providers
available but disabled, because enabling one sends case data off-host.

| Option | Description | Consequence |
|---|---|---|
| **A (proposed)** | Local LLM default (`LLM_ALLOW_EXTERNAL_EGRESS=false`) | Case data never leaves the host. Needs RAM/VRAM (a usable 7–14B model wants ~16 GB VRAM or ~32 GB RAM quantised). Slower and less capable than frontier APIs. |
| B | External API (OpenAI/Anthropic/Gemini/etc.) | Best answer quality, no local hardware. **Evidence content and case metadata leave your infrastructure** — likely unacceptable for real casework, and a disclosure issue in many jurisdictions. |
| C | Both, admin-switchable per deployment, with an explicit audited opt-in | Proposed implementation shape regardless of A or B; A is the shipped default. |

**Blocks M17** (and the `LLM_*` variables in `.env.example`).

---

### D-008 — Repository licence and distribution intent

**Assumed:** undecided. This interacts directly with D-001/D-002/D-003.

| Option | Description | Consequence |
|---|---|---|
| A | Keep the source private / proprietary | Maximises freedom, but AGPL components still bind you **if you host the service for third parties** (AGPL §13 doesn't care about source distribution). |
| **B (proposed interim)** | No `LICENSE` file yet; treat as private; run the licence gate so we know exactly what is in the tree | Lets M1 start without a legal decision, while keeping the facts visible. |
| C | Open-source under AGPL-3.0 | Makes D-001/D-002/D-003 moot (everything is already AGPL-compatible). |
| D | Open-source under a permissive licence (MIT/Apache-2.0) | Then AGPL/GPL components **cannot** be in the default dependency set at all — options A in D-001/D-002 and B in D-003 become mandatory. |

**Blocks M1** only in the sense that I need to know whether to add a `LICENSE` file; the licence gate
runs either way.

---

## 🟡 Design-shaping decisions (not blocking, but please weigh in)

### D-009 — Primary key strategy
**Assumed:** UUIDv4 (`gen_random_uuid()`) with `created_at` in every sort key.
**Alternative:** UUIDv7 (time-ordered) gives far better index locality on append-heavy tables
(`audit_logs`, `custody_events`, `detections`) at 1M+ rows.
**Proposal:** UUIDv7 for high-volume append-only tables, UUIDv4 elsewhere — or UUIDv7 everywhere for
simplicity. Postgres 18 has native `uuidv7()`; on PG16 it is a small PL/pgSQL function. Cost: ~0.5 d.
**Affects M2.**

### D-010 — Row-Level Security
**Assumed:** *not* used in v1; least privilege is enforced by the single `require_case_access` gate +
a repository rule + the route-authorisation matrix test.
**Alternative:** enable Postgres RLS as defence in depth (a leaked query can't cross cases even if
application logic fails). Cost: ~4 d, plus per-request `SET LOCAL` plumbing and careful testing of
every role. **Recommendation:** add it in M20 as hardening if you want belt-and-braces. Affects M2/M20.

### D-011 — Object storage adapter
**Assumed:** `filesystem` backend in v1; an `s3`-compatible adapter (MinIO/AWS) written behind the
`StorageBackend` interface but disabled. If D-005 is B, this becomes primary. Affects M5 (~+2 d).

### D-012 — Data residency / jurisdiction
**Assumed:** evidence stays on infrastructure you control, in your jurisdiction. If that is a hard
requirement (it usually is for real casework), then D-005 = A and D-007 = A follow automatically, and
no external enrichment service (geocoding, LLM) may be enabled. **Please confirm explicitly** — it is
the kind of constraint that is cheap to honour at design time and expensive to retrofit.

### D-013 — ALPR jurisdiction and plate formats
**Assumed:** no defaults shipped; the deployment configures its own `plate_formats` rows. Your
location suggests Pakistan, so a starter set of *example* Pakistani format validators
(`LLL-DDDD`, province-token variants) would be seeded with `is_example=true` and must be reviewed by
you before being relied upon — I will not assert authoritative plate-format knowledge.
**Also confirmed as out of scope:** any automatic lookup against a vehicle-ownership registry
(ALPR-06). Affects M13.

### D-014 — Antivirus scanning of uploads
**Assumed:** ClamAV container included but **disabled by default** (`ENABLE_AV_SCAN=false`) — it adds
~1 GB of image and scan latency, and evidence uploads are already isolated in workers.
**Alternative:** enabled by default if your environment expects hostile files (it is a forensic tool,
so arguably yes). Cost: ~1 d. Affects M5.

### D-015 — Reverse geocoding data source
**Assumed:** offline gazetteer (a GeoNames subset, ~200 MB) so location intelligence works with no
egress. Online providers opt-in per deployment.
**Question:** do you want the offline gazetteer bundled (larger image) or fetched on first run
(needs egress once)? Affects M8.

### D-016 — Frontend component strategy
**Assumed:** Radix UI primitives + vendored shadcn-style components in `components/ui` (so the code is
in our tree and auditable) rather than a heavyweight component library.
**Alternative:** Ant Design / MUI (faster to build, larger bundle, weaker control over forensic-viewer
a11y). Affects M1 and every frontend milestone.

### D-017 — ASR engine default
**Assumed:** `faster-whisper` (MIT, CTranslate2) as default for CPU throughput, with `openai-whisper`
(MIT) available. Model size configurable; `base`/`small` for CPU deployments, `large-v3` for GPU.
Both are MIT so there is no licence issue — this is purely a performance preference. Affects M11.

### D-018 — Two-factor enforcement scope
**Assumed:** TOTP **mandatory** for `admin` and `lead_investigator`, optional for others.
**Alternative:** mandatory for everyone (more secure, more support overhead and lockout risk in the
field). Affects M3.

### D-019 — Report signing
**Assumed:** platform attestation block + stored PDF SHA-256 in v1; **cryptographic** PDF signing
(certificate-based) optional and deployment-configured, since it requires you to procure/manage a
signing certificate. Affects M18.

### D-020 — Retention defaults
**Assumed:** originals retained for case lifetime + a configurable statutory period; audit/custody
logs **never** deleted in v1 (archived to cold storage after 24 months); derivatives purged when stale
or after 90 days.
**Question:** what statutory period should the default be for your jurisdiction? I will not guess a
legal retention requirement. Affects M2 seeds and M19.

---

## 🟢 Informational assumptions (flag if wrong)

| # | Assumption |
|---|---|
| I-01 | Python **3.11** exactly as specified (all pinned deps support it; Pillow 13 and PyMuPDF 2.1 require ≥3.11). No move to 3.12/3.13 in v1 to keep the ML stack boring. |
| I-02 | Node 22 LTS for the frontend build (sandbox has v22.22.3). Next.js 16 / React 19 / TypeScript 7 / Tailwind 4 are current as of 2026-11-10. |
| I-03 | PostgreSQL **16** (not 17/18) for stability and because `pgvector/pgvector:pg16` is a well-trodden image. Upgrading is a documented runbook. |
| I-04 | Redis 7 as broker/cache; **Postgres** as the Celery result backend (task outcomes are evidentially significant and must not be evicted). |
| I-05 | `passlib` is deliberately avoided (last release 2020; breaks against bcrypt ≥ 4.1). argon2id via `argon2-cffi`, with direct `bcrypt` for legacy verification only. |
| I-06 | OpenCV **headless** build (`opencv-python-headless`, Apache-2.0) — no GUI/X11 dependencies in containers. |
| I-07 | ffmpeg/ffprobe are installed as system binaries and invoked with argument lists (never `shell=True`). ffmpeg is LGPL/GPL depending on build; the standard permissive-build (no `--enable-gpl` codecs beyond what we need) is proposed — **flag if you need x264/x265**, which pulls GPL. |
| I-08 | Model weights are **never** committed to git; `models.lock.json` pins family/version/SHA-256 and a fetch script verifies checksums. CI runs without weights. |
| I-09 | This development sandbox has **no Docker daemon**, so compose files are validated in CI and on your host, not locally. A Docker-less dev path (`uvicorn` + `next dev`) will be provided. |
| I-10 | The UI language for v1 is English, with i18n scaffolding in place. Urdu/Arabic RTL is a v2 item (NFR-11). Flag now if Urdu is a v1 requirement — it changes the frontend layout approach. |
| I-11 | No integration with any external law-enforcement, vehicle-registry, telecom, or biometric database in v1. |
| I-12 | All timestamps stored UTC; source offsets preserved; `TZ=UTC` in every container. |
| I-13 | Git workflow: all work on `arena/c6f7bbe4-truthlens-x`, milestone commits, PR when you want review, merge only on your instruction. |
| I-14 | "ExifTool", "YOLO", "Whisper", "ByteTrack" in the brief are treated as *capability* requirements; where a specific package carries a licence problem, a capability-equivalent alternative is proposed rather than silently dropping the capability. |
| I-15 | The eight document filenames in the brief (`MASTER_PRD.md`, `SYSTEM_ARCHITECTURE.md`, `DATABASE_DESIGN.md`, `API_SPECIFICATION.md`, `SECURITY_ARCHITECTURE.md`, `IMPLEMENTATION_ROADMAP.md`, `TESTING_STRATEGY.md`, `DEPLOYMENT_GUIDE.md`) were rendered as markdown links in the request; I read them as literal filenames and created exactly those, plus this register and an index. |

---

## Decision log (filled in as you approve)

| ID | Question | Proposed | **Decision** | Decided by | Date | ADR |
|---|---|---|---|---|---|---|
| D-001 | Detector licence | A (permissive default + flag) | *pending* | | | |
| D-002 | PDF library | A (pikepdf/MPL + flag) | *pending* | | | |
| D-003 | ExifTool | A (subprocess + fallback) | *pending* | | | |
| D-004 | Multi-tenancy | A (single-org v1) | *pending* | | | |
| D-005 | Deployment target | A (single-host compose) | *pending* | | | |
| D-006 | Encryption at rest | A (disk-level only) | *pending* | | | |
| D-007 | Assistant model | A (local default) | *pending* | | | |
| D-008 | Repo licence | B (none yet, gate on) | *pending* | | | |
| D-009 | PK strategy | UUIDv7 for append-only tables | *pending* | | | |
| D-010 | Postgres RLS | Defer to M20 | *pending* | | | |
| D-011 | S3 adapter | Interface now, disabled | *pending* | | | |
| D-012 | Data residency | On-prem, no egress | *pending* | | | |
| D-013 | Plate formats | Examples only, you review | *pending* | | | |
| D-014 | ClamAV | Included, disabled | *pending* | | | |
| D-015 | Gazetteer | Offline subset | *pending* | | | |
| D-016 | UI components | Radix + vendored | *pending* | | | |
| D-017 | ASR engine | faster-whisper default | *pending* | | | |
| D-018 | MFA scope | Mandatory admin+lead | *pending* | | | |
| D-019 | Report signing | Hash in v1, crypto optional | *pending* | | | |
| D-020 | Retention default | You specify the statutory period | *pending* | | | |

---

*End of DECISIONS.md. Once you respond, each decision becomes `docs/adr/ADR-000N-*.md` in M1 and the
roadmap status board unblocks.*
