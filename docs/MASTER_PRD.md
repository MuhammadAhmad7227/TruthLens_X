# TruthLens X — Master Product Requirements Document (PRD)

| | |
|---|---|
| **Document ID** | TLX-DOC-001 |
| **Version** | 0.1.0 (DRAFT — pending approval) |
| **Status** | Awaiting stakeholder sign-off |
| **Last updated** | 2026-11-10 |
| **Owner** | Lead Software Architect |
| **Related** | [SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md), [DATABASE_DESIGN.md](./DATABASE_DESIGN.md), [API_SPECIFICATION.md](./API_SPECIFICATION.md), [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md), [IMPLEMENTATION_ROADMAP.md](./IMPLEMENTATION_ROADMAP.md), [TESTING_STRATEGY.md](./TESTING_STRATEGY.md), [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md), [DECISIONS.md](./DECISIONS.md) |

---

## 1. Executive summary

**TruthLens X** is an AI-powered digital forensics and evidence intelligence platform. It accepts
digital media (images, video, audio, documents), preserves the originals immutably, runs a battery
of classical and machine-learning forensic analyses, and presents the results as **weighted
investigative indicators** that a human examiner reviews, confirms or rejects.

The platform's defining constraint is *evidential discipline*. Every byte of original evidence is
write-once, hash-verified, and never mutated. Every AI-generated claim carries the model name,
model version, parameters, confidence, known limitations, and a human verification state. Every
access to an evidence item is recorded in a tamper-evident audit log.

TruthLens X does **not** decide guilt, authenticity, or truth. It narrows the search space for a
qualified human examiner and produces a defensible, reproducible record of how each conclusion was
reached.

### 1.1 Product thesis

> A forensic platform that cannot be trusted is worse than no platform at all. Therefore
> **provenance, reproducibility, and honest uncertainty** are first-class features — not
> compliance afterthoughts.

### 1.2 Non-goals (v1)

TruthLens X v1 explicitly does **not**:

- Recover deleted data from raw disk images / unallocated space (no disk-image carving).
- Perform memory (RAM) forensics or mobile device acquisition.
- Crack passwords or perform cryptographic key recovery.
- Provide legally conclusive authenticity determinations.
- Operate on live network traffic (no IDS/PCAP analysis).
- Perform speaker *identification* against a biometric database (privacy/legal exposure).
- Reverse-geocode or enrich without an explicit, logged, opt-in external call.

---

## 2. Users and personas

| ID | Persona | Role | Primary needs |
|---|---|---|---|
| P1 | **Lead Investigator** | `lead_investigator` | Owns cases, assigns evidence, reviews all findings, signs off reports, decides verification status of every AI indicator. |
| P2 | **Forensic Analyst** | `analyst` | Uploads evidence, runs analysis pipelines, triages results, annotates regions/frames, documents methodology. |
| P3 | **Field Investigator** | `investigator` | Submits evidence from the field with minimal friction, tracks custody status, receives findings. |
| P4 | **Reviewer / QA** | `reviewer` | Read-mostly access; audits methodology and verifies that indicators are supported before a report is released. |
| P5 | **Auditor** | `auditor` | Read-only access to audit logs, chain of custody, and integrity status. No access to raw evidence content unless explicitly granted. |
| P6 | **Administrator** | `admin` | User/role management, storage quotas, model registry management, system health, retention policy, licence configuration. |

**Assumption A-01** *(requires approval)*: v1 is **single-organisation** (one tenant) with
case-level access control. True multi-tenancy (per-tenant isolation, per-tenant keys, tenant
quotas) is deferred to v2. See [DECISIONS.md → D-004](./DECISIONS.md).

---

## 3. Functional requirements by module

Requirement IDs are stable and referenced by tests, API docs and the roadmap.
Priority: **M** = Must (v1), **S** = Should (v1 if schedule allows), **C** = Could (v2+).

### Module 1 — Authentication & Authorization

| ID | Req | P |
|---|---|---|
| AUTH-01 | Email/username + password login issuing a short-lived JWT access token (≤15 min) and a rotating refresh token (≤12 h, httpOnly, `Secure`, `SameSite=Strict`, path-scoped). | M |
| AUTH-02 | Passwords hashed with **argon2id** (RFC 9106 low-memory parameters); legacy bcrypt hashes verified and transparently upgraded on successful login. | M |
| AUTH-03 | Password policy: ≥12 chars, breach-list check optional, per-account lockout after N failures with exponential backoff, and admin-unlock path. | M |
| AUTH-04 | Role-based access control with the six roles in §2, plus **case-level membership** (`case_role`) granting least-privilege scoping. | M |
| AUTH-05 | Every protected route enforces both global role *and* case membership in a single dependency (`require_case_access`). Deny-by-default. | M |
| AUTH-06 | Session revocation list (Redis-backed `jti` denylist) supporting logout, admin force-logout, and automatic revocation on password change. | M |
| AUTH-07 | Optional TOTP two-factor enrolment and enforcement (per-role policy, e.g. mandatory for `admin` and `lead_investigator`). | S |
| AUTH-08 | Audit every authentication event: success, failure reason, MFA challenge, token refresh, logout, lockout. | M |
| AUTH-09 | OAuth2/OIDC federation (Keycloak/Entra/Google) behind a feature flag. | C |

### Module 2 — Case management

| ID | Req | P |
|---|---|---|
| CASE-01 | Create/read/update/archive a case with a human-readable, unique, immutable case number (e.g. `TLX-2026-000123`). | M |
| CASE-02 | Case lifecycle: `draft → active → under_review → closed → archived`; transitions validated against allowed-state matrix and recorded in the audit log. | M |
| CASE-03 | Case membership management with per-member `case_role` and time-bounded grants (`valid_from`, `valid_until`). | M |
| CASE-04 | Case-level metadata: jurisdiction, case type, lead investigator, statutory deadline, sensitivity classification (`public/internal/confidential/restricted`). | M |
| CASE-05 | Case dashboard: evidence counts by type, analysis coverage, open findings, verification backlog, integrity exceptions. | M |
| CASE-06 | Closed cases become read-only for non-admins; reopening requires `admin` + justification, both audited. | M |
| CASE-07 | Case tagging and full-text search across title/description/tags. | S |
| CASE-08 | Duplicate-detection warning when a case with a similar title/reference already exists. | C |

### Module 3 — Evidence management

| ID | Req | P |
|---|---|---|
| EVID-01 | Accept evidence via multipart upload (chunked/resumable for files > 100 MB) and via server-side ingest from a mounted intake directory. | M |
| EVID-02 | On ingest, compute **SHA-256** (streaming, never fully buffered in RAM), byte size, and detect true media type from **magic bytes** (not from client-supplied MIME or filename). | M |
| EVID-03 | Store the original in a **content-addressed, write-once** store keyed by SHA-256. Deduplicate identical bytes across cases via a `sha256 → physical_object` mapping while preserving per-case logical evidence records. | M |
| EVID-04 | Originals are **never** overwritten, transcoded, rotated, re-encoded, or thumbnail-modified in place. All derived data lives in a separate `derivatives/` tree. | M |
| EVID-05 | Reject or quarantine uploads exceeding configured size limits, disallowed type allowlists, or files containing embedded executables/scripts where policy forbids them. | M |
| EVID-06 | Evidence metadata: source (upload/intake/API/third-party), submitter, acquisition datetime, acquisition method, device description, original filename (preserved verbatim in DB, never used as a storage path), and free-text notes. | M |
| EVID-07 | Re-verify SHA-256 on demand and on a scheduled integrity sweep; surface any mismatch as a **critical integrity exception** to admins and in the case dashboard. | M |
| EVID-08 | Soft-delete only (legal hold). Hard deletion of an original requires `admin`, a written justification, a second approver, and is permanently audited. | M |
| EVID-09 | Evidence item types: `image`, `video`, `audio`, `document`, `archive`, `text`, `other`. Type drives which analysis pipelines are offered. | M |
| EVID-10 | Download via short-lived signed URLs; each download is an auditable custody event. | M |
| EVID-11 | Optional per-block Merkle root in addition to whole-file SHA-256, enabling partial-integrity proofs for very large files. | C |

### Module 4 — Chain of custody

| ID | Req | P |
|---|---|---|
| CUST-01 | Immutable, append-only custody ledger: every event (`ingested`, `accessed`, `analyzed`, `exported`, `hash_verified`, `custody_transferred`, `held`, `released`, `verification_set`) records actor, timestamp (UTC), IP, user agent, purpose, and the SHA-256 at that moment. | M |
| CUST-02 | Each custody record stores `prev_hash`, forming a **SHA-256 hash chain** across the case; breaking or rewriting history is detectable by re-computing the chain. | M |
| CUST-03 | Chain verification endpoint + scheduled job returning `valid / broken_at_record_id`. | M |
| CUST-04 | Exportable, human-readable custody report (PDF) per evidence item, showing the complete, ordered history including who verified what and when. | M |
| CUST-05 | Custody transfer between users requires acceptance by the recipient (two-party event) for `restricted` evidence. | S |
| CUST-06 | Read-access logging granularity configurable (`all_reads` vs `content_reads_only`) to avoid audit-log explosion on browsing-heavy workflows. | S |

### Module 5 — Image forensics

| ID | Req | P |
|---|---|---|
| IMG-01 | Decode and normalise a *working copy* (never the original) for analysis; record the working-copy derivation parameters. | M |
| IMG-02 | **ELA (Error Level Analysis)** at configurable JPEG quality: produce a heat-map derivative and a per-region anomaly score. Reported as an *indicator of recompression inconsistency*, never as proof of manipulation. | M |
| IMG-03 | **JPEG quantisation-table fingerprinting**: extract DQTs, compare against a curated reference table of known camera/encoder signatures, report closest matches with a distance metric. | M |
| IMG-04 | **Copy-move detection**: block-wise DCT/keypoint matching with geometric verification (RANSAC), returning matched region pairs and a confidence. | S |
| IMG-05 | **Splice/region inconsistency**: per-block noise-variance (wavelet/DCT-residual) and CFA-demosaicing-artefact maps; report outlier regions. | S |
| IMG-06 | **Metadata inconsistency**: EXIF/XMP vs pixel-dimension vs encoder-software cross-checks (e.g. `Software=Adobe Photoshop` present, `DateTime` ≠ `DateTimeDigitized`, missing camera Make/Model). | M |
| IMG-07 | Face and landmark detection; crop and hash face regions to enable cross-evidence person linking (as *candidate* links only). | S |
| IMG-08 | Perceptual hashing (pHash, dHash, aHash, wHash) stored for similarity search and duplicate/near-duplicate detection. | M |
| IMG-09 | Region annotation: analysts can draw polygons/boxes on a derivative and attach notes; annotations are versioned and never modify the original. | S |
| IMG-10 | Invisible/LSB steganography indicator (LSB-plane statistics, chi-square on LSB pairs). Reported as an indicator with a stated false-positive caveat. | C |

### Module 6 — Video forensics

| ID | Req | P |
|---|---|---|
| VID-01 | Probe container/stream metadata (codec, profile, bitrate, fps, duration, timebase, creation time, encoder tag, GOP structure) without re-encoding. | M |
| VID-02 | Deterministic keyframe extraction (scene-change + fixed-interval sampling), each frame stored as a derivative with its exact source PTS/timecode recorded. | M |
| VID-03 | Run the image-forensics suite (ELA, DQT, noise) across sampled frames and aggregate per-frame scores into a temporal anomaly track. | S |
| VID-04 | **Temporal consistency indicators**: inter-frame flicker, inconsistent shadow direction, frame-rate/timestamp discontinuities, duplicate-frame and dropped-frame detection. | S |
| VID-05 | Detect re-encode lineage: container claims one encoder while codec-level parameters indicate another; flag double-compression. | M |
| VID-06 | Object detection + multi-object tracking across frames (see Module 12). | M |
| VID-07 | Audio-track separation for the audio pipeline (see Module 7) — extraction only, never in-place mutation. | M |
| VID-08 | Shot/scene segmentation with a per-shot summary and representative frame. | S |

### Module 7 — Audio forensics

| ID | Req | P |
|---|---|---|
| AUD-01 | Probe audio metadata: codec, sample rate, bit depth, channels, encoder string, duration, and any embedded timestamp fields. | M |
| AUD-02 | **ASR transcription** via Whisper (model size configurable: `tiny`→`large-v3`), producing word-level timestamps, per-segment confidence, detected language and its probability. Transcripts are *derived artifacts*, clearly labelled as machine output. | M |
| AUD-03 | Speaker diarisation producing anonymous speaker labels (`SPK_00`) — **no identity claims**. | S |
| AUD-04 | **Edit/splice indicators**: silence-boundary detection, abrupt spectral-energy discontinuities, phase/ENF-style anomalies, background-noise profile change points. Reported with confidence and explicit limitations. | S |
| AUD-05 | Clipping/saturation and dynamic-range anomaly detection; codec-artefact and bandwidth-limit estimation (e.g. hard spectral cut-off indicating an upstream MP3/AMR transcode). | M |
| AUD-06 | Synthetic-speech (vocoder) *indicators*: unusual high-frequency roll-off, harmonic-structure regularity, GAN-style spectral fingerprints. **Explicitly non-conclusive** — see §5. | S |
| AUD-07 | Waveform + spectrogram derivatives for the UI viewer; interactive region selection tied to transcript segments. | M |
| AUD-08 | Optional redaction of PII in transcripts (name/phone/CNIC patterns) as a separate, reversible-with-log derivative. | C |

### Module 8 — Document forensics

| ID | Req | P |
|---|---|---|
| DOC-01 | PDF structural analysis: version, page count, object counts, linearisation, encryption/permissions flags, XRef layout. | M |
| DOC-02 | **Incremental-update / revision detection**: enumerate saved revisions, list objects changed per revision, and diff the text of each revision. A PDF whose visible content differs from an earlier revision is a high-value finding. | M |
| DOC-03 | Metadata extraction: `Info` dictionary (Author, Creator, Producer, CreationDate, ModDate) and full **XMP** packet; flag producer/creator mismatches and timezone oddities. | M |
| DOC-04 | Embedded-file and attachment extraction (each becomes a child evidence item with its own hash and custody link). | M |
| DOC-05 | Text, table, and image extraction with page/coordinates provenance; OCR fallback for scanned/image-only pages (EasyOCR), with per-page OCR confidence. | M |
| DOC-06 | Font inventory: embedded vs referenced fonts, subset tags, font-family/anomaly cross-checks against the claimed producer application. | S |
| DOC-07 | Annotation, form-field, JavaScript, and launch-action inventory (security-relevant and provenance-relevant). | M |
| DOC-08 | Office documents (DOCX/XLSX/PPTX = OOXML zip): ZIP entry order/timestamps, `docProps/core.xml` & `app.xml`, revision IDs, author history, hidden data. | M |
| DOC-09 | Document-level image forensics: run the image suite on embedded raster images. | S |

### Module 9 — Metadata extraction

| ID | Req | P |
|---|---|---|
| META-01 | Run **ExifTool** as an isolated subprocess on a read-only working copy; capture the full tag set as structured JSON; never let tag values execute or be interpreted as code. | M |
| META-02 | Normalise a curated common schema across types (timestamps → UTC + original offset, GPS, dimensions, device, software, author) while retaining the complete raw tag dump. | M |
| META-03 | Timestamp provenance classification: `device_clock`, `container`, `filesystem`, `embedded_xmp`, `server_supplied` — each with a reliability rating, because these routinely disagree. | M |
| META-04 | Detect metadata stripping/rewriting signals (e.g. all timestamps identical to the second, absent camera identifiers on a JPEG, `Software` indicating an editor). | M |
| META-05 | Metadata comparison between two items: field-level diff with highlighted inconsistencies. | S |
| META-06 | Store the ExifTool version and invocation arguments with every extraction (reproducibility). | M |

### Module 10 — Location intelligence

| ID | Req | P |
|---|---|---|
| GEO-01 | Parse GPS/GNSS tags (decimal, DMS, and video/Audio `GPSPosition` variants) plus altitude, speed, bearing, and `GPSTimeStamp`. | M |
| GEO-02 | Normalise to WGS84 decimal degrees; record datum and coordinate-precision loss; surface precision as an explicit uncertainty radius. | M |
| GEO-03 | Cluster evidence by geographic proximity; produce per-location evidence groups and a map view (self-hosted tiles only — no third-party tile provider in v1). | M |
| GEO-04 | Build movement tracks from ordered GPS points across a case; flag physically implausible transitions (distance/time > plausible speed) as **data-quality indicators**, not deception findings. | S |
| GEO-05 | Reverse geocoding: **offline** gazetteer (e.g. GeoNames dump) by default; any online provider call is opt-in per deployment, rate-limited, logged, and SSRF-guarded. | M |
| GEO-06 | Plausibility cross-checks: claimed capture time vs sunrise/sunset at the coordinate vs shadow direction in the image. Reported as an *indicator* with stated error bounds. | C |
| GEO-07 | Privacy: location data is personal data — access gated by case membership and every read audited; coordinate display can be deliberately truncated (geographic fuzzing) for lower-privilege roles. | M |

### Module 11 — Deepfake / synthetic-media analysis

| ID | Req | P |
|---|---|---|
| DF-01 | **Never** emit a binary "real/fake" verdict. Emit a set of independently-scored *indicators*, each with confidence, the model/algorithm that produced it, and a plain-language limitation statement. | M |
| DF-02 | Face-focused indicators: blending/edge inconsistency around face boundaries, unnatural landmark symmetry, eye/teeth/glass-reflection artefacts, frequency-domain artefacts in the face crop. | M |
| DF-03 | Global frequency indicators: DCT/FFT spectral analysis for GAN/CNN upsampling fingerprints (characteristic spectral peaks and grid artefacts). | M |
| DF-04 | Video temporal indicators: identity-flicker across frames, inconsistent head-pose/face-crop jitter, lip-motion vs audio-energy correlation mismatch. | S |
| DF-05 | Audio indicators per AUD-06, correlated with the video track when both exist. | S |
| DF-06 | Aggregate indicator set into a single **advisory score** (0–100) with a mandatory confidence interval and an explicit `requires_human_verification = true` flag that cannot be disabled. | M |
| DF-07 | Every deepfake result ships with a fixed disclaimer string rendered in the UI *and* in the PDF report. | M |
| DF-08 | Record model name, version, weights checksum, framework version, GPU/CPU execution device, inference parameters, and seed where applicable — for every single invocation. | M |
| DF-09 | Maintain a labelled internal evaluation set so the platform can report its **own measured performance** (TPR/FPR on that set) rather than quoting vendor marketing numbers. | S |
| DF-10 | Support "known-source" whitelisting: media from a verified camera/publisher can be marked with provenance signals (e.g. C2PA manifest if present) which are reported factually. | C |

### Module 12 — Object detection & tracking

| ID | Req | P |
|---|---|---|
| OBJ-01 | Run configurable detectors on images and sampled video frames; store per-detection class, confidence, bbox, and the exact model version. | M |
| OBJ-02 | **Multi-object tracking** across frames (ByteTrack-style association) producing stable track IDs, track lifespans, and per-track class vote. | M |
| OBJ-03 | Detection results are queryable: "all evidence containing a `person` with confidence ≥ 0.6", "all tracks crossing region X". | M |
| OBJ-04 | Overlay rendering as a derivative (never on the original) with a toggleable per-class visibility in the UI. | M |
| OBJ-05 | Class taxonomy is configurable per deployment (COCO-80 default) and the mapping is versioned. | S |
| OBJ-06 | Track-level aggregation: first/last seen timecode, path polyline, mean speed in px/s, occlusion segments. | S |

### Module 13 — Licence-plate recognition (ALPR)

| ID | Req | P |
|---|---|---|
| ALPR-01 | Two-stage pipeline: plate detection (dedicated detector or general detector + aspect/region heuristics) then character recognition via OCR with plate-charset constraints. | M |
| ALPR-02 | Confidence at both stages; reject and flag candidates below threshold rather than guessing. | M |
| ALPR-03 | **Region-aware plate formats**: configurable regex/format validators per jurisdiction (default set must be explicitly configured for the deployment country — e.g. Pakistan's `LLL-DDDD` / province-token formats). An unmatched format is reported as "unresolved", not silently coerced. | M |
| ALPR-04 | Ambiguous-character reporting: present the top-N candidate readings with per-character confidence instead of a single string. | M |
| ALPR-05 | Plate occurrence linking: group identical/likely-identical plates across a case, with the evidence items, frames, and timecodes. | M |
| ALPR-06 | **No automatic external registry lookups in v1.** Any integration with a vehicle-ownership database is out of scope and, if ever added, must be an explicit, authorised, logged, jurisdiction-approved integration. | M |
| ALPR-07 | Privacy controls: plate masking on shared/report derivatives where policy requires, with the unmasked original preserved and access-controlled. | S |

### Module 14 — Evidence comparison

| ID | Req | P |
|---|---|---|
| CMP-01 | Pairwise comparison workspace for image↔image, video↔video, audio↔audio, document↔document, and cross-type (image↔video frame). | M |
| CMP-02 | Comparison methods, each with a documented interpretation: exact-hash, perceptual-hash distance, feature matching (ORB/AKAZE + RANSAC homography with inlier count), colour/edge histograms, template matching, embedding cosine similarity, metadata field diff, audio cross-correlation and spectral similarity, document text diff. | M |
| CMP-03 | Every comparison stores inputs, method, method version, parameters, numeric score, a normalised similarity band, and a human-readable interpretation with limitations. | M |
| CMP-04 | Side-by-side and overlay visualisation with synchronised pan/zoom; difference heat-maps as derivatives. | M |
| CMP-05 | Bulk comparison ("compare this item against all case images") queued as a background job with progress. | S |
| CMP-06 | Comparisons are saveable as named artifacts and citable in reports. | M |

### Module 15 — Evidence relationship graph

| ID | Req | P |
|---|---|---|
| GRAPH-01 | Typed, directed edges between entities (`evidence`, `person_candidate`, `location`, `device`, `vehicle_plate_candidate`, `event`, `document_subject`) with `origin = manual | inferred` and a confidence for inferred edges. | M |
| GRAPH-02 | Inferred edges are generated by pipelines (perceptual-hash similarity, shared GPS, shared device metadata, same plate string, same face-cluster, transcript mention) and are **always** marked inferred with the producing rule and version. | M |
| GRAPH-03 | Interactive graph view: filter by type/confidence/origin, expand/collapse neighbourhoods, highlight paths between two nodes, pin and annotate. | M |
| GRAPH-04 | Analyst can promote an inferred edge to `confirmed` or mark it `rejected` (with reason) — both audited. | M |
| GRAPH-05 | Export graph as JSON, GraphML, and as a static image for reports. | S |
| GRAPH-06 | Cycle/duplicate-edge handling and a stable layout (deterministic seeded layout so screenshots are reproducible). | S |

### Module 16 — Investigation timeline

| ID | Req | P |
|---|---|---|
| TIME-01 | Timeline events from: metadata timestamps, GPS track points, transcript segments, detected object/track first-seen, document revision dates, analysis completion times, and **analyst-entered events**. | M |
| TIME-02 | Every event carries: `occurred_at` (with precision), `timezone_confidence`, `source_evidence_id`, `derivation` (device_claimed / filesystem / container / analyst_asserted / inferred), and a reliability rating. | M |
| TIME-03 | Explicitly distinguish *claimed* time from *corroborated* time. Conflicting timestamps for the same logical event are shown side-by-side, never silently merged. | M |
| TIME-04 | Zoomable timeline (decade → second) with lanes by evidence type, filtering, and event grouping. | M |
| TIME-05 | Gap detection: highlight periods with no evidence, and periods where evidence timestamps are implausibly clustered. | S |
| TIME-06 | Timeline export (PDF/CSV/JSON) for reports. | M |

### Module 17 — AI investigation assistant

| ID | Req | P |
|---|---|---|
| AI-01 | Case-scoped assistant that answers questions **only** from retrieved platform data (RAG over case evidence metadata, findings, transcripts, timeline) — never from unconstrained parametric memory about the case. | M |
| AI-02 | Every answer includes inline citations to the specific evidence items/findings used, and a "not supported by case data" response when retrieval is insufficient. | M |
| AI-03 | Assistant **cannot** set verification status, cannot alter custody records, and cannot delete anything. It can propose next investigative steps, which an analyst must accept explicitly. | M |
| AI-04 | Prompt + retrieval context + model + version + temperature + token counts logged for every interaction (reproducibility and audit). | M |
| AI-05 | Fixed system-prompt guardrails: no guilt/innocence conclusions, no legal advice, no fabrication of evidence, mandatory uncertainty language. | M |
| AI-06 | Local/self-hosted model support (e.g. an Ollama/vLLM endpoint) as the default deployment mode; external API providers opt-in per deployment because case data is sensitive. | M |
| AI-07 | Suggested-action generation ("run ELA on the 4 images lacking it", "3 findings await verification") derived from real queryable state, not free-form invention. | S |
| AI-08 | Full conversation persistence per case, exportable, with a per-message "regenerate with citation view". | S |

### Module 18 — Evidence similarity search

| ID | Req | P |
|---|---|---|
| SIM-01 | Vector similarity search over embeddings (image CLIP-style, document text, audio) using **pgvector**, with the embedding model name/version stored per vector. | M |
| SIM-02 | Search by example ("find items like this one"), by text ("night-time street scene with a white sedan"), and by attribute filters combined with vector similarity (hybrid search). | M |
| SIM-03 | Near-duplicate detection across the whole store with a configurable distance threshold and a review queue. | M |
| SIM-04 | Every similarity result reports distance, normalised score, the embedding model version, and the caveat that similarity ≠ same source. | M |
| SIM-05 | Re-embedding job when a model version changes, keeping old vectors queryable during migration (versioned vector sets). | S |
| SIM-06 | Index maintenance: HNSW index parameters recorded; recall spot-checks against brute-force on a sample set as a CI quality gate. | S |

### Module 19 — PDF investigation reports

| ID | Req | P |
|---|---|---|
| RPT-01 | Generate structured PDF reports (ReportLab): cover, executive summary, scope, methodology, evidence inventory with hashes, findings per module, comparison results, timeline, graph image, AI-indicator section with disclaimers, verification status table, limitations, examiner attestation, appendices. | M |
| RPT-02 | Report templates: `full_investigation`, `evidence_summary`, `custody_only`, `deepfake_advisory`, `custom` (section picker). | M |
| RPT-03 | Every AI-derived statement in the report carries its indicator framing, confidence, model version, and the disclaimer. Reports must never state an AI indicator as fact. | M |
| RPT-04 | Report generation is a background job; the resulting PDF is stored as a derivative with its own SHA-256, recorded generation parameters, and the exact set of source entity IDs + their hash at generation time (a reproducible "report manifest"). | M |
| RPT-05 | Versioning: regenerating a report creates a new version; prior versions remain retrievable. Watermark (`DRAFT` / `FINAL` / `COPY n OF m`) and optional classification banner. | M |
| RPT-06 | Digital signature support: platform-level signature block, and optional cryptographic signing of the PDF bytes (deployment-configured). | S |
| RPT-07 | Deterministic output where achievable (stable ordering, fixed fonts, no run-timestamp-only diffs) so that regenerating the same manifest yields byte-identical or near-identical output. | S |

### Module 20 — Audit logs

| ID | Req | P |
|---|---|---|
| AUD-01 | Append-only audit log for: auth events, RBAC changes, case lifecycle, evidence CRUD, every original-file access, analysis launches, verification decisions, report generation, admin actions, config changes. | M |
| AUD-02 | Audit records are hash-chained (per-tenant/global sequence) and periodically anchored; no update or delete path exists in the ORM (enforced by DB permissions and code review). | M |
| AUD-03 | Structured fields: `actor_id`, `actor_role`, `action`, `resource_type`, `resource_id`, `case_id`, `result`, `reason`, `ip`, `user_agent`, `request_id`, `metadata JSONB`, `prev_hash`, `record_hash`. | M |
| AUD-04 | Search, filter (actor/action/date/case/resource), and export (CSV/JSON/PDF) with the export itself audited. | M |
| AUD-05 | Application logs (structured JSON) separate from audit logs, with correlation via `request_id`; PII redaction in application logs. | M |
| AUD-06 | Retention: audit logs outlive their cases; archival to cold storage with a documented restore procedure. | S |

### Module 21 — Administration dashboard

| ID | Req | P |
|---|---|---|
| ADM-01 | User management: create/deactivate, role assignment, password reset, MFA reset, force-logout, impersonation **disabled by default** (and always audited if enabled). | M |
| ADM-02 | Case oversight: all cases, storage per case, activity, integrity exceptions, verification backlog. | M |
| ADM-03 | Model registry management: register/retire models, pin active versions per pipeline, view invocation stats, and see measured performance on the internal evaluation set. | M |
| ADM-04 | Queue and worker monitoring: per-queue depth, task success/failure rates, retries, long-running tasks, dead-letter queue, and manual retry/cancel. | M |
| ADM-05 | Storage and quota management, integrity-sweep status, backup status, licence flags (e.g. AGPL component enablement). | M |
| ADM-06 | System configuration UI for a curated allowlist of runtime-adjustable settings (all others stay environment-driven). | S |
| ADM-07 | Health and dependency status (DB, Redis, workers, GPU, external providers) with an unauthenticated `/healthz` for orchestrators and an authenticated detailed status page. | M |

### Module 22 — Security & monitoring

| ID | Req | P |
|---|---|---|
| SEC-01 | Enforce the controls in [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md): TLS everywhere, secure headers, CSRF protection, rate limiting, request-size limits, CORS allowlist, SSRF egress filtering. | M |
| SEC-02 | Secrets exclusively from environment/secret store; no secret ever in code, logs, error messages, DB rows, or reports. Startup fails closed if required secrets are missing. | M |
| SEC-03 | Structured logging with `request_id`, log levels per module, error capture with stack traces (never returned to clients), and a metrics endpoint (`/metrics`, Prometheus format). | M |
| SEC-04 | Dependency and container scanning in CI (fail the build on critical findings), SBOM generation, and image digest pinning. | M |
| SEC-05 | Detection alerts: repeated auth failures, hash-chain break, integrity mismatch, privilege escalation attempts, unusual bulk export, direct-original access outside allowed paths. | M |
| SEC-06 | Backup verification: scheduled restore test of a sample evidence item and DB snapshot, with results recorded. | S |
| SEC-07 | Security event export to an external SIEM via a documented webhook/syslog sink. | C |

---

## 4. Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-01 | **Performance** | Ingest throughput ≥ 50 MB/s per worker (hash-bound). API p95 < 300 ms for metadata reads, < 800 ms for graph/timeline queries at ≤ 50k events. |
| NFR-02 | **Scalability** | Horizontally scale stateless API replicas and Celery workers independently. Target: 100 concurrent investigators, 200 active cases, 1M evidence items, 50 TB store (validated by design review + load test at M14). |
| NFR-03 | **Availability** | 99.5% for the API in business hours (single-node deployments explicitly documented as best-effort). Analysis queues may lag without affecting read availability. |
| NFR-04 | **Durability** | Originals: ≥ 2 copies (primary store + backup), verified monthly by integrity sweep. RPO ≤ 24 h, RTO ≤ 4 h on a single-node deployment. |
| NFR-05 | **Reproducibility** | Any analysis can be re-run with the recorded model version and parameters and produce the same result (fixed seeds, pinned model weights by checksum, recorded library versions). |
| NFR-06 | **Auditability** | 100% of evidence-content access and verification decisions are logged and hash-chained. |
| NFR-07 | **Portability** | Runs on a single Linux host with Docker Compose; no mandatory proprietary cloud service. Optional cloud object storage behind an adapter interface. |
| NFR-08 | **Usability** | A trained analyst can ingest → analyse → verify → export a report for a 10-item case within 15 minutes of wall-clock time (excluding queued GPU work). |
| NFR-09 | **Accessibility** | WCAG 2.1 AA on all analyst-facing screens; keyboard-navigable graph and timeline; colour-blind-safe palettes for heat-maps. |
| NFR-10 | **Maintainability** | ≥ 80% backend line coverage on new code; every module independently testable with no live model weights required (stub/fake engines). |
| NFR-11 | **Internationalisation** | UI English (v1) with i18n scaffolding in place; Urdu/Arabic RTL support is a v2 item. OCR language packs configurable. |
| NFR-12 | **Data protection** | Location, face-cluster, plate, and transcript data treated as personal data: minimised, access-controlled, audited, retention-bounded, and exportable/deletable under a documented process. |

---

## 5. AI responsibility policy (binding)

This section is normative. It overrides any conflicting convenience elsewhere in the product.

**AR-1 — Indicators, not facts.** Every AI/algorithmic output is labelled an *indicator*. UI copy,
API field names (`indicator`, `advisory_score`, `confidence`), and report templates must use
indicator language. The words "confirmed", "proven", "verified as fake/authentic" may appear only
in reference to a *human* verification action.

**AR-2 — Mandatory provenance.** No result may be persisted or displayed without: producing
algorithm/model name, model version, weights checksum where applicable, library versions,
invocation parameters, execution device, and timestamp.

**AR-3 — Mandatory uncertainty.** Where a numeric confidence is meaningful, it must be shown
*alongside* a plain-language interpretation of what that confidence does and does not mean. Where
confidence is not meaningful (e.g. deterministic metadata parsing), the UI must say so rather than
inventing a number.

**AR-4 — Mandatory limitations.** Each analysis type has a fixed, versioned limitations statement
rendered next to its results and embedded in reports. Examples:

- *ELA*: "Error Level Analysis highlights recompression inconsistency. Legitimate operations
  (cropping, saving, platform re-encoding, screenshotting) produce the same signature. It does not
  establish manipulation."
- *Deepfake indicators*: "No deepfake detector is reliable in the wild. Authentic media that has
  been compressed, resized, or transcoded by messaging platforms frequently produces these
  indicators, and high-quality synthetic media frequently does not. This output must not be used as
  the sole basis for any conclusion."
- *ALPR*: "Character recognition degrades sharply with motion blur, low resolution, oblique angle,
  glare, and non-standard plate formats. Top-N candidates are shown; human confirmation is
  required."
- *ASR*: "Transcription errors are common with noise, accents, overlapping speakers, and
  low-bitrate audio. Timestamps are approximate."

**AR-5 — Human verification state.** Every finding has `verification_status ∈ {unverified,
confirmed, rejected, inconclusive}`, `verified_by`, `verified_at`, `verification_notes`. Reports
must print the status; unverified findings are visually distinct everywhere.

**AR-6 — No fabricated metrics.** The platform must never quote an accuracy figure it has not
measured on a disclosed dataset. Where third-party benchmarks are referenced, they are labelled as
vendor-reported, with the dataset named.

**AR-7 — Fail visibly.** If a model is unavailable, out of memory, or returns an error, the
pipeline records a `failed` result with the error class. It must never substitute a default or
"looks clean" result.

**AR-8 — No automated legal conclusions.** No feature may output a determination of guilt,
liability, identity, or legal admissibility.

> **Legal note.** TruthLens X is engineering tooling. It is not legal advice, and admissibility of
> its output depends on jurisdiction, examiner qualification, and procedure. In Pakistan, electronic
> evidence is addressed by the Prevention of Electronic Crimes Act 2016 and the Qanun-e-Shahadat
> Order 1984 (as amended); deployment owners must obtain local legal counsel on handling,
> retention, and presentation of digital evidence. Nothing in this document establishes legal
> compliance.

---

## 6. End-to-end user journeys (acceptance-level)

### J1 — Ingest and preserve
Analyst uploads 12 items to case `TLX-2026-000123`. Each receives an evidence ID, SHA-256,
detected type, size, and a custody `ingested` event. Originals land in the content-addressed store.
*Pass when*: hashes match an independent `sha256sum` run; re-upload of the same bytes deduplicates
physically but creates a distinct logical evidence record; original bytes are bit-identical on
download.

### J2 — Analyse
Analyst selects 6 images and launches ELA + metadata + deepfake-indicator pipelines. Jobs queue,
progress streams to the UI, and results appear with model versions and confidence.
*Pass when*: every result carries AR-2 provenance; a failed job shows a `failed` state with a
retry; no result is shown as a verdict.

### J3 — Verify
Lead investigator reviews 9 unverified findings, confirms 3, rejects 1 (with reason), leaves 5
unverified. *Pass when*: statuses persist, the rejecting reason is mandatory, and each change is a
custody/audit event attributable to the actor.

### J4 — Correlate
Analyst compares two images, links them in the graph with an inferred edge from perceptual-hash
similarity, and confirms the edge. *Pass when*: comparison stores method + version + score +
interpretation; the graph shows `origin=inferred → confirmed` with the actor recorded.

### J5 — Report
Lead generates a `full_investigation` PDF. *Pass when*: report contains evidence hashes, findings
with verification status, AR-4 limitation text, the report manifest with source entity IDs, its own
SHA-256, and a version number; regeneration from the same manifest produces equivalent output.

### J6 — Audit
Auditor filters the log by evidence item and exports a custody report, then verifies the hash chain.
*Pass when*: chain verification returns `valid`; the export event itself appears in the log; no
audit record can be modified through any API.

---

## 7. Success criteria for v1

| # | Criterion | Measure |
|---|---|---|
| S1 | Evidence integrity is provable | 100% of items hash-verified on demand; integrity sweep catches injected corruption in tests |
| S2 | Custody is tamper-evident | Hash-chain verification passes; a manually tampered row is detected in tests |
| S3 | AI honesty is enforced by code | Lint/test asserts every AI result schema includes provenance + limitations + verification fields; zero "verdict" wording in UI/report strings |
| S4 | Modules are independently testable | All 22 modules have automated tests that run without GPU and without downloaded model weights |
| S5 | Platform is deployable | `docker compose up` produces a working system on a clean host per DEPLOYMENT_GUIDE |
| S6 | Documentation is complete | All 9 docs current, API spec matches implemented routes (contract test), README accurate |

---

## 8. Open product questions

Tracked formally in [DECISIONS.md](./DECISIONS.md). The highest-impact ones:

1. **AGPL components** — Ultralytics YOLO and PyMuPDF are AGPL-3.0; ExifTool is GPL-3.0. Are these
   acceptable for your intended distribution/hosting model, or should the permissive alternative
   stack (torchvision/mmdetection detectors, pikepdf + pdfminer.six, subprocess-isolated ExifTool)
   be the default? → **D-001, D-002, D-003**
2. **Deployment target** — single on-prem Linux host with optional GPU, or cloud-hosted? Drives
   storage adapter, backup design and cost model. → **D-005**
3. **AI assistant model** — self-hosted local LLM (privacy-preserving, needs hardware) vs external
   API (easy, sends case data off-box). → **D-007**
4. **Multi-tenancy** — confirm single-organisation v1. → **D-004**
5. **Encryption at rest for originals** — rely on disk/volume encryption, or implement
   application-level envelope encryption (adds key-management complexity and recovery risk)? → **D-006**

---

*End of MASTER_PRD.md — v0.1.0 DRAFT. Nothing in this document has been implemented yet.*
