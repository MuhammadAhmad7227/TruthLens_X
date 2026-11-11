# TruthLens X — API Specification

| | |
|---|---|
| **Document ID** | TLX-DOC-004 |
| **Version** | 0.1.0 (DRAFT — pending approval) |
| **Base path** | `/api/v1` |
| **Transport** | HTTPS only (TLS 1.2+); HTTP is redirected |
| **Formats** | Request/response `application/json`; uploads `multipart/form-data`; downloads `application/octet-stream`; errors `application/problem+json` |
| **Contract source of truth** | The generated OpenAPI 3.1 document; **this file is the design spec, the OpenAPI export is the contract** and TS types are generated from it |

---

## 1. Conventions

### 1.1 URL design

- Nouns, plural, kebab-free snake-free: `/cases`, `/cases/{case_id}/evidence`.
- Case-scoped resources are **always nested under `/cases/{case_id}/`** so that the ACL check has a
  single, unavoidable entry point. Flat aliases are not offered.
- Non-CRUD operations use a `:verb` suffix (custom-method style): `/evidence/{id}:verify-integrity`,
  `/reports/{id}:regenerate`.
- IDs are UUIDs in path params. Human identifiers (`case_number`, `evidence_number`) are accepted on
  dedicated lookup endpoints (`/cases:by-number/{case_number}`), never overloaded onto `{id}`.
- Max URL depth 4; deeper nesting uses query filters.

### 1.2 Methods & idempotency

| Method | Semantics | Idempotent |
|---|---|---|
| GET | read, no side effects except audit logging of content access | yes |
| POST | create, or execute a custom verb | **no** — unless `Idempotency-Key` is supplied |
| PATCH | partial update (JSON Merge Patch semantics; `null` clears an optional field) | yes |
| PUT | only for full replacement of small config resources | yes |
| DELETE | soft delete | yes |

**`Idempotency-Key`** (required on evidence upload, accepted on job creation): a client-generated
UUID. The server stores `(key, user, endpoint) → response` for 24 h; a replay returns the stored
response with header `Idempotency-Replayed: true`. A key reused with a different body returns `409`.

### 1.3 Authentication

```
Authorization: Bearer <access_token>
```

Access tokens: JWT, **15 min** TTL, claims `sub`, `jti`, `roles`, `sid`, `iat`, `exp`, `iss`, `aud`.
Refresh: `POST /auth/refresh` with the httpOnly cookie `tlx_refresh` (path-scoped to `/api/v1/auth`).
Refresh rotation with reuse detection — presenting a rotated token revokes the whole family and
emits a security audit event.

Unauthenticated endpoints (exhaustive): `GET /healthz`, `GET /readyz`, `POST /auth/login`,
`POST /auth/refresh`, `POST /auth/mfa/verify`, `GET /openapi.json`. Everything else requires a valid
token **and** passes the case ACL check.

### 1.4 Error model — RFC 9457 `application/problem+json`

```json
{
  "type": "https://errors.truthlens.local/evidence/integrity-mismatch",
  "title": "Evidence integrity verification failed",
  "status": 409,
  "detail": "Computed SHA-256 does not match the recorded value for evidence TLX-2026-000123-E004.",
  "instance": "/api/v1/cases/9c1f.../evidence/4b7a...:verify-integrity",
  "request_id": "req_01HXYZ...",
  "error_code": "EVIDENCE_INTEGRITY_MISMATCH",
  "field_errors": [],
  "remediation": "Do not use this item for analysis. Contact an administrator; the item has been flagged and quarantined."
}
```

Stable machine codes (never parsed from `title`):

| HTTP | `error_code` | Meaning |
|---|---|---|
| 400 | `VALIDATION_ERROR` | body/query failed schema validation (`field_errors` populated) |
| 400 | `UNSUPPORTED_EVIDENCE_TYPE` | pipeline not applicable to this item type |
| 401 | `UNAUTHENTICATED` / `TOKEN_EXPIRED` / `MFA_REQUIRED` | |
| 403 | `FORBIDDEN_ROLE` / `FORBIDDEN_CAPABILITY` / `CASE_CLOSED` / `LEGAL_HOLD` (423) | deny-by-default ACL outcomes where the resource's existence is already known to the caller |
| 404 | `NOT_FOUND` | **also returned for case-access denial** — existence itself must not leak |

> **⚠️ Corrected during ratification (conflict #4, [ADR-0004](adr/ADR-0004-single-organisation-capability-rbac.md)).**
> This table originally listed `FORBIDDEN_CASE_ACCESS` under **403**, which contradicted
> `SECURITY_ARCHITECTURE.md` §5.5 (a denial must not confirm that the case exists) **and** §9 (such
> denials must be detectable for insider-threat alerting). Resolved in favour of security:
>
> * the HTTP status is **404** and the client-visible `error_code` is **`NOT_FOUND`**, so a denial is
>   indistinguishable from a missing resource;
> * the server separately records **`audit_reason = FORBIDDEN_CASE_ACCESS`** in the audit log, which
>   is where the alerting requirement is satisfied.
>
> `FORBIDDEN_CASE_ACCESS` is therefore an **audit reason, not a client-facing error code.** It never
> appears in a response body.
| 409 | `EVIDENCE_INTEGRITY_MISMATCH` / `CONFLICT` / `IDEMPOTENCY_KEY_REUSED` / `INVALID_STATE_TRANSITION` | |
| 413 | `PAYLOAD_TOO_LARGE` | exceeds `MAX_UPLOAD_BYTES` |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | magic bytes not in the allowlist |
| 422 | `ENGINE_UNAVAILABLE` / `MODEL_NOT_LOADED` | honest failure, not "no findings" (AR-7) |
| 423 | `LEGAL_HOLD` | mutation blocked by legal hold |
| 429 | `RATE_LIMITED` | `Retry-After` set |
| 500 | `INTERNAL_ERROR` | `request_id` is the only correlation handle; no stack traces |
| 503 | `DEPENDENCY_UNAVAILABLE` | DB/Redis/worker queue down |

### 1.5 Pagination, filtering, sorting

Cursor pagination is the default (stable under concurrent writes); offset is available for admin tables only.

```
GET /api/v1/cases/{case_id}/evidence?limit=50&cursor=eyJpZCI6IjRiN2EiLCJjcmVhdGVkX2F0IjoiLi4uIn0
```

```json
{
  "data": [ ... ],
  "page": {
    "limit": 50,
    "next_cursor": "eyJpZCI6IjVjOGIi...",
    "prev_cursor": null,
    "total_count": 1284,
    "total_count_exact": false
  }
}
```

- `limit` default 50, max 200 (max 1000 for admin listings).
- `cursor` is an opaque base64url of `(sort_key, id)`; it is validated and rejected with
  `VALIDATION_ERROR` if tampered — it is **never** trusted as authorisation.
- `total_count_exact=false` when the count is an estimate from a capped scan (keeps list endpoints fast).
- Filtering: `filter[field]=value`, `filter[field]=in:a,b,c`, `filter[created_at]=gte:2026-01-01`.
  Allowed filter fields are declared per endpoint in the OpenAPI schema — arbitrary column filtering
  is **not** supported (prevents injection and query explosion).
- Sorting: `sort=-created_at,+evidence_number`. Allowlist per endpoint.
- `fields=evidence_number,item_type,status` for sparse fieldsets on large listings.

### 1.6 Standard response envelope

List endpoints use `{ "data": [...], "page": {...} }`. Single-resource endpoints return the resource
directly (no wrapper) so it matches the OpenAPI schema exactly. Job-creating endpoints return `202`
with:

```json
{ "job_id": "...", "status": "queued", "status_url": "/api/v1/cases/{c}/jobs/{j}",
  "progress_url": "/api/v1/cases/{c}/jobs/{j}/events" }
```

### 1.7 Headers

| Header | Direction | Purpose |
|---|---|---|
| `X-Request-ID` | both | generated if absent, echoed always; correlates logs, audit, tasks |
| `Idempotency-Key` | request | see §1.2 |
| `ETag` / `If-None-Match` | both | on evidence metadata, results, reports (`304` support) |
| `Content-SHA256` | response | on any endpoint returning original or derivative bytes |
| `X-Content-Type-Options` | response | `nosniff` |
| `Retry-After` | response | with `429`/`503` |
| `X-RateLimit-*` | response | `limit`, `remaining`, `reset` |
| `Content-Disposition` | response | downloads; filename is the *sanitised* name, RFC 5987 encoded |

### 1.8 Versioning & compatibility

- Path version `/api/v1`. Breaking changes → `/api/v2`; v1 supported for one full release cycle.
- **Additive** changes (new optional field, new enum value, new endpoint) are non-breaking and may
  ship in place. Clients must ignore unknown fields.
- Enum values are documented per endpoint; adding a value is accompanied by a client-visible
  `x-enum-additions` changelog entry.
- A CI **contract test** diffs the generated OpenAPI against the committed baseline and fails on
  unannounced breaking changes.

---

## 2. Endpoint map

Legend: 🔒 = requires a valid token **and** the named case capability; 👑 = requires `admin`;
⚖ = requires the `verify_finding` capability; 📝 = writes an audit record.

Every route declares its required capability via `x-capability` in the OpenAPI document, and a
CI-blocking test asserts that declaration matches the expected matrix for **100% of routes** — a new
route without a declared capability cannot be merged (ADR-0004, TESTING_STRATEGY §7.1). Case-scoped
resources the caller cannot access return **`404`**, not `403`, so existence is not enumerable.
Frontend visibility is never a security control: the server re-evaluates every request.

### 2.1 Auth & session

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/auth/login` | public | Email/password → access token + refresh cookie. Returns `MFA_REQUIRED` when enrolled. |
| POST | `/auth/mfa/verify` | public+challenge | TOTP verification step. |
| POST | `/auth/refresh` | cookie | Rotate refresh token, issue access token. |
| POST | `/auth/logout` | 🔒📝 | Revoke current session family. |
| POST | `/auth/logout-all` | 🔒📝 | Revoke all sessions for the user. |
| GET | `/auth/me` | 🔒 | Profile, global role, case memberships, capability set, MFA state. |
| PATCH | `/auth/me` | 🔒📝 | Update own `full_name`; password change requires current password. |
| POST | `/auth/password/change` | 🔒📝 | Revokes all refresh tokens on success. |
| POST | `/auth/mfa/enrol` · `/auth/mfa/confirm` · `DELETE /auth/mfa` | 🔒📝 | TOTP lifecycle (QR secret returned once, encrypted at rest). |

### 2.2 Cases

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/cases` | 🔒 | Cases the caller can access; filters `status`, `lead`, `tag`, `q`, `sensitivity`. |
| POST | `/cases` | 🔒 (≥`investigator`)📝 | Create case; caller becomes `owner` member. |
| GET | `/cases:by-number/{case_number}` | 🔒 | Lookup by human identifier. |
| GET | `/cases/{case_id}` | 🔒 | Case detail + computed counters. |
| PATCH | `/cases/{case_id}` | 🔒 `owner/lead`📝 | Update metadata. Closed cases reject writes (`CASE_CLOSED`). |
| POST | `/cases/{case_id}:transition` | 🔒📝 | `{to: "under_review", reason}` — validated against the allowed-state matrix. |
| GET | `/cases/{case_id}/dashboard` | 🔒 | Evidence counts, analysis coverage, verification backlog, integrity exceptions, storage used. |
| GET · POST · PATCH · DELETE | `/cases/{case_id}/members` | 🔒 `owner/lead`📝 | Membership + capability grants. |
| GET | `/cases/{case_id}/activity` | 🔒 | Recent audit-derived activity feed (paginated). |

### 2.3 Evidence

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/cases/{case_id}/evidence:upload` | 🔒📝 | Multipart chunk upload; `Idempotency-Key` **required**; returns `202` + `evidence_id`. |
| POST | `/cases/{case_id}/evidence:upload-session` | 🔒 | Init resumable upload → `{upload_id, chunk_size, expiry}`. |
| PUT | `/cases/{case_id}/evidence:upload-session/{upload_id}` | 🔒 | Upload chunk `Content-Range`. |
| POST | `/cases/{case_id}/evidence:upload-session/{upload_id}:complete` | 🔒📝 | Finalise → enqueue `finalize_ingest`. |
| GET | `/cases/{case_id}/evidence` | 🔒 | Inventory; filters `item_type`, `status`, `integrity_status`, `submitter`, `acquired_at`, `tag`, `q`. |
| GET | `/cases/{case_id}/evidence/{evidence_id}` | 🔒 | Full record incl. hashes, timestamps, custody summary, current results. |
| PATCH | `/cases/{case_id}/evidence/{evidence_id}` | 🔒📝 | Editable metadata only (notes, tags, acquisition fields). Hash/type/size are immutable. |
| DELETE | `/cases/{case_id}/evidence/{evidence_id}` | 🔒📝 | Soft delete; blocked by `legal_hold` unless justification + `admin`. |
| POST | `/cases/{case_id}/evidence/{evidence_id}:verify-integrity` | 🔒📝 | Enqueue/execute SHA-256 re-verification → `{status, expected, actual}`. |
| GET | `/cases/{case_id}/evidence/{evidence_id}:download-url` | 🔒📝 | Short-lived signed URL (default 120 s, max 900 s); `purpose` query param **required**. |
| GET | `/cases/{case_id}/evidence/{evidence_id}/content` | 🔒📝 | Direct byte stream (rate-limited; audited as content access). |
| GET | `/cases/{case_id}/evidence/{evidence_id}/derivatives` | 🔒 | Artifact list (thumbnails, heatmaps, frames, transcripts). |
| GET | `/cases/{case_id}/derivatives/{derivative_id}/content` | 🔒 | Serve a derivative (not the original). |
| GET | `/cases/{case_id}/evidence/{evidence_id}/custody` | 🔒 | Full ordered custody chain + `chain_valid` flag. |
| GET · POST | `/cases/{case_id}/evidence/{evidence_id}/annotations` | 🔒📝 | Region annotations (versioned). |
| POST | `/cases/{case_id}/evidence/{evidence_id}:transfer-custody` | 🔒📝 | `{recipient_id, purpose}` → pending acceptance. |
| POST | `/cases/{case_id}/evidence/{evidence_id}:accept-custody` | 🔒📝 | Recipient accepts (CUST-05). |

### 2.4 Metadata

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/cases/{case_id}/evidence/{evidence_id}/metadata` | 🔒 | Normalised + raw tag dump, extractor/version/args, stripping signals. |
| POST | `/cases/{case_id}/evidence/{evidence_id}/metadata:reextract` | 🔒📝 | Re-run with a specified extractor version. |
| GET | `/cases/{case_id}/evidence/{evidence_id}/metadata/diff?other={id}` | 🔒 | Field-level metadata diff with inconsistency highlights. |

### 2.5 Analysis jobs & results

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/cases/{case_id}/analysis:run` | 🔒📝 | `{evidence_ids[], pipelines[], params{}, priority}` → `202` + job ids. Validates pipeline↔item-type compatibility. |
| GET | `/cases/{case_id}/jobs` | 🔒 | Job list; filters `status`, `pipeline`, `evidence_id`, `requested_by`. |
| GET | `/cases/{case_id}/jobs/{job_id}` | 🔒 | Job detail incl. `progress_pct`, `error_class`, timings, resource stats. |
| GET | `/cases/{case_id}/jobs/{job_id}/events` | 🔒 | **SSE** progress stream (`queued → running → progress → succeeded/failed`). |
| POST | `/cases/{case_id}/jobs/{job_id}:cancel` | 🔒📝 | Cancel if not yet finished. |
| POST | `/cases/{case_id}/jobs/{job_id}:retry` | 🔒📝 | Retry a failed job (new attempt, same job id). |
| GET | `/cases/{case_id}/results` | 🔒 | Findings across the case; filters `result_kind`, `pipeline`, `verification_status`, `min_confidence`, `evidence_id`. |
| GET | `/cases/{case_id}/evidence/{evidence_id}/results` | 🔒 | Findings for one item, grouped by pipeline, `is_current` only by default (`include_superseded=true` opt-in). |
| GET | `/cases/{case_id}/results/{result_id}` | 🔒 | Full result: indicators, score+interval, confidence+basis, limitations text, provenance, derivatives, verification state. |
| POST | `/cases/{case_id}/results/{result_id}:verify` | ⚖📝 | `{status: confirmed|rejected|inconclusive, notes (required for confirmed/rejected)}`. |
| GET | `/cases/{case_id}/results/{result_id}/provenance` | 🔒 | `model_invocations` rows + library versions + params + device. |
| GET | `/cases/{case_id}/verification-backlog` | 🔒 | Unverified findings, oldest first, grouped by pipeline (ADM-02). |

**Result payload shape (normative):**

```json
{
  "id": "…",
  "evidence_id": "…",
  "pipeline": "image.ela",
  "pipeline_version": "1.2.0",
  "result_kind": "ela_heatmap",
  "is_current": true,
  "summary": "Recompression inconsistency is elevated in the lower-right quadrant. This is an indicator, not evidence of manipulation.",
  "indicators": [
    { "code": "ela.region_anomaly", "label": "Region anomaly score", "value": 0.71, "unit": "normalised",
      "confidence": 0.62, "region": {"type": "bbox", "x": 2140, "y": 1830, "w": 610, "h": 420},
      "interpretation": "Local recompression level differs from the image median." }
  ],
  "advisory_score": 71.0,
  "score_confidence_low": 55.0,
  "score_confidence_high": 84.0,
  "confidence": 0.62,
  "confidence_basis": "statistical_test",
  "limitations": {
    "code": "ELA", "version": 3,
    "text": "Error Level Analysis highlights recompression inconsistency. Legitimate operations (cropping, saving, platform re-encoding, screenshotting) produce the same signature. It does not establish manipulation."
  },
  "requires_human_verification": true,
  "verification": { "status": "unverified", "verified_by": null, "verified_at": null, "notes": null },
  "provenance": {
    "engine": {"name": "image_forensics.ela", "version": "1.2.0"},
    "models": [], "device": "cpu", "params": {"quality": 90, "scale": 15},
    "deterministic": true, "job_id": "…", "invocation_ids": ["…"],
    "library_versions": {"opencv": "5.0.0.93", "pillow": "13.0.0", "numpy": "2.x"}
  },
  "derivative_ids": ["…"],
  "created_at": "2026-11-10T14:22:31Z"
}
```

Note the absence of any verdict field. `advisory_score` is always accompanied by an interval, and
`confidence` always by `confidence_basis` — mirroring the DB CHECK constraints.

### 2.6 Module-specific analysis endpoints

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/cases/{c}/evidence/{e}/image-forensics` | 🔒 | ELA + DQT + noise + copy-move bundle for an image. |
| GET | `/cases/{c}/evidence/{e}/frames` | 🔒 | Extracted keyframes with PTS, filterable by scene/interval. |
| GET | `/cases/{c}/evidence/{e}/detections` | 🔒 | Detection rows; filters `class`, `min_confidence`, `frame_range`, `track_id`. |
| GET | `/cases/{c}/evidence/{e}/tracks` | 🔒 | MOT tracks with first/last PTS, path polyline, occlusions. |
| GET | `/cases/{c}/evidence/{e}/plates` | 🔒 | ALPR occurrences with top-N candidates and matched format. |
| GET | `/cases/{c}/evidence/{e}/transcript` | 🔒 | Segments with speaker labels, word timings, per-segment confidence, language probability. |
| GET | `/cases/{c}/evidence/{e}/audio-forensics` | 🔒 | Splice/clipping/bandwidth/vocoder indicators. |
| GET | `/cases/{c}/evidence/{e}/document-forensics` | 🔒 | Structure, revisions, XMP, fonts, attachments, actions. |
| GET | `/cases/{c}/evidence/{e}/document-revisions/{n}/diff` | 🔒 | Text/object diff between two saved PDF revisions. |
| GET | `/cases/{c}/evidence/{e}/location` | 🔒 | Parsed GPS, uncertainty radius, gazetteer match (fuzzed by role). |
| GET | `/cases/{c}/evidence/{e}/deepfake-advisory` | 🔒 | Indicator set + advisory score + interval + **mandatory disclaimer**. |
| GET | `/cases/{c}/entities` | 🔒 | Extracted entities; filters `entity_type`, `min_confidence`, `origin`. |
| GET | `/cases/{c}/entities/{id}` | 🔒 | Entity detail + all supporting evidence occurrences. |

### 2.7 Comparison

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/cases/{c}/comparisons` | 🔒📝 | `{item_a_id, item_b_id, method, params}` → sync result for cheap methods, `202` + job for expensive ones. |
| GET | `/cases/{c}/comparisons` | 🔒 | List; filters `method`, `similarity_band`, `item_id`, `verification_status`. |
| GET | `/cases/{c}/comparisons/{id}` | 🔒 | Score, unit, band, interpretation, limitations, regions, derivatives. |
| POST | `/cases/{c}/comparisons/{id}:verify` | ⚖📝 | Analyst confirms/rejects the comparison conclusion. |
| POST | `/cases/{c}/comparisons:bulk` | 🔒📝 | Compare one item against a filtered set → job with progress. |

### 2.8 Similarity search

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/cases/{c}/search:similar` | 🔒 | `{evidence_id | vector | text, modality, vector_set, limit, filters}` → ranked hits with distance, normalised score, model version, caveat. |
| POST | `/cases/{c}/search:query` | 🔒 | Hybrid: text + filters + vector, with reciprocal-rank fusion. |
| GET | `/cases/{c}/search/near-duplicates` | 🔒 | Threshold-configured near-duplicate groups + review queue. |
| GET | `/cases/{c}/search/vector-sets` | 🔒 | Available embedding model versions and coverage counts. |

### 2.9 Graph & timeline

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/cases/{c}/graph` | 🔒 | `{nodes, edges}` filtered by `node_types`, `relations`, `min_confidence`, `origin`, `neighbourhood_of`, `depth`. Deterministic seeded layout hints included. |
| GET | `/cases/{c}/graph/paths?from=…&to=…` | 🔒 | Shortest/strongest paths between two nodes. |
| POST | `/cases/{c}/graph/edges` | 🔒📝 | Manual edge `{source, target, relation, annotation}` → `origin=manual`. |
| POST | `/cases/{c}/graph/edges/{id}:verify` | ⚖📝 | Promote inferred → confirmed, or reject with reason. |
| GET | `/cases/{c}/graph:export?format=json|graphml` | 🔒📝 | Export (audited). |
| GET | `/cases/{c}/timeline` | 🔒 | Events in range; filters `event_type`, `derivation`, `reliability`, `evidence_id`, `from`, `to`, `precision`. Returns conflict groups intact. |
| GET | `/cases/{c}/timeline/gaps` | 🔒 | Periods with no evidence / implausible clustering. |
| POST | `/cases/{c}/timeline/events` | 🔒📝 | Analyst-asserted event (`derivation=analyst_asserted`). |
| GET | `/cases/{c}/timeline:export?format=csv|json` | 🔒📝 | Export. |

### 2.10 AI assistant

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET · POST | `/cases/{c}/assistant/conversations` | 🔒📝 | List/create conversations. |
| GET | `/cases/{c}/assistant/conversations/{id}/messages` | 🔒 | Persisted messages with citations + retrieval context. |
| POST | `/cases/{c}/assistant/conversations/{id}/messages` | 🔒📝 | `{content}` → assistant reply with `citations[]` or `unsupported=true`. **SSE** streaming variant at `…/messages:stream`. |
| POST | `/cases/{c}/assistant/suggested-actions` | 🔒 | Derived from real case state (coverage gaps, backlog) — not free-form invention. |
| GET | `/cases/{c}/assistant/guardrails` | 🔒 | Active guardrail version + system-prompt summary (transparency). |
| POST | `/cases/{c}/assistant/conversations/{id}/messages:egress-preview` | 🔒 | **Returns exactly what would leave the host** — provider, destination host, data categories, char count, redactions applied, and the never-send list — plus a bound, expiring `confirmation_token`. Only meaningful when external AI is enabled. |
| GET | `/cases/{c}/assistant/egress-status` | 🔒 | Whether external AI is enabled, by whom, when it expires, and which categories are allowed. |

The assistant namespace exposes **no** mutation of evidence, custody, or verification state (AI-03).

**Egress control (ADR-0007 / ADR-0021).** When `ENABLE_EXTERNAL_AI=false` (the default), every
external-transmission path returns `403 EXTERNAL_AI_DISABLED` and the server makes **zero** outbound
connections. When enabled, a message request that would transmit data **must** present a valid,
unexpired `confirmation_token` bound to `(user, conversation, category set, char-count band)`;
without it the request is rejected with `403 EGRESS_CONFIRMATION_REQUIRED`. The token cannot be
replayed for a larger payload. A failing **local** provider returns `ASSISTANT_UNAVAILABLE` with
`fallback_attempted: false` — there is **no** cloud fallback code path.

Error codes added for this namespace: `EXTERNAL_AI_DISABLED`, `EGRESS_CONFIRMATION_REQUIRED`,
`EGRESS_CATEGORY_NOT_ALLOWED`, `EGRESS_GRANT_EXPIRED`, `ASSISTANT_UNAVAILABLE`.

### 2.11 Reports

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/cases/{c}/reports` | 🔒📝 | `{template, sections[], filters, watermark, include_unverified}` → `202` + job. Builds and stores the manifest. |
| GET | `/cases/{c}/reports` | 🔒 | Report list with versions and lineage. |
| GET | `/cases/{c}/reports/{id}` | 🔒 | Metadata + manifest hash + PDF hash + approval state. |
| GET | `/cases/{c}/reports/{id}/manifest` | 🔒 | Exact source entities and their hashes at generation time (RPT-04). |
| GET | `/cases/{c}/reports/{id}:download-url` | 🔒📝 | Short-lived signed URL for the PDF. |
| POST | `/cases/{c}/reports/{id}:regenerate` | 🔒📝 | New version from the same manifest (or an updated one). |
| POST | `/cases/{c}/reports/{id}:approve` | 🔒 `owner/lead`📝 | Marks FINAL; records attestation. |
| GET | `/cases/{c}/evidence/{e}/custody-report` | 🔒📝 | Custody-only PDF for one item (CUST-04). |

### 2.12 Audit

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/audit/logs` | 🔒 (`auditor`/`admin`) | Global audit search; filters `actor`, `action`, `case`, `resource`, `from`, `to`, `result`. |
| GET | `/cases/{c}/audit/logs` | 🔒 | Case-scoped audit search. |
| GET | `/audit/logs/{id}` | 🔒 | Single record incl. `prev_hash`, `record_hash`. |
| POST | `/audit/chain:verify` | 👑📝 | Recompute and verify the hash chain → `{valid, checked_count, broken_at}`. |
| GET | `/audit/logs:export?format=csv|json` | 🔒📝 | Export (the export itself is audited). |

There is **no** PATCH/PUT/DELETE on any audit resource, by design and by DB grants.

### 2.13 Administration

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET · POST · PATCH | `/admin/users` · `/admin/users/{id}` | 👑📝 | User lifecycle, role assignment. |
| POST | `/admin/users/{id}:deactivate` · `:suspend` · `:force-logout` · `:reset-password` · `:reset-mfa` | 👑📝 | Administrative actions. |
| GET | `/admin/cases` | 👑 | Cross-case oversight incl. storage and backlog metrics. |
| GET · POST · PATCH | `/admin/models` · `/admin/models/{id}` | 👑📝 | Model registry; `POST /admin/models/{id}:set-default`, `:deprecate`. |
| GET | `/admin/models/{id}/performance` | 👑 | Measured performance on the internal eval set (AR-6). |
| GET | `/admin/queues` | 👑 | Per-queue depth, throughput, failure rate, retries, DLQ contents. |
| POST | `/admin/queues/{name}:purge` · `/admin/jobs/{id}:requeue` | 👑📝 | Queue operations. |
| GET | `/admin/storage` | 👑 | Usage by case/type, quota status, integrity-sweep results, backup status. |
| POST | `/admin/integrity-sweep:run` | 👑📝 | Trigger a full/partial sweep. |
| GET · PATCH | `/admin/settings` | 👑📝 | Curated runtime settings (allowlisted keys only). |
| GET | `/admin/flags` | 👑 | Feature/licence flags incl. AGPL component state. |
| GET | `/admin/alerts` | 👑 | Security/detection alerts (auth failures, chain break, integrity mismatch, bulk export, cross-case denial spikes). |
| POST | `/admin/ai/external:enable` | 👑 `enable_external_ai`📝 | `{justification (required), expires_at (≤30 days), acknowledged_disclosure: true}` → writes an `ai_external_grants` row, notifies every case lead, audits `admin.ai.external_enabled`. Refused if `ENABLE_EXTERNAL_AI=false` in config. |
| POST | `/admin/ai/external:disable` | 👑📝 | **Kill switch.** Immediate; revokes all outstanding confirmation tokens; audits `admin.ai.external_disabled`. |
| POST | `/admin/ai/kill` | 👑📝 | Disables **all** assistant inference, local included — incident response. |
| GET | `/admin/ai/egress-log` | 👑 | Every external transmission: actor, case, provider, model, categories, char count, redactions, purpose, confirmation-token id. |
| GET | `/admin/deployment/verify` | 👑 | Runs the host preflight checks (encrypted volume mounted, permissions, nginx isolation, disk, NTP, auditd) and returns the per-check result. |

### 2.14 Health & metrics

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/healthz` | public | Liveness. `200 {"status":"ok"}`. No dependency checks (so it can't flap). |
| GET | `/readyz` | public | Readiness: DB reachable, Redis reachable, migrations at head, worker heartbeat seen, **and the host preflight has passed** (encrypted volume mounted at the expected path). `503` otherwise. |
| GET | `/api/v1/status` | 👑 | Detailed dependency + worker + GPU status. |
| GET | `/metrics` | network-restricted | Prometheus text format; **not** exposed through the public nginx route. |

---

## 3. Real-time progress

**SSE** is the primary mechanism (simpler through proxies, unidirectional, auto-reconnecting):

```
GET /api/v1/cases/{c}/jobs/{j}/events
Accept: text/event-stream

event: status
data: {"status":"running","progress_pct":35,"progress_message":"ELA on frame 120/340","ts":"..."}

event: log
data: {"level":"info","message":"quantisation table extracted","ts":"..."}

event: completed
data: {"status":"succeeded","result_ids":["…"],"duration_ms":48213}
```

Rules: heartbeat comment every 15 s to defeat proxy idle timeouts; `Last-Event-ID` resumption
supported; stream closes on terminal state; the client falls back to polling `GET …/jobs/{j}` if SSE
is unavailable.

**WebSocket** is used only for the case-wide live feed (`/api/v1/cases/{c}/ws`) pushing
job-state changes, new results, and integrity alerts to all connected members of that case. It is
authenticated during the handshake (token in the first frame, not the query string — query strings
land in proxy logs).

---

## 4. Rate limiting & quotas

| Scope | Default | Notes |
|---|---|---|
| `/auth/login` | 10 / 5 min / IP + account | exponential lockout, security alert on burst (SEC-05) |
| `/auth/refresh` | 60 / min / session | |
| Authenticated read | 600 / min / user | Redis sliding window |
| Upload | 60 / h / user; `MAX_UPLOAD_BYTES` (default 4 GiB) | nginx `client_max_body_size` + app-level check |
| `content` / `download-url` | 30 / min / user | these are the audited original-access paths |
| Analysis launches | 100 / h / user, plus per-case concurrent-job cap | prevents one analyst monopolising the GPU queue |
| Assistant messages | 60 / h / user | token-budget aware |
| Report generation | 10 / h / case | expensive |

`429` always carries `Retry-After`. Limits are configuration, not code, and changes are audited.

---

## 5. Security-relevant API behaviours

1. **Existence hiding.** A request for a case the caller cannot access returns `404 NOT_FOUND`, not
   `403`, so case existence is not enumerable. Case *list* endpoints return only accessible cases.
2. **Capability checks are server-side only.** The `capabilities` array returned by `/auth/me` is a
   UI hint; the server re-evaluates on every request.
3. **Filename hygiene.** `original_filename` is stored as data, echoed only in JSON, and never used
   to construct a path or set `Content-Disposition` without sanitisation + RFC 5987 encoding.
4. **Signed URLs.** Download URLs are HMAC-signed, single-purpose (evidence id + expiry + purpose),
   and short-lived. They do not embed a user token.
5. **No secrets in responses.** Configuration endpoints return keys with values redacted
   (`{"SECRET_KEY": "***set***"}`).
6. **Input size limits** at nginx and again in the app (defence in depth).
7. **SSRF guard.** Any endpoint accepting a URL (none in v1 except the opt-in geocoder/LLM provider
   config, admin-only) resolves and blocks private/link-local/metadata ranges before connecting.
8. **Mass assignment.** Schemas declare writable fields explicitly; `PATCH` ignores unknown keys
   and reports them in `field_errors` rather than applying them.
9. **CORS.** Disabled by default (same-origin frontend through nginx). If enabled, an explicit origin
   allowlist and no wildcard credentials.
10. **Problem details never leak internals.** `detail` is written for humans; internals go to logs
    keyed by `request_id`.

---

## 6. OpenAPI & client generation

- FastAPI emits OpenAPI 3.1 at `/openapi.json`; committed as `tools/openapi/openapi-v1.json` (the
  contract baseline).
- CI: `pnpm run gen:api` regenerates `frontend/src/types/api.ts` via `openapi-typescript`; a diff
  against the committed types fails the build if the API changed without regeneration.
- A **contract test** asserts the running app's schema equals the committed baseline (catches
  accidental response-shape changes).
- Every route declares: operation id, tags (module), summary, description, security scheme, request
  and response schemas, error responses, and `x-audit: true|false` (consumed by a test that asserts
  all mutating endpoints write audit records).

---

*End of API_SPECIFICATION.md — v0.1.0 DRAFT. No endpoints are implemented yet; M2 delivers
`/healthz`, `/readyz` and the auth namespace.*
