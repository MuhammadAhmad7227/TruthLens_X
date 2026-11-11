# TruthLens X — Security Architecture

| | |
|---|---|
| **Document ID** | TLX-DOC-005 |
| **Version** | 0.1.0 (DRAFT — pending approval) |
| **Last updated** | 2026-11-10 |
| **Framework alignment** | OWASP ASVS v4.0 L2, OWASP Top 10 (2021/2025), NIST SP 800-53 (selected families), ISO 27001 Annex A (mapping only) |
| **Related** | [MASTER_PRD.md](./MASTER_PRD.md) §5, [SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md) §6/§8, [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) §8 |

> **Scope note.** This document describes the security design of the *software*. It is not a legal
> opinion, not an accreditation, and not a substitute for a deployment-specific risk assessment by
> the operating organisation. Digital-evidence handling carries jurisdiction-specific legal
> obligations; obtain local counsel (see PRD §5 legal note).

---

## 1. Security objectives

| # | Objective | Why it dominates the design |
|---|---|---|
| SO-1 | **Evidence integrity is provable at any moment** | A forensic platform whose evidence can silently change is worthless and potentially defamatory. |
| SO-2 | **Every action on evidence is attributable** | Court-defensible chain of custody requires actor, time, purpose, and state. |
| SO-3 | **Audit records are tamper-evident** | An attacker (or a careless admin) who can rewrite history defeats SO-2. |
| SO-4 | **Least privilege, deny by default** | Case data is compartmented; a user in case A must not reach case B by guessing a UUID. |
| SO-5 | **AI output cannot be mistaken for fact** | Misplaced confidence causes real harm to real people. Treated as a *safety* property, not a UX nicety. |
| SO-6 | **Personal data (faces, plates, GPS, transcripts) is minimised and controlled** | These are identifying data about people who may be innocent. |
| SO-7 | **The platform must not become an attack vector itself** | It ingests hostile files by design — parsing untrusted input is the product. |
| SO-8 | **Secrets never leak** | Into code, git, logs, error responses, DB rows, reports, or model outputs. |

---

## 2. Threat model (STRIDE, per trust boundary)

### 2.1 Actors

| Actor | Trust | Notes |
|---|---|---|
| Anonymous internet client | None | Blocked at the edge; only login/health reachable. |
| Authenticated analyst/investigator | Low-medium | Legitimate access to *their* cases only; may attempt to exceed it. |
| Lead investigator / reviewer | Medium | Can set verification status — a privileged epistemic act. |
| Administrator | High, but **not trusted with evidence content** | Admin manages users/config; content access is separately authorised and audited. |
| Case subject / third party whose data appears in evidence | N/A — data subject | Their interests drive SO-6. |
| Worker/service identity | Medium | Compromised worker could poison results — mitigated by provenance + result validation. |
| Upstream model/dependency supplier | Low | Supply-chain risk (SO-7): pinned checksums, licence/dep scanning, no auto-update of weights. |

### 2.2 Threat register

| ID | Threat (STRIDE) | Scenario | Impact | Mitigation | Residual |
|---|---|---|---|---|---|
| T-01 | **Tampering** — original evidence modified | Attacker or careless ops replaces a file in the store | Catastrophic (SO-1) | Write-once store, RO mounts, `O_EXCL` + `0440`, SHA-256 at ingest + pre-analysis + scheduled sweep, `integrity_checks` history, DB trigger blocking `physical_objects` mutation | Low — physical root access on the host remains; mitigate with disk encryption + host hardening + offsite backup |
| T-02 | **Tampering** — audit/custody rewritten | Admin with DB access deletes incriminating rows | High (SO-3) | Hash chain (`prev_hash`/`record_hash`), `UPDATE`/`DELETE` revoked from app role, append-only tables, nightly chain verification, exported chain anchors retained outside the DB | Medium — an attacker with superuser + time can rebuild a chain; external anchoring (signed digest stored off-host) reduces this |
| T-03 | **Elevation of privilege** — cross-case access | User guesses/enumerates another case's evidence UUID | High (SO-4) | Mandatory `require_case_access(case_id, capability)` dependency on *every* case-scoped route; case_id always in the path (never inferred from body); `404` instead of `403`; a test suite that enumerates all routes and asserts the dependency is present | Low |
| T-04 | **Elevation of privilege** — role escalation | User PATCHes their own `global_role` | High | Explicit per-endpoint writable-field schemas; role changes only via `/admin/users/{id}` (admin-only); change is diffed into `audit_logs.before/after` | Low |
| T-05 | **Spoofing** — credential stuffing / password spray | Bulk login attempts | Medium | Rate limit + per-account exponential lockout + argon2id + optional TOTP (mandatory for admin/lead) + IP reputation hook + security alerts | Medium |
| T-06 | **Spoofing** — stolen refresh token | Token exfiltrated via XSS or a shared machine | High | httpOnly + Secure + SameSite=Strict + path-scoped cookie, rotation with **reuse detection** revoking the family, short access-token TTL, Redis `jti` denylist, force-logout admin action, strict CSP | Medium |
| T-07 | **Tampering** — malicious file exploits a parser | Crafted JPEG/PDF/MP4 triggers a memory-safety bug in a native decoder | High (SO-7) | Parsing happens **only in workers**, never in the API; workers run non-root, read-only root FS, `no-new-privileges`, seccomp, dropped capabilities, memory/CPU/time limits; magic-byte type detection before decode; optional ClamAV pre-scan; quarantine path; parser libraries pinned and scanned; no shell interpolation of filenames | Medium — native parsers will always carry risk; isolation contains the blast radius |
| T-08 | **Tampering** — filename/path injection | `original_filename` = `../../originals/aa/bb/<hash>` | High | Filenames are **data, never path components**; storage paths derived solely from SHA-256; sanitised names for display/download; unit tests with adversarial names (NUL, `..`, RTL overrides, 4 KB names, emoji) | Low |
| T-09 | **Information disclosure** — evidence leak via signed URL | URL forwarded/shared | Medium | Short TTL (≤900 s), single-purpose HMAC binding evidence id + expiry + purpose, download audited, `restricted` sensitivity can require re-auth before URL issue | Medium |
| T-10 | **Information disclosure** — SSRF via a URL-accepting feature | Geocoder/LLM provider URL points at cloud metadata | High | v1 accepts URLs only from admins; resolution-time private/link-local/loopback/metadata-range blocking; egress allowlist at the network layer; providers fixed at deploy time in config, not per-request | Low |
| T-11 | **Information disclosure** — secrets in logs/errors/reports | `DATABASE_URL` in a traceback shown to a user | High | Structured logging with a redaction filter (regex + key allowlist), RFC 9457 errors with no internals, `request_id` correlation, a test asserting known secret values never appear in any log/error/report output | Low |
| T-12 | **Repudiation** — analyst denies a verification decision | "I never confirmed that finding" | Medium | Verification requires an authenticated write with mandatory notes, recorded in `analysis_results` + `custody_events` + `audit_logs` (hash-chained) | Low |
| T-13 | **Denial of service** — resource exhaustion | 4 GB video upload × 100, or unbounded analysis fan-out | Medium | Body-size caps, per-user and per-case upload/job quotas, queue priorities, GPU `prefetch=1`, task time/memory limits, streaming (never buffer whole files), rate limits, nginx connection limits | Medium |
| T-14 | **Denial of service** — Redis/DB loss stalls ingest | Broker outage | Medium | `202` + durable job rows mean work is recoverable; result backend is Postgres, not Redis; re-queue tooling; `/readyz` gating | Low |
| T-15 | **Tampering** — supply chain | Typosquatted package or compromised model weight | High | Pinned versions + hashes in lockfiles, private index/mirror if available, `pip-audit`/`npm audit`/Trivy in CI, SBOM artefacts, **model weights pinned by SHA-256 and verified before load**, image digests pinned, no `latest` tags | Medium |
| T-16 | **Elevation** — AI assistant used to exfiltrate cross-case data | Prompt injection via evidence text asking the assistant to reveal other cases | High | Retrieval is **hard-scoped by `case_id` at the query layer** (the LLM cannot widen it); the assistant has no tool that touches other cases; guardrail prompt version is recorded; injected instructions found in evidence content are treated as data, never as commands; assistant cannot mutate anything | Medium — prompt injection is unsolved generally; scoping is the real control |
| T-17 | **Tampering** — poisoned analysis result | Compromised worker returns "no anomalies" | High | Result contract validation, mandatory provenance, `model_invocations` cross-check (a result with no invocation row is rejected), re-runnability (any result can be reproduced from recorded params/version), worker identity recorded | Medium |
| T-18 | **Information disclosure** — PII over-exposure | A `reviewer` sees full GPS coordinates and unmasked plates | Medium | Role capability `can_view_original_content`, coordinate truncation (GEO-07), masked `display_value`, masking derivatives (ALPR-07), field-level redaction in list endpoints | Low |
| T-19 | **Spoofing** — forged timestamps mislead the timeline | Attacker sets file mtime / EXIF to a false date | High (epistemic) | **Not preventable** — instead, *detect and label*: `derivation` + `reliability` + `corroborated` + `conflict_group_id`; conflicting timestamps are never merged; the UI shows "claimed" vs "corroborated" | Accepted; this is an inherent property of digital media, documented in AR-4 |
| T-20 | **Repudiation** — report contents disputed | "That report didn't say this" | Medium | Report manifest + manifest hash + PDF SHA-256 + version lineage + immutable prior versions + optional cryptographic signing | Low |

---

## 3. Cryptographic design

| Purpose | Algorithm / parameters | Notes |
|---|---|---|
| Evidence integrity | **SHA-256**, streamed in 1 MiB blocks | Primary. SHA-1/MD5 recorded only for external interoperability and never trusted. |
| Merkle integrity (optional, large files) | SHA-256 over 4 MiB blocks, RFC 6962-style domain separation | Enables partial proofs (EVID-11). |
| Audit/custody chain | SHA-256 over canonical JSON (sorted keys, RFC 3339 UTC, no insignificant whitespace, explicit nulls) | Canonicalisation unit-tested with golden vectors — a chain that verifies on one machine must verify on all. |
| Password storage | **argon2id**: `m=64 MiB, t=3, p=4` (RFC 9106 low-memory first-recommended), 16 B salt, 32 B tag; params embedded in the stored string so they can be upgraded transparently | Legacy bcrypt (`cost=12`) verified then rehashed on login. `passlib` avoided (unmaintained; breaks on bcrypt ≥ 4.1). |
| JWT signing | **EdDSA (Ed25519)** preferred; **RS256** where an external verifier needs the public key. Symmetric HS256 is **disallowed** in production config (startup check). | Keys from env/secret store, with `kid` and rotation support; rotation keeps the previous public key valid for one token TTL. |
| Token/secret at rest | Refresh tokens stored **only** as SHA-256 hashes. TOTP secrets and any provider API keys encrypted with AES-256-GCM under a KEK from env/KMS. | No plaintext long-lived credential in the DB. |
| Optional evidence encryption (D-006) | AES-256-GCM envelope: random per-object DEK, DEK wrapped by KEK; nonce uniqueness enforced per object; AAD binds `sha256` + `physical_object_id` | **Off by default.** Trade-off: protects against disk theft; adds a key-loss = evidence-loss failure mode. Requires key backup/escrow design before enabling. |
| Signed download URLs | HMAC-SHA256 over `evidence_id|expires_at|purpose|nonce`, base64url | Short TTL, single purpose, no token embedded. |
| TLS | TLS 1.2+ (1.3 preferred); Mozilla *intermediate* cipher list; HSTS `max-age=31536000; includeSubDomains` (preload only once the domain is stable) | Terminated at nginx; internal traffic on a private Docker network. |
| Randomness | `secrets` module / OS CSPRNG for all tokens, salts, nonces, ids | `random` is forbidden for security purposes (ruff/bandit rule). |

**Key management (v1, honest scope):** keys live in environment variables injected from the host's
secret store (Docker secrets / systemd credentials / cloud KMS in phase 2). There is **no** in-product
HSM. Documented consequences: key rotation is a manual, runbook-driven operation; a host compromise
exposes keys; `ENCRYPTION_KEY` loss with envelope encryption enabled is unrecoverable without backup.
Runbooks: `docs/runbooks/key-rotation.md`, `docs/runbooks/key-compromise.md` (delivered in M14).

---

## 4. Authorization model

### 4.1 Two-layer model

```
Layer 1 — Global role   (who you are in the platform)
Layer 2 — Case membership + capability (what you may do in THIS case)
Effective permission = global_role_allows(action) AND case_membership_active AND capability_granted AND NOT blocked_by_state
```

Any layer failing ⇒ deny. Denials are logged with the specific failing layer (`FORBIDDEN_ROLE` vs
`FORBIDDEN_CASE_ACCESS` vs `FORBIDDEN_CAPABILITY` vs `CASE_CLOSED` vs `LEGAL_HOLD`).

### 4.2 Capability matrix

C = create, R = read, U = update, X = execute, — = no access. `(m)` = metadata only, no original content.

| Capability | admin | lead_investigator | investigator | analyst | reviewer | auditor |
|---|---|---|---|---|---|---|
| Case create | C | C | C | — | — | — |
| Case read (own/accessible) | R | R | R | R | R | R(m) |
| Case metadata update | U | U (owner/lead) | — | — | — | — |
| Case status transition | U | U (owner/lead) | — | — | — | — |
| Case membership manage | U | U (owner/lead) | — | — | — | — |
| Evidence upload | C | C | C | C | — | — |
| Evidence metadata update | U | U | U (own) | U (own) | — | — |
| **Original content access** | R ⁽¹⁾ | R | R | R | R(m) | — ⁽²⁾ |
| Derivative access | R | R | R | R | R | R(m) |
| Evidence soft-delete | X | X (owner/lead) | — | — | — | — |
| Evidence hard-delete | X + second approver | — | — | — | — | — |
| Analysis launch | X | X | X | X | — | — |
| Result read | R | R | R | R | R | R(m) |
| **Verification set** | — ⁽³⁾ | X | — | — | X | — |
| Comparison create | C | C | C | C | R | — |
| Graph edge create / verify | C / X | C / X | C / — | C / — | R / X | R |
| Timeline event create | C | C | C | C | R | R |
| Report generate | X | X | — | X | — | — |
| Report approve (FINAL) | — | X (owner/lead) | — | — | — | — |
| Assistant use | X | X | X | X | X | X |
| Audit log read | R | R (own case) | — | — | — | R |
| Chain verify | X | — | — | — | — | X |
| User management | C/R/U | — | — | — | — | — |
| Model registry manage | C/U | R | R | R | R | R |
| System settings | U | R | — | — | — | R |
| Queue administration | X | R | — | — | — | R |

⁽¹⁾ Admin content access is **not** implicit: `admin` gains access to a case's originals only when
they are an explicit case member, or via a break-glass procedure that requires a justification, is
time-bounded, notifies the case lead, and is audited. This prevents "admin sees everything" — the
single most common forensic-platform integrity failure.
⁽²⁾ `auditor` may be granted `can_view_original_content` per case membership where required.
⁽³⁾ `admin` deliberately cannot set verification status — administrative power must not be able to
manufacture an epistemic conclusion (separation of duties).

The matrix is **data** (`rbac_matrix` table, seeded by migration), consumed by one authorisation
service, and covered by a test that walks every registered route and asserts the expected capability.
Changing a cell requires a migration + review, which makes privilege changes auditable.

### 4.3 Enforcement points

1. Edge (nginx): coarse rate limiting, body size, TLS, headers.
2. Middleware: request id, authn, denylist check, `Authorization` validation, timing-safe comparisons.
3. Route dependency `require_case_access(case_id, capability)`: the single gate. Case id comes from
   the **path**, resolved before the handler, and re-verified against the loaded resource (so a
   resource in case B cannot be reached through a case A path — an ownership assertion, not a filter).
4. Service layer: state rules (case closed, legal hold, verification eligibility, second approver).
5. Repository layer: every query is case-scoped by construction; a lint rule flags any query on a
   case-scoped table without a `case_id` predicate.
6. Database: RLS is **excluded from v1 entirely, including M20** — [ADR-0010](adr/ADR-0010-no-row-level-security-in-v1.md)
   records this as a strengthening of the original "defer to M20" proposal (ratification conflict #1).
   No `tenant_id` column exists on any table; `cases.organisation_id` is **inert** and is never read by
   authorisation. Compensating controls are the single `require_case_access` gate + the 100%
   `x-capability` route-enumeration CI gate + immutable audit + cross-case-attempt alerting. **Because
   there is one enforcement layer rather than two, application-layer correctness is load-bearing** —
   that residual risk is recorded here rather than hidden. RLS remains a
   phase-2 hardening option (D-010).

---

## 5. Application security controls

### 5.1 Input handling

| Control | Detail |
|---|---|
| Schema validation | Pydantic v2 on every body/query/param; `extra="forbid"` on writes; unknown keys reported, not applied. |
| Type allowlist | Evidence accepted only if **magic bytes** match an allowed type for the declared category; extension and client MIME are advisory only. |
| Size limits | nginx `client_max_body_size`, app `MAX_UPLOAD_BYTES`, per-chunk limits, per-case quota. |
| Filename hygiene | Stored as data; sanitised for display/download (strip control chars, path separators, RTL overrides; length cap; RFC 5987 encoding). Never a path component. |
| Path traversal | Storage keys derived from SHA-256 hex only; a single `resolve_within_root()` helper validates containment and is the only way to build a filesystem path (property-tested). |
| SQL | ORM/parameterised only; raw SQL allowed solely in reviewed repository functions with bound params; no string interpolation (bandit + ruff rules). |
| Shell | **No `shell=True` anywhere.** External binaries (ffmpeg, exiftool) invoked with argument lists; env sanitised; timeouts enforced. |
| Deserialisation | JSON only; no pickle/yaml.load of untrusted data (Celery serialiser pinned to JSON — this also blocks a classic Celery RCE path). |
| Archive handling | Zip/tar extraction with member-count, total-uncompressed-size, and path-containment guards (zip-bomb and slip protection); extraction is opt-in per deployment. |
| Redirects | No open-redirect endpoints; any `next` param validated against a path allowlist. |
| Regex | ReDoS-aware: user-supplied patterns (plate formats) are compiled with a complexity check + match timeout in a worker, never in the request path. |

### 5.2 Output & transport

- Security headers from nginx: `Content-Security-Policy` (default-src 'self'; no unsafe-inline;
  img-src restricted to self + blob: for forensic viewers; connect-src 'self' + wss for the live
  feed; frame-ancestors 'none'), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy` minimal, `X-Frame-Options: DENY` (belt and
  braces with frame-ancestors), HSTS.
- Derived forensic images are served with `Content-Disposition: attachment` where they could be
  interpreted as HTML/SVG; SVG rendering is disabled (SVG is an XSS vector).
- User-generated text is rendered as text, never as HTML; no `dangerouslySetInnerHTML` (ESLint rule
  errors on it, with a documented exception path requiring review).
- Cookies: `Secure`, `HttpOnly`, `SameSite=Strict`, path-scoped; CSRF protection via
  double-submit token on state-changing requests when cookie auth is in play (JWT-in-header clients
  are exempt but still rate-limited).
- JSON responses set `Cache-Control: no-store` for anything case-scoped (prevents proxy/browser
  caching of evidence metadata).

### 5.3 Secrets management

1. Every secret comes from the environment; `Settings` fails closed at startup if a required one is
   missing or is a known placeholder (`changeme`, `dev`, empty).
2. `.env.example` documents every variable with purpose, default, and risk — and contains **no real
   values**. `.env` is git-ignored; a pre-commit/CI secret-scanning gate (gitleaks/trufflehog) blocks
   accidental commits.
3. Secrets are redacted from logs, errors, audit `before/after`, reports, and `/admin/settings`
   responses. A test asserts that a canary secret value never appears in any captured output.
4. JWT/encryption keys support `kid`-based rotation; rotation runbook documents dual-key overlap.
5. Git history is assumed public: any secret ever committed is treated as compromised and rotated.

### 5.4 Dependency & supply chain

| Gate | Tool | Policy |
|---|---|---|
| Python vulnerabilities | `pip-audit` (CI, blocking) | Fail on known-exploited/high with no fix and no accepted risk record. |
| Python static security | `bandit` + `ruff` security rules | Fail on high severity. |
| JS vulnerabilities | `npm audit` / `pnpm audit` | Fail on high/critical. |
| Images | `trivy image` | Fail on critical; SBOM (CycloneDX) published as a build artefact. |
| Lockfiles | `uv.lock` / `pnpm-lock.yaml` committed | Reproducible installs; CI installs with `--frozen-lockfile`. |
| Base images | Digest-pinned, no `latest` | Renovate-style PRs with the licence/dep gate re-run. |
| Model weights | `models.lock.json` (family, version, sha256, source) | Checksum verified before load; mismatch = fail closed, alert. |
| Licence policy | `tools/license-check/` | Fails on unexpected AGPL/GPL entering the default (flag-off) dependency set. |

### 5.5 Container & host hardening

Every container in the compose stack:

```yaml
security_opt: ["no-new-privileges:true"]
cap_drop: [ALL]
read_only: true                 # with explicit tmpfs for /tmp and the intake scratch path
user: "10001:10001"             # non-root, fixed uid
# volumes: originals mounted read-only for every container except the ingest worker
deploy.resources.limits: {cpus, memory}   # workers: hard limits to contain parser bugs (T-07)
```

- Seccomp: default Docker profile for API/frontend; a custom profile for media workers that permits
  the syscalls ffmpeg/OpenCV need and nothing more (documented, tested).
- Networks: `edge` (nginx↔frontend↔api), `data` (api/workers↔postgres/redis), `isolated` (media
  workers, **no outbound internet**). Only nginx publishes ports. Postgres/Redis are never published
  to the host in production profiles.
- GPU worker: `--gpus` scoped to the minimum device set; no host mounts beyond `/evidence` (RO for
  originals), `/models` (RO), and its scratch tmpfs.
- Host: SSH key-only, fail2ban/nftables rate limits, unattended security updates, auditd rules on
  `/evidence/originals` (immutable attribute `chattr +i` where the filesystem supports it — a strong
  complement to T-01), NTP synchronized (timestamps matter evidentially), and disk-full alerting
  (a full disk during ingest can truncate a file).

### 5.6 Detection & response

| Signal | Detector | Response |
|---|---|---|
| Repeated auth failure / lockout burst | App counter + `/admin/alerts` | Alert, temporary IP block, admin notification |
| Refresh-token reuse | Family rotation logic | Revoke family, force re-auth, security audit event, alert |
| Hash-chain break | Nightly + on-demand `POST /audit/chain:verify` | **Critical** alert, freeze report generation for the case, incident runbook |
| Integrity mismatch | Sweep + pre-analysis verification | Flag `integrity_failed`, quarantine, block analysis, critical alert |
| Original accessed outside allowed path | Filesystem auditd + app-level access logging | Alert, investigate |
| Unusual bulk export / download burst | Rate + volume anomaly on the audited download path | Throttle, alert, require re-auth |
| Privilege escalation attempt (403 spike for one actor) | Audit log analytics | Alert, optional auto-suspend pending review |
| Cross-case access attempt | `FORBIDDEN_CASE_ACCESS` audit events | Alert (this is the highest-signal insider indicator) |
| Engine returning results with no invocation row | Result-contract validation | Reject write, alert (possible worker compromise, T-17) |

Incident response: `docs/runbooks/incident-response.md` (M14) covering detection → containment →
evidence preservation *of the platform itself* → eradication → recovery → post-incident review. Note
the recursion: an incident on a forensic platform must itself be handled forensically (preserve
logs, images, and DB snapshots before remediation).

---

## 6. Data protection & privacy

| Data class | Handling |
|---|---|
| Original evidence | Write-once, RO mounts, access audited with a mandatory `purpose`, download via short-lived signed URLs. |
| Faces / face clusters | `person_candidate` naming, no identity claim, no external face database, cluster access case-scoped, deletion path on case closure/archival. |
| Plates | `vehicle_plate_candidate`; **no automatic registry lookup** (ALPR-06); masking derivative for shared/report contexts; top-N candidates rather than a confident single string. |
| GPS / locations | Uncertainty always surfaced; coordinate truncation for lower-privilege roles; offline gazetteer by default; online enrichment opt-in, rate-limited, logged, SSRF-guarded. |
| Transcripts | Machine output labelled as such; optional PII redaction derivative; speaker labels anonymous (`SPK_00`); no speaker identification against a biometric database. |
| Assistant conversations | Prompt + retrieval context retained for audit; external LLM providers disabled by default because case data would leave the host (D-007). |
| Audit `before/after` | Redaction allowlist; never secrets, never full file content, minimised PII. |
| Retention | Per PRD §Module 20 / DATABASE_DESIGN §12; retention jobs are logged and reversible-up-to-execution. |
| Data subject requests | Documented procedure (`docs/runbooks/data-subject-request.md`, M14): export, redaction, or deletion with an audit trail and a legal-hold check. |

**Minimisation principle:** the platform stores what an investigation needs and nothing speculative.
Concretely: no automatic enrichment of plates against external registries, no automatic face
identification, no automatic geocoding of every coordinate, no retention of assistant data beyond the
case lifetime, and no cross-case analytics on personal data.

---

## 7. AI-specific safety controls

These extend PRD §5 into enforcement mechanisms (SO-5).

| Control | Enforcement point |
|---|---|
| No verdicts | Schema has no verdict field; DB CHECKs require an interval with any score and a basis with any confidence; a **string-lint test** scans UI/report copy for forbidden phrasing ("confirmed fake", "proven authentic", "is a deepfake", "guilty"). |
| Mandatory provenance | `model_invocations` write is part of the same transaction as `analysis_results`; a result without an invocation is rejected (T-17). |
| Mandatory limitations | `limitations_code NOT NULL`; the resolved text is snapshotted onto the row so historical reports stay truthful. |
| Mandatory verification state | `verification_status NOT NULL DEFAULT 'unverified'`; `requires_human_verification` cannot be set false by engine code (no API path exists). |
| No fabricated metrics | Only `measured_performance` from our own eval harness is displayed; vendor numbers appear only as labelled third-party references with the dataset named. |
| Fail visibly | Engine errors persist a `failed` result with `error_class`; the UI renders "analysis failed — no conclusion available", never "no issues found" (AR-7). |
| Prompt-injection containment | Evidence text entering the assistant context is wrapped as data with an explicit instruction that it is untrusted; retrieval scope is enforced in the query layer, not the prompt (T-16). |
| Determinism & reproducibility | Fixed seeds, pinned weights by checksum, recorded library versions; `deterministic` flag on every invocation; golden-file tests on synthetic fixtures. |
| Model lifecycle | Deprecating a version never deletes it, so historical results remain interpretable; only one default per `(family, task)`. |

---

## 8. Compliance & assurance mapping

| Requirement family | Where satisfied |
|---|---|
| ASVS V1 (architecture) | SYSTEM_ARCHITECTURE §1 principles, this doc §4 |
| ASVS V2 (authentication) | §3 crypto, AUTH-01..09, T-05/T-06 |
| ASVS V3 (session) | refresh rotation + reuse detection, denylist, TTLs |
| ASVS V4 (access control) | §4 two-layer model + capability matrix + route-enumeration test |
| ASVS V5 (validation) | §5.1 |
| ASVS V7 (error/logging) | §5.2, SYSTEM_ARCHITECTURE §6.2/6.3, audit vs app logs separation |
| ASVS V8 (data protection) | §6 |
| ASVS V10 (malicious code) | §5.4 scanning, T-07 parser isolation, optional AV |
| ASVS V14 (build/config) | §5.4 lockfiles/SBOM, §5.5 container hardening, DEPLOYMENT_GUIDE |
| NIST SP 800-53: AU (audit), AC (access), IA (identification), MP/SI (media & system integrity), SC (comms protection), RA (risk assessment) | mapped through §2–§7; a full control-by-control crosswalk is deferred to M14 as `docs/compliance/asvs-crosswalk.md` |

**Assurance activities per milestone:** threat-model review, RBAC route-enumeration test, secret-scan
gate, dependency-scan gate, integrity-sweep test, chain-verification test, and a negative-testing
pass (attempt every forbidden action and assert the specific deny reason). See TESTING_STRATEGY §7.

---

## 9. Known limitations (stated plainly)

1. **Timestamps can be forged.** No software can prevent a device or tool from writing a false
   capture time. We detect, label, and corroborate — we do not certify (T-19).
2. **Deepfake detection is unreliable in the wild.** Adversarially crafted synthetic media can evade
   every known detector, and heavily compressed authentic media routinely triggers them. The platform
   reports indicators with intervals and never a verdict (DF-01, AR-4).
3. **Metadata absence is not evidence of tampering.** Messaging platforms strip metadata by design.
   We report stripping signals factually without implying intent (META-04, R-5).
4. **A root-level host compromise can defeat in-database tamper evidence.** Hash chains raise the
   cost and make tampering detectable; off-host anchoring and backups are the real mitigation (T-02).
5. **Parser vulnerabilities are unavoidable.** We contain them (isolation, limits, no API-process
   parsing) rather than claiming immunity (T-07).
6. **ALPR accuracy degrades sharply** with blur, angle, glare, low resolution, and non-standard plate
   formats; hence top-N candidates and mandatory human confirmation.
7. **v1 has no HSM, no RLS, no multi-tenant isolation, and single-host HA limits.** Each is a
   documented, tracked decision (D-004, D-006, D-010), not an oversight.
8. **Prompt injection is unsolved.** Assistant scoping and tool restriction reduce, not eliminate,
   the risk (T-16).

---

*End of SECURITY_ARCHITECTURE.md — v0.1.0 DRAFT. No controls are implemented yet; the first
(authn, RBAC, audit chain) land in milestones M2 and M4.*
