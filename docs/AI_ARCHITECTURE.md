# TruthLens X — AI Architecture

| | |
|---|---|
| **Document ID** | TLX-DOC-011 |
| **Version** | 1.0.0 |
| **Last updated** | 2026-11-10 |
| **Status** | Current — ratified |
| **Related** | [ADR-0007](adr/ADR-0007-local-default-ai-with-gated-external-providers.md) · [ADR-0012](adr/ADR-0012-data-residency-no-default-egress.md) · [ADR-0021](adr/ADR-0021-external-ai-activation-and-egress-confirmation.md) · [ADR-0023](adr/ADR-0023-weight-free-deepfake-indicators.md) · [SECURITY_ARCHITECTURE](SECURITY_ARCHITECTURE.md) · [API_SPECIFICATION](API_SPECIFICATION.md) |

---

## 1. The governing principle

> **AI outputs in TruthLens X are investigative indicators, not confirmed facts.**

Every AI-produced result must carry, at minimum:

1. **Supporting evidence** — references to the specific artifacts and analysis results it rests on.
2. **Model information** — name, version, provider, and the **prompt template version**.
3. **Confidence, where meaningful** — always with a stated `confidence_basis` and, for advisory
   scores, an interval rather than a point.
4. **Limitations** — a `limitations_code` that is `NOT NULL`, with the limitation text snapshotted at
   the time of the analysis so a later wording change cannot retroactively alter what a result meant.
5. **Human verification status** — `requires_human_verification` defaults to `true` and there is **no
   code path that sets it to `false`**. A human moves a finding to `confirmed` or `rejected`, and must
   write `verification_notes` to do so.

The system **never** fabricates forensic results and **never** claims guaranteed deepfake detection
accuracy. Where it cannot support an answer, it says so — see §4.5.

These are not aspirations. They are enforced by database `CHECK` constraints (§6) and by a
string-lint test (§8) that fails CI on overclaiming language.

---

## 2. Provider abstraction

```
                    ┌────────────────────────┐
   assistant API ──▶│  InferenceProvider     │  protocol
                    │  .locality             │  ('local' | 'external')
                    │  .complete(request)    │
                    └───────────┬────────────┘
             ┌──────────────┬───┴──────────┬───────────────┬──────────────┐
             ▼              ▼              ▼               ▼              ▼
     OllamaProvider   VLLMProvider   OpenAICompatible  StubProvider   NullProvider
      (DEFAULT)       (optional)      Provider (gated)    (CI)        (off)
       local            local            external       external*     n/a
```

\* `StubProvider` reports `locality='external'` in CI so that egress-guard tests exercise the
external code path **without any network access**.

### 2.1 The protocol

| Member | Purpose |
|---|---|
| `locality` | `'local'` or `'external'`. **Drives every egress decision** — it is not informational. |
| `model_id` | Exact model name and version actually used, recorded on every invocation. |
| `complete(request)` | Single entry point. `request` carries messages, retrieval context, generation limits and a `purpose`. |
| `health()` | Reachability probe for `/readyz` (registered as **not required** in M1, required from M17). |

### 2.2 The provider is fixed at startup

**There is no runtime provider switch.** The provider is resolved once during application startup from
`LLM_PROVIDER` and the grant state, and cannot change for the life of the process.

This makes automatic cloud fallback **structurally impossible** rather than merely discouraged. A
retry loop, an exception handler, a timeout path or a misconfiguration cannot fall back to an external
provider, because no code exists that could select one. `fallback_attempted` is therefore always
`false`, and that field exists only so the guarantee is auditable rather than implicit.

> **Requirement:** *never fall back to cloud AI automatically when local inference fails.*
> Satisfied architecturally — see [ADR-0007](adr/ADR-0007-local-default-ai-with-gated-external-providers.md).

### 2.3 Adapters

| Adapter | Locality | Status | Notes |
|---|---|---|---|
| `OllamaProvider` | local | **Default** | MIT. Local HTTP on the `data` network; never published to a host port. |
| `VLLMProvider` | local | Optional, future | Apache-2.0. Higher throughput; same locality guarantees. |
| `OpenAICompatibleProvider` | external | **Gated** | Requires a bound grant (§4) and a confirmation token (§4.3). |
| `StubProvider` | external | CI only | Deterministic canned responses; zero network calls. Keeps CI hermetic (risk RR-3). |
| `NullProvider` | — | Configured-off | Refuses every request with `ASSISTANT_UNAVAILABLE`. Used when the assistant is disabled. |

Local inference failure returns **`422 ASSISTANT_UNAVAILABLE`**. The user sees a failure — never a
silently substituted answer from a different provider.

---

## 3. Configuration

```ini
# ── Provider selection (fixed at startup) ────────────────────────────────
LLM_PROVIDER=local                      # local | external | stub | null
OLLAMA_BASE_URL=http://ollama:11434     # data network only, never published
OLLAMA_MODEL=<operator-provisioned>
LLM_REQUEST_TIMEOUT_SECONDS=120
LLM_MAX_TOKENS=2048
LLM_TEMPERATURE=0.0                     # deterministic by default for forensic use

# ── External AI — all four required, see ADR-0021 §Verification ──────────
ENABLE_EXTERNAL_AI=false                # master gate; cannot be true without the rest
LLM_ALLOW_EXTERNAL_EGRESS=false         # requires ENABLE_EXTERNAL_AI=true
LLM_EGRESS_CONFIRMATION_REQUIRED=true   # false ABORTS startup in production
LLM_EXTERNAL_ALLOWED_CATEGORIES=        # EMPTY by default — enabling AI alone authorises nothing
LLM_EXTERNAL_API_KEY=                   # server-side only; never in NEXT_PUBLIC_*
LLM_EXTERNAL_GRANT_MAX_DAYS=30

# ── Retrieval grounding ──────────────────────────────────────────────────
LLM_RETRIEVAL_MIN_SCORE=0.62            # below this: templated refusal, model NOT called
LLM_RETRIEVAL_TOP_K=8
LLM_PROMPT_TEMPLATE_VERSION=v1.0.0      # logged with every invocation
```

### 3.1 Startup validation — fail closed

Each rule aborts startup with a message naming the offending variable. All are unit-tested.

| Condition | Result |
|---|---|
| `LLM_PROVIDER=external` without `ENABLE_EXTERNAL_AI=true` | **Abort** |
| `LLM_ALLOW_EXTERNAL_EGRESS=true` without `ENABLE_EXTERNAL_AI=true` | **Abort** |
| `LLM_EGRESS_CONFIRMATION_REQUIRED=false` in production | **Abort** — requirement 9 of ADR-0021 is not negotiable |
| `LLM_PROVIDER=external` with an empty or placeholder API key | **Abort** |
| `ENABLE_EXTERNAL_AI=true` in production without a valid, unexpired grant | Refuse at request time (`EGRESS_GRANT_EXPIRED`) |

`external_ai_effectively_enabled` is true only when **all three** switches are set *and* a real key is
present. It is reported by `/api/v1/status` so an operator can verify posture at a glance.

---

## 4. External AI activation and the egress protocol

Full rationale in [ADR-0021](adr/ADR-0021-external-ai-activation-and-egress-confirmation.md).

### 4.1 Activation (administrator only)

```
POST /api/v1/admin/ai/external-grants          capability: enable_external_ai
{
  "provider": "openai-compatible",
  "model": "<exact model id>",
  "justification": "<written reason — required, non-empty>",
  "expires_at": "2026-12-01T00:00:00Z",          // ≤ 30 days — DB CHECK enforces this
  "acknowledgement": true                        // operator confirms they reviewed provider ToS
}
```

* Writes an `ai_external_grants` row. A **database `CHECK` constraint** enforces
  `expires_at <= now() + interval '30 days'`, so no code path can create a perpetual grant.
* Writes audit event **`admin.ai.external_enabled`** recording provider, model, actor, timestamp,
  case reference, data categories and purpose.
* Notifies case leads.
* A scheduled beat job **expires grants automatically**; expiry is also re-checked at request time.

### 4.2 Data minimisation

Redaction is applied before transmission wherever technically possible. The **preview endpoint shows
the operator exactly what will be sent** — the same bytes, not a summary of them.

### 4.3 Per-request confirmation

```
POST /api/v1/cases/{case_id}/assistant/messages:egress-preview
  └─▶ returns { preview, confirmation_token, expires_at, categories }

POST /api/v1/cases/{case_id}/assistant/messages
  X-Egress-Confirmation: <confirmation_token>     // bound to the previewed payload
```

Without a valid token the request is rejected **`403 EGRESS_CONFIRMATION_REQUIRED`** and **zero**
outbound calls are made. The token is **bound to the specific previewed payload**, so confirming a
small payload does not authorize a larger one. Tokens are revocable via Redis (kill switch 2).

### 4.4 Never transmittable — under any grant or confirmation

| Category | Why |
|---|---|
| Original evidence bytes | The core residency guarantee |
| Derivative media (frames, thumbnails, audio, overlays) | Same content, different container |
| Complete case records | Aggregation reveals more than any single field |
| Full metadata dumps | Can identify a person or a device |
| **GPS coordinates** | Identifies movements of a real person |
| **Plate values** | Direct identifier; [ADR-0013](adr/ADR-0013-alpr-examples-only-and-registry-lookup-hard-disabled.md) |
| **Face embeddings** | Biometric identifier |
| Secrets, keys, tokens | Obvious |
| Data from **other cases** | Cross-case leakage is the highest-signal insider indicator |

The category allowlist (`LLM_EXTERNAL_ALLOWED_CATEGORIES`) is **empty by default**: enabling external
AI alone authorises the transmission of *nothing*. Categories must be listed explicitly, and anything
not listed returns `EGRESS_CATEGORY_NOT_ALLOWED`.

### 4.5 Grounding and refusal

Assistant answers must cite evidence references, and citations are **validated against the retrieved
set** — a citation to something that was not retrieved is rejected, not passed through.

When retrieval scores fall below `LLM_RETRIEVAL_MIN_SCORE`, the system returns a **templated refusal
without calling the model at all**. This prevents both an ungrounded answer and an unnecessary egress
event. The assistant states its uncertainty and limitations and **never invents evidence, sources,
timestamps or conclusions.**

### 4.6 Kill switches — three independent layers

| # | Layer | Effect | Latency |
|---|---|---|---|
| 1 | Application flag `ENABLE_EXTERNAL_AI=false` | No new grants; provider resolves to local | Next request |
| 2 | Redis token revocation | All outstanding confirmation tokens die | Immediate |
| 3 | Host `nftables` egress rule | **No packets leave**, regardless of application state | Immediate |

Any single layer stops transmission. Layer 3 is the one that holds even if the application is
compromised.

---

## 5. Model registry and artifact provenance

```
models/                                  # 0555, read-only mount
├── <family>/<version>/
│   ├── model.bin
│   └── manifest.json
└── models.lock.json                     # the authority — see below
```

`models.lock.json` records, per artifact:

| Field | Purpose |
|---|---|
| `sha256` | Integrity |
| `code_licence` | Licence of the code that runs the model |
| `weights_licence` | Licence of the weights **themselves** — audited separately ([ADR-0001](adr/ADR-0001-permissive-default-dependency-set.md) §9) |
| `weights_licence_source` | The URL or document the licence was read from |
| `weights_licence_verified_at` | When it was verified — a licence can change |
| `commercial_use_cleared` | Explicit boolean, not inferred |
| `legal_review_id` | Links to the review that cleared it |
| `allow_fetch` | Whether automated fetching is permitted at all |

**The loader refuses any artifact where `allow_fetch != true`, `weights_licence` is empty, or the
SHA-256 does not match — fail closed, never fall back.** A model that cannot be verified is not
substituted with a convenient alternative; the capability reports itself unavailable.

Other registry rules:

* Weights are **never committed to git**. CI uses `StubProvider` and tiny synthetic fixtures (RR-3).
* Exactly one `is_default` per `(family, task)` — enforced by a partial unique index.
* Artifacts are provisioned offline by `infra/scripts/fetch-models.sh` on a networked machine, then
  copied in and hash-verified. `ALLOW_MODEL_DOWNLOAD=false` by default ([ADR-0012](adr/ADR-0012-data-residency-no-default-egress.md)).
* **Only self-measured performance figures are ever displayed.** A benchmark from a paper is never
  shown as though it described this deployment.

---

## 6. Honesty enforcement in the schema

Honesty is a database property, not a code convention. From [DATABASE_DESIGN §8](DATABASE_DESIGN.md):

**`analysis_results`:**

* **No verdict column exists.** There is no field in which "fake" or "authentic" can be stored.
* Any `advisory_score` requires **both** `score_confidence_low` and `score_confidence_high`.
* Any `confidence` requires a non-empty `confidence_basis`.
* Status `confirmed` or `rejected` requires `verification_notes`.
* `verified_by IS NULL` while the status is unverified.
* `limitations_code` is `NOT NULL`, with limitation text snapshotted at analysis time.
* `requires_human_verification` defaults `true`; no code path sets it `false`.

**`ai_messages`:**

* `CHECK` requires **citations OR `unsupported=true`** — an uncited, unflagged message cannot be stored.
* **No verification-status column.** An assistant message can never be marked as a verified finding.

**Reports:** the report builder **cannot read assistant tables** ([ADR-0019](adr/ADR-0019-report-manifest-hashing-with-optional-crypto-signing.md)).
Unverified assistant output cannot be laundered into attested work product.

**Superseded results** are retained with `is_current=false` — never deleted, because the fact that an
earlier analysis differed is itself evidentially relevant.

---

## 7. Deepfake analysis — weight-free by decision

M14 implements **classical signal indicators**, each independently explainable, with **no third-party
weights**. Full rationale in [ADR-0023](adr/ADR-0023-weight-free-deepfake-indicators.md).

| Indicator | Signal examined |
|---|---|
| **Spectral (DCT / FFT)** | GAN and diffusion generators leave characteristic spectral fingerprints and periodic artifacts |
| **Boundary blending** | Face-swap compositing leaves seam, colour-temperature and noise-floor discontinuities |
| **Landmark symmetry / geometry** | Physiological implausibility: blink rate, pupil circularity, landmark jitter |
| **Temporal flicker** | Per-frame generators produce unstable high-frequency detail across consecutive frames |
| **Lip-sync mismatch** | Audio-visual correlation between phoneme timing and mouth movement |
| **Vocoder roll-off** | Synthetic speech shows characteristic high-frequency spectral truncation |

Output is an **advisory score with an interval** plus a mandatory `confidence_basis`. Each indicator
reports **individually** as well as in aggregate, so a reviewer can see which signal fired and discount
the ones they judge inapplicable.

**Stated limitation, in the product, not hidden:** classical indicators are weaker than a
state-of-the-art classifier against sophisticated, well-compressed material, and are sensitive to
re-encoding. The limitations text says so explicitly.

---

## 8. Testing the honesty properties

| Property | Test |
|---|---|
| No verdict can be stored | Schema assertion: `analysis_results` has no verdict-capable column |
| Confidence bounds required with any score | Migration test rejects a row with a score and no bounds |
| Basis required with any confidence | Migration test rejects a row with confidence and empty basis |
| Verification notes required | Migration test rejects `confirmed` without notes |
| Unverified ⇒ no verifier | Migration test rejects `verified_by` set while status is unverified |
| Limitations always present | `NOT NULL` + a test that no code path omits it |
| No automatic human-verification bypass | Search for the assignment **plus** a mutation test |
| Assistant messages need citations or a flag | DB `CHECK` rejects a row with neither |
| Reports exclude assistant content | Test asserts the builder raises if asked; no read path exists |
| No automatic cloud fallback | Mocked transport asserts **zero** outbound calls when local inference fails |
| Refusal without calling the model | Below-threshold retrieval returns the template; provider is never invoked |
| Egress confirmation is bound | A token for payload A cannot authorize payload B |
| No overclaiming language | **String-lint test (AR-1…AR-8)** — CI-blocking |
| No published benchmarks shown | Test asserts no third-party benchmark figure appears in any response |

### 8.1 Banned phrases (AR-1 … AR-8)

The string-lint test fails CI if any of these appear in a template, UI string, report or prompt:

> "confirmed fake" · "proven authentic" · "is a deepfake" · "guilty" · "100% accurate" ·
> "guaranteed detection"

Permitted framing: *"advisory indicator"*, *"consistent with"*, *"requires human verification"*,
*"confidence interval"*, *"limitations apply"*.

The assistant UI carries a persistent footer — **"AI-generated — not a forensic finding"** — asserted
by test.

---

## 9. API key handling

* Provider API keys are **server-side only**. They are read from configuration at startup and never
  returned by any endpoint.
* **No `NEXT_PUBLIC_*` variable may hold a provider key.** CI greps the **built frontend bundle** to
  prove it — grepping source is insufficient, since a build step could inline one.
* Keys are treated as sensitive by the logging redaction processor: `api_key`, `apikey`, `api-key`,
  `authorization`, `token`, `secret` and `sk-…`-shaped values are replaced with `[REDACTED]`
  unconditionally.
* `/api/v1/status` reports **secret names only, never values** — `secret_names_set()` returns booleans.

---

## 10. Distinguishing AI output from verified forensic results

| Dimension | AI-generated | Verified forensic result |
|---|---|---|
| Visual treatment | Distinct styling + persistent "AI-generated — not a forensic finding" footer | Standard result styling |
| Storage | `ai_messages`, `analysis_results` with `requires_human_verification=true` | `analysis_results` with a human `verified_by` and `verification_notes` |
| Mutability | Append-only conversation history | Immutable; a correction creates a superseding row |
| In reports | **Excluded entirely** — the builder cannot read assistant tables | Included with full provenance |
| Confidence | Interval + stated basis, or `unsupported=true` | Human attestation with notes |
| Capability | `use_assistant` | `verify_finding` (a different capability; `admin` cannot self-verify) |

---

## 11. Milestone delivery

| Milestone | AI scope |
|---|---|
| **M1** | Configuration and fail-closed validation only. `StubProvider`/`NullProvider` exist so the gates are testable. **No inference.** |
| M7 | Celery plumbing for long-running inference jobs |
| M9–M13 | Classical and operator-weighted analysis engines; model registry and `models.lock.json` loader |
| **M14** | Weight-free deepfake indicators |
| M15 | Similarity search, pgvector embeddings (hard-scoped by `case_id` + `vector_set`) |
| **M17** | Assistant: retrieval grounding, citations, refusal path, egress protocol, grant lifecycle |
| M19 | Admin dashboard: grant management, kill switches, model registry UI |
| M20 | Security hardening: egress rule verification, audit-chain checks |

**M1 delivers no AI capability and claims none.** The configuration gates above are implemented and
tested in M1 precisely so that no later milestone can enable external AI without them.
