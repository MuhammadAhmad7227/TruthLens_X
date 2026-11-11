# ADR-0021 — External AI activation protocol: bound, expiring grants and per-request egress confirmation

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 · emerged from the licence and AI audit, not from a D-0NN proposal |
| **Decision ID** | Refines D-007 and D-012 |
| **Related** | [ADR-0007](ADR-0007-local-default-ai-with-gated-external-providers.md), [ADR-0012](ADR-0012-data-residency-no-default-egress.md), [AI_ARCHITECTURE §4](../AI_ARCHITECTURE.md) |

## Context

ADR-0007 fixes the provider at startup so automatic cloud fallback is structurally impossible. That
leaves the question of what a *deliberate* activation must look like. The owner required: activation
by an authorized administrator, a **clear confirmation step before external transmission**, audit of
provider/model/actor/timestamp/case/data-categories/purpose, data minimisation, redaction where
technically possible, an **administrator-controlled kill switch**, and a prohibition on transmitting
original evidence files, complete case records or sensitive metadata without explicit authorization.

## Decision

1. Activation is an **administrator `POST`** requiring the `enable_external_ai` capability, a written
   justification, an acknowledgement, and an `expires_at` **no more than 30 days** out. It writes an
   `ai_external_grants` row, and a **database `CHECK` constraint enforces the expiry bound** so no
   code path can create a perpetual grant.
2. Activation writes audit event `admin.ai.external_enabled` and notifies case leads.
3. A scheduled beat job **expires grants automatically**; an expired grant is refused at request time
   as well (`EGRESS_GRANT_EXPIRED`).
4. **Per-request confirmation**: sending anything requires a bound, expiring `confirmation_token`
   obtained from `POST …/messages:egress-preview`. Without it the request is rejected with
   **`403 EGRESS_CONFIRMATION_REQUIRED`**. The token is bound to the specific previewed payload, so
   confirming a small payload does not authorize a larger one.
5. `LLM_EGRESS_CONFIRMATION_REQUIRED=false` **aborts startup in production.** The confirmation step
   cannot be turned off where it matters.
6. **Never transmittable, under any grant or confirmation**: original evidence bytes, derivative
   media, complete case records, full metadata dumps, GPS coordinates, plate values, face embeddings,
   secrets, and data from other cases.
7. A **category allowlist** (`LLM_EXTERNAL_ALLOWED_CATEGORIES`) governs what may be sent. The default
   is **empty**, so enabling external AI alone authorises nothing; categories must be listed
   explicitly. `EGRESS_CATEGORY_NOT_ALLOWED` is returned otherwise.
8. Redaction is applied where technically possible before transmission, and the preview endpoint shows
   the operator **exactly** what will be sent.
9. **Three independent kill switches**: the application flag, Redis token revocation, and a host
   nftables egress rule. Any one stops transmission.
10. Every invocation logs model name, version, provider and **prompt template version**, plus the
    analysis references that grounded the answer.
11. Assistant answers must cite evidence references validated against the retrieved set. Below
    `LLM_RETRIEVAL_MIN_SCORE` the system returns a **templated refusal without calling the model at
    all** — it will not guess.
12. `ai_messages` carries a `CHECK` requiring **citations or `unsupported=true`**, and has no
    verification-status column: an assistant message can never be marked as a verified finding.

## Alternatives considered

| Option | Verdict |
|---|---|
| One-time activation, then unrestricted sending | Rejected — a single decision would authorize unlimited future transmission of case material. |
| Confirmation via a UI checkbox in client code | Rejected — must be a server-bound token, or a modified client bypasses it. |
| Perpetual grants | Rejected — the DB `CHECK` on `expires_at` exists precisely to make this impossible. |
| Default allowlist of "safe" categories | Rejected — empty-by-default forces a conscious choice per deployment. |
| Call the model and filter the answer afterwards | Rejected — filtering after transmission does not undo the transmission. |

## Rationale

Binding confirmation to a previewed payload makes the operator's consent specific and informed rather
than abstract. Enforcing the expiry bound in the database, not the application, means a future code
change cannot silently create a permanent grant.

## Consequences

* External AI is genuinely awkward to use. That friction is the design.
* The preview endpoint must render the exact transmission, which means building redaction before
  building sending.
* `fallback_attempted` is always `false`; a local failure is a visible failure.

## Licensing implications

External providers are a **service** relationship, not a dependency, so no licence enters the
dependency graph. Provider terms of service — including any training-on-inputs clause — are the
operator's to review before activation, and the acknowledgement field records that they did.

## Security implications

Defence in depth: capability check → grant validity → category allowlist → per-request bound token →
redaction → three kill switches → audit. A failure at any layer stops transmission rather than
degrading it. The refusal-without-calling rule prevents both an ungrounded answer and an unnecessary
egress event.

## Reversal strategy

Disabling is immediate and total: flip the flag, revoke tokens in Redis, close the nftables rule.
Grants expire on their own within 30 days regardless.

## Verification

* Unit tests: `LLM_PROVIDER=external` without `ENABLE_EXTERNAL_AI=true` aborts startup;
  `LLM_EGRESS_CONFIRMATION_REQUIRED=false` aborts in production; `LLM_ALLOW_EXTERNAL_EGRESS=true`
  requires the master gate; `external` requires a real API key.
* Unit test: `external_ai_effectively_enabled` requires **all three** switches.
* Migration test: inserting a grant with `expires_at` beyond 30 days violates the `CHECK`.
* Test: a request without a valid `confirmation_token` is rejected 403 and makes **zero** outbound
  calls.
* Test: a token bound to payload A cannot authorize payload B.
* Test: a below-threshold retrieval returns the templated refusal and the model is **not** called.
* Test: an expired grant is refused with `EGRESS_GRANT_EXPIRED`.
* DB test: inserting an `ai_messages` row with neither citations nor `unsupported=true` is rejected.
