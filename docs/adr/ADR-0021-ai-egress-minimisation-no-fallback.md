# ADR-0021 — AI egress minimisation and the prohibition on automatic cloud fallback

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-007 conditions 7–10, 17, 18 |
| **Related** | [ADR-0007](./ADR-0007-local-first-ai-assistant.md) · [AI_ARCHITECTURE.md](../AI_ARCHITECTURE.md) §4, §7 · [ADR-0012](./ADR-0012-data-residency-no-egress-by-default.md) |

## Context
ADR-0007 establishes local-first inference. This ADR fixes the two properties that make that promise
real under failure and under configuration drift: what may be transmitted, and what happens when local
inference fails.

## Decision
1. **Never-send list** (no configuration can enable these): original evidence bytes, derivative
   images/frames/heat-maps/spectrograms, complete case records, complete raw metadata dumps, full GPS
   coordinates, plate values, face/biometric embeddings, credentials, and any data from a case other
   than the one in scope.
2. **Category allowlist**: `LLM_EXTERNAL_ALLOWED_CATEGORIES` defaults to **empty**, so even with
   external AI enabled nothing may be sent until an administrator explicitly allows named categories,
   each with its own character budget and redaction profile.
3. **Redaction** is applied in a fixed order (secrets → PII patterns → coordinate fuzzing → entity
   masking → filename normalisation → length bounding) and is documented to users as
   **pattern-based best-effort**, because it cannot catch every identifier embedded in free text.
4. **Truncation is visible.** Budget overruns produce an explicit `[truncated]` marker shown to the
   user and recorded in the audit log — never silent.
5. **No automatic fallback to a cloud provider when local inference fails.** The response is
   `ASSISTANT_UNAVAILABLE` with `fallback_attempted: false`. **No fallback code path exists**, so this
   cannot be violated by a future refactor that "helpfully" adds one.
6. **Kill switch at three levels**: application flag (immediate), Redis confirmation-token revocation
   (immediate), and a host egress rule restricting the API container to configured provider hosts
   (immediate). Any one level stops egress.
7. Enabling external AI is **time-bounded** (≤30 days) and expires automatically, audited as
   `admin.ai.external_expired`. There is no permanent enablement.

## Alternatives considered
| Option | Verdict |
|---|---|
| Cloud fallback for resilience | **Rejected** — a silent egress event during an outage is the worst possible time to disclose data, and nobody is watching to confirm it |
| Allow all categories once external AI is enabled | Rejected — coarse; per-category allowlisting keeps disclosure proportional to need |
| Claim redaction is comprehensive | **Rejected** — it is not, and saying so would be a false assurance. Disclosed in the confirmation modal instead |

## Rationale
Requirement 18 exists because "fall back to the cloud if local fails" is the single most likely way a
well-intentioned engineer would silently break a data-residency guarantee. Removing the code path
entirely is stronger than documenting a prohibition.

## Consequences
**Positive:** egress is bounded, previewed, category-limited, time-limited and revocable at three
levels; a local outage degrades availability but never confidentiality.
**Negative / accepted costs:** an outage means no assistant — accepted, and the honest outcome;
per-category budgets may truncate context and reduce answer quality, which is disclosed rather than
hidden.

## Licensing implications
None beyond ADR-0007 (Ollama MIT, vLLM Apache-2.0; external providers are contractual, not code-licence,
matters for counsel to review before enablement).

## Security implications
Directly mitigates T-16 and the data-leakage arm of the assistant threat model. The never-send list is
enforced by construction (no code reads originals into a prompt) rather than by filtering. Residual:
pattern-based redaction is incomplete — disclosed.

## Reversal strategy
Adding a fallback would require amending this ADR with an explicit owner decision and a legal basis,
because it changes a confidentiality property, not a performance one. Categories and budgets are
configuration and freely adjustable (audited).

## Verification
- Test: with default config, an egress attempt makes **zero** outbound connections (instrumented adapter counter).
- Test: failing local provider → `ASSISTANT_UNAVAILABLE`, `fallback_attempted=false`, zero external calls.
- Test: a category not in the allowlist is refused even when external AI is enabled.
- Test: over-budget content is truncated with the marker visible in both the response and the audit record.
- Test: expired enablement blocks transmission and writes `admin.ai.external_expired`.
- Test: the kill switch takes effect within one request, at each of the three levels independently.
