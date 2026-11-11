# ADR-0007 — Local-first AI assistant; external providers behind an audited administrator opt-in

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-007 |
| **Decided by** | Project owner, with 18 attached conditions |
| **Related** | [AI_ARCHITECTURE.md](../AI_ARCHITECTURE.md) (full specification) · [ADR-0021](./ADR-0021-ai-egress-minimisation-no-fallback.md) · [ADR-0004](./ADR-0004-single-organisation-capability-rbac.md) |

## Context
The assistant reasons over case data: transcripts, findings, metadata, entities. Sending that to an
external provider moves evidence-derived content off infrastructure the organisation controls.

## Decision
**Local default, external API behind an audited administrator opt-in.** All 18 conditions of the
approval are normative and specified in [AI_ARCHITECTURE.md](../AI_ARCHITECTURE.md) §1. In summary:

1. A **provider-independent adapter interface** (`InferenceProvider`) with `locality: local|external`
   as a first-class field that every egress control keys on.
2. **Ollama** is the shipped local adapter; **vLLM** is a first-class optional adapter.
3. External providers are **disabled by default**; no external cloud SDK is even installed.
4. `ENABLE_EXTERNAL_AI=false` by default; startup **aborts** if `LLM_PROVIDER=external` while the
   gate is false.
5. Activation is an **administrator action** with a mandatory justification, an expiry (≤30 days), an
   acknowledgement of the egress disclosure, notification to case leads, and a hash-chained audit record.
6. Every AI interaction is audited with provider, model, actor, timestamp, case reference,
   **data categories transmitted** and request purpose.
7. Original evidence bytes, derivative media, complete case records, full metadata dumps, GPS
   coordinates, plate values and face embeddings are **never** transmittable under any configuration.
8. A **per-request confirmation** step is required before any external transmission; the server
   enforces a bound, expiring confirmation token independently of the UI.
9. Redaction is applied (secrets, PII patterns, coordinate fuzzing, entity masking, filename
   normalisation) and is documented as **pattern-based best-effort**.
10. API keys live in server-side secret management only; a CI test greps the built client bundle for
    key-shaped strings and asserts every `NEXT_PUBLIC_*` value is allowlisted.
11. AI-generated output is **structurally** distinct from verified forensic findings: `ai_messages`
    has no verification column, and the report builder cannot read assistant tables at all.
12. Assistant answers require **evidence references**; citations are validated against the retrieved
    set, and an answer with no valid citation is persisted as `unsupported = true` (DB CHECK).
13. The assistant states uncertainty and limitations, and is prevented from inventing evidence,
    sources, timestamps or forensic conclusions by post-generation linting and refusal templates.
14. Model name, version, provider, **prompt template version**, guardrail version and analysis
    references are logged on every invocation.
15. An administrator-controlled **kill switch** exists at three levels (application flag, Redis token
    revocation, host egress rule).
16. **No automatic cloud fallback** when local inference fails — see ADR-0021.

## Alternatives considered
| Option | Verdict |
|---|---|
| External API only | **Rejected** — evidence-derived data leaves the host by default; unacceptable for real casework |
| Local only, no external option | Rejected — some deployments have adequate local hardware constraints and a legitimate, governed need for a frontier model |
| External with a one-time global consent | Rejected — per-request confirmation with a category preview is the only design that keeps the user informed about *what* is leaving |

## Rationale
Defaulting local preserves the data-residency property that the rest of the platform is built on,
while the audited opt-in keeps a genuinely useful capability available for deployments that can
justify it. Egress is treated as a privileged, temporary, revocable act rather than a feature toggle.

## Consequences
**Positive:** no case data leaves the host by default; egress is deliberate, previewed, bounded,
logged and revocable; the assistant cannot contaminate forensic findings or reports.
**Negative / accepted costs:** local inference needs hardware (~16 GB VRAM, or ~32 GB RAM quantised)
and is less capable than a frontier API; per-request confirmation adds friction — deliberately;
redaction cannot catch every identifier embedded in natural language, which is disclosed to the user
rather than hidden.

## Licensing implications
Ollama is MIT; vLLM is Apache-2.0. **Local model weights are operator-supplied** and must be
registered in `models.lock.json` with their own weight licence verified (THIRD_PARTY_LICENSE_AUDIT
§5.3) — the platform does not fetch them. External providers introduce **no** code licence obligation
but do introduce contractual and data-processing obligations that counsel should review before
enablement.

## Security implications
Mitigates **T-16** (prompt-injection-driven cross-case exfiltration) by enforcing `case_id` at the
query layer with a required (not optional) parameter; mitigates data leakage via the never-send list,
category allowlist, confirmation token and kill switch; mitigates key exposure via server-side-only
secrets and the client-bundle scan. Residual: prompt injection is unsolved generally, and
pattern-based redaction is incomplete — both disclosed (SECURITY_ARCHITECTURE §9.8).

## Reversal strategy
Adapters are pluggable behind one interface. To make external the default would require changing
`ENABLE_EXTERNAL_AI`'s default **and** amending this ADR with a legal basis; the never-send list,
confirmation token and kill switch are not configurable away in production (startup aborts). To remove
the assistant entirely: disable the feature flag; `ai_messages` rows are retained for audit.

## Verification
- Startup test: `LLM_PROVIDER=external` + `ENABLE_EXTERNAL_AI=false` → process aborts.
- Egress test with default config: attempt a transmission and assert **zero** outbound connections.
- Confirmation test: request without a valid token → `403 EGRESS_CONFIRMATION_REQUIRED`.
- Fallback test: failing local provider → `ASSISTANT_UNAVAILABLE` with `fallback_attempted=false`.
- Injection test: hostile instructions embedded in a fixture transcript yield no out-of-case data.
- Citation test: a hallucinated evidence id is discarded; an answer left with no citation is
  persisted `unsupported=true`.
- Secret test: a canary `LLM_EXTERNAL_API_KEY` appears in no log, response, DB row, PDF or bundle.
