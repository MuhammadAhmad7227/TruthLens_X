# ADR-0007 — Local inference by default; external AI providers behind an audited admin opt-in

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-007 |
| **Related** | [ADR-0021](ADR-0021-external-ai-activation-and-egress-confirmation.md), [ADR-0012](ADR-0012-data-residency-no-default-egress.md), [AI_ARCHITECTURE](../AI_ARCHITECTURE.md) |

## Context

The investigation assistant is an LLM-backed feature operating on case material that may be
legally sensitive. The owner directed: a provider-independent adapter interface, **local Ollama
initially**, vLLM as an optional future adapter, external providers **disabled by default**, an
explicit `ENABLE_EXTERNAL_AI` setting defaulting to `false`, activation requiring an authorized
administrator action, and **never falling back to cloud AI automatically when local inference fails.**

## Decision

1. A provider-independent **`InferenceProvider` protocol** with a `locality` attribute. Adapters:
   `OllamaProvider` (default), `VLLMProvider` (optional future), `OpenAICompatibleProvider` (gated),
   `StubProvider` (CI), `NullProvider`.
2. **`LLM_PROVIDER=local`** by default. `ENABLE_EXTERNAL_AI=false` by default and cannot be true
   without also satisfying the confirmation requirements of ADR-0021.
3. **The provider is fixed at startup.** There is no runtime provider switch, which makes cloud
   fallback *structurally impossible* rather than merely discouraged. `fallback_attempted` is always
   `false`.
4. Local inference failure returns `422 ASSISTANT_UNAVAILABLE`. The user sees a failure, never a
   silently-substituted answer from an external provider.
5. Activation of an external provider requires an authorized administrator action, with audit
   recording **provider, model, actor, timestamp, case reference, data categories transmitted and
   request purpose** (protocol in ADR-0021).
6. **API keys are server-side only.** No `NEXT_PUBLIC_*` variable may hold a provider key; CI greps
   the built frontend bundle to prove it.
7. Original evidence files, complete case records and sensitive metadata are **never** transmitted
   without explicit authorization plus a documented data-minimization process.
8. AI-generated findings are visually and structurally distinguished from verified forensic results,
   and assistant answers require evidence references and supporting analysis.

## Alternatives considered

| Option | Verdict |
|---|---|
| Cloud-first with local fallback | Rejected — inverts the residency guarantee and makes accidental egress the default path. |
| Runtime provider selection per request | Rejected — creates an automatic cloud-fallback path, which the owner explicitly forbade. |
| No assistant in v1 | Rejected — the capability is in scope; the risk is managed by gating rather than omission. |

## Rationale

Fixing the provider at startup converts a policy ("never fall back to cloud") into an architectural
property that cannot be violated by a bug, a retry loop or a misconfiguration.

## Consequences

* Local models are less capable than frontier cloud models; the assistant must state its
  uncertainty and limitations, and must never invent evidence, sources, timestamps or conclusions.
* Enabling external AI is a deliberate, expiring, auditable act — not a config-file edit that takes
  effect silently.
* `StubProvider` keeps CI deterministic without any model download (risk RR-3).

## Licensing implications

Ollama is MIT; vLLM is Apache-2.0. Model weights are audited **separately** from the serving stack —
see `THIRD_PARTY_LICENSE_AUDIT.md` and the `models.lock.json` loader contract, which refuses any
artifact whose `weights_licence` is empty or whose `allow_fetch` is not `true`.

## Security implications

Default posture is zero external egress for AI. Kill switches exist at three layers: application
flag, Redis token revocation, and host nftables. Every activation, transmission and revocation is
audit-recorded.

## Reversal strategy

Adding vLLM or another OpenAI-compatible provider means implementing the protocol and registering the
adapter; no schema or API change. Reverting to local-only is a config change.

## Verification

* Unit test: `LLM_PROVIDER=external` without `ENABLE_EXTERNAL_AI=true` **aborts startup**.
* Unit test: a failing local provider yields `422 ASSISTANT_UNAVAILABLE` and performs **zero**
  outbound calls (asserted on a mocked transport).
* CI grep proves no provider key appears in the built frontend bundle.
* Audit assertion: activation writes provider, model, actor, timestamp, case reference, data
  categories and purpose.
