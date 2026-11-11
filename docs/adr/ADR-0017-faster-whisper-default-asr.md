# ADR-0017 — faster-whisper (MIT) as the default ASR engine

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-017 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [ADR-0012](ADR-0012-data-residency-no-default-egress.md), [THIRD_PARTY_LICENSE_AUDIT §5.3](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

Audio forensics (M11) needs automatic speech recognition to produce transcripts and time-aligned
segments. Two Whisper implementations were audited: `openai-whisper` (reference, PyTorch) and
`faster-whisper` (CTranslate2). **Both the code and the model weights of OpenAI's Whisper are MIT** —
verified from the upstream README: *"Whisper's code and model weights are released under the MIT
License."* This is unusually clear for a model family and was a decisive factor.

## Decision

1. **`ASR_ENGINE=faster-whisper`** is the default. CTranslate2 inference is roughly 4× faster and
   substantially lower memory than the reference implementation, at identical weights.
2. **`ASR_ENGINE=openai-whisper`** remains selectable for parity checks and for operators who prefer
   the reference implementation.
3. Both engines consume the **same MIT weights**, provisioned offline by
   `infra/scripts/fetch-models.sh` and recorded in `models.lock.json` with `weights_licence: MIT`.
4. Weights are **never downloaded at runtime** by default (`ALLOW_MODEL_DOWNLOAD=false`, ADR-0012).
5. Transcripts are stored as `transcript_segments` with UUIDv7 ids (ADR-0009), each carrying model
   name, version, provider, start/end offsets and a confidence measure with a stated basis.
6. Transcripts are **derivative artifacts**, stored separately from originals, and are labelled as
   machine-generated requiring human verification.
7. **Speaker diarisation weights are a separate, unresolved licence question** — recorded as finding
   **L-6** (`pyannote` models require acceptance of gated terms). Diarisation ships **disabled**;
   if enabled later, it needs its own flag and its own licence verification.

## Alternatives considered

| Option | Verdict |
|---|---|
| `openai-whisper` as default | Rejected as default — slower and heavier for identical output; retained as an option. |
| Vosk / Kaldi | Viable and Apache-2.0, but lower accuracy on the multilingual material this platform targets. |
| Cloud ASR | Rejected outright — transmitting evidence audio off-host breaches ADR-0012 and the never-transmittable list. |
| Ship bundled weights in the image | Rejected — multi-GB images, and weights must be operator-provisioned and hash-verified (risk RR-3). |

## Rationale

Same weights, better runtime, both MIT. There is no licensing tension to resolve, so the choice is
purely operational — and faster inference directly serves the ingest throughput target.

## Consequences

* Two engine code paths must both be tested; a parity fixture asserts segment boundaries agree within
  tolerance.
* CTranslate2 adds a native dependency to the worker image (not to `api`).
* Diarisation is visibly absent in v1; the UI states this rather than showing an empty speaker column.

## Licensing implications

Clean: code MIT, weights MIT, CTranslate2 Apache-2.0. **L-6 remains open for diarisation weights** and
gates that feature, not ASR.

## Security implications

Runs on the `isolated` network with no egress, so audio content cannot leave the host during
transcription. Model artifacts are hash-verified at load; a mismatch fails closed (ADR-0001 §9).

## Reversal strategy

The engine is selected by configuration behind a common `TranscriptionEngine` interface. Switching is
a config change; switching model size is a provisioning change.

## Verification

* Parity test: both engines on the same short fixture produce segments whose boundaries agree within
  a stated tolerance.
* Loader test: a `models.lock.json` entry with a mismatched SHA-256 is **refused**, with no fallback.
* Test: transcripts are written to the derivatives tree, never into the originals tree.
* UI/report string-lint: transcripts are labelled machine-generated and `requires_human_verification`
  is true with no code path setting it false.
