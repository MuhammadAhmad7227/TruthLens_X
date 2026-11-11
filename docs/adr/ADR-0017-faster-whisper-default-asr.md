# ADR-0017 — faster-whisper is the default ASR engine; openai-whisper available

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-017 |
| **Related** | [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §5 (W-1, W-2) |

## Context
Both `faster-whisper` (1.2.1) and `openai-whisper` (20250625) are **MIT**, and openai/whisper's README
explicitly states *"Whisper's code and model weights are released under the MIT License"* — verified
2026-11-10. So this is a performance and fidelity choice, not a licence one.

## Decision
1. Default engine: **`faster-whisper`** (CTranslate2 backend) — materially faster on CPU, lower
   memory, and the CPU-only default deployment (ADR-0005) benefits most.
2. `openai-whisper` remains selectable via `ASR_ENGINE=openai-whisper` for reference-fidelity checks.
3. Both sit behind one `AsrEngine` interface producing identical `transcript_segments` rows, with the
   engine name and version recorded on every invocation.
4. Model size is configurable (`ASR_MODEL_SIZE`): `base`/`small` for CPU deployments, `large-v3` where
   a GPU is present.
5. Word-level timestamps, detected language **and its probability**, and per-segment confidence are
   always recorded; transcripts are labelled machine output everywhere.
6. Weights are operator-provisioned via `fetch-models.sh` and pinned by SHA-256 in `models.lock.json`
   with `weights_licence: MIT`.

## Alternatives considered
| Option | Verdict |
|---|---|
| `openai-whisper` as default | Rejected — slower and heavier on CPU, which is the default deployment |
| A commercial cloud ASR API | **Rejected** — would transmit audio off-host, contradicting ADR-0012 |
| WhisperX or other derivatives | Deferred — extra dependencies and unclear weight provenance; the diarisation need is covered separately |

## Rationale
Same licence, same weights, better CPU throughput. Keeping both means any transcription can be
reproduced with the reference implementation if a result is ever challenged.

## Consequences
**Positive:** faster CPU transcription; a reference path for verification; MIT code **and** weights
(verified).
**Negative / accepted costs:** two code paths to keep contract-compatible; CTranslate2 conversion adds
a build step for custom models; quantisation differences can produce small transcript variations
between engines, which is why the engine and version are always recorded.

## Licensing implications
MIT for both packages; MIT explicitly stated for the weights. `ctranslate2` is MIT. **No open legal
item.** This is the cleanest weight-licence position of any AI component in the stack.

## Security implications
Audio is processed in the worker container only, on a read-only working copy. Transcripts may contain
personal data and are access-controlled, audited and covered by the optional PII-redaction derivative.
A missing model yields `error_class=MODEL_UNAVAILABLE` — **never** an empty transcript presented as
"no speech" (AR-7).

## Reversal strategy
Set `ASR_ENGINE`. Both produce the same rows; historical results remain interpretable because the
engine name and version are stored per invocation. Re-embedding/re-transcription on engine change is a
maintenance job, and old segments are superseded rather than deleted.

## Verification
- Golden test on a short synthetic fixture: deterministic transcript with a fixed model and seed on CPU.
- Contract test: both engines produce schema-identical `transcript_segments`.
- Failure test: model absent → `MODEL_UNAVAILABLE`, no empty-transcript result row.
- Test asserts `language_probability` and word timings are present, and that a diarisation result
  never contains a personal name (only `SPK_nn` labels).
