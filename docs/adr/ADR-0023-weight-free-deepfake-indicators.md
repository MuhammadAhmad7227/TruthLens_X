# ADR-0023 — Deepfake analysis uses weight-free classical indicators in v1

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-001 consequence (artifact licence audit) + PRD Module 11 |
| **Related** | [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §5 (W-11), §5.2, §6 (DS-4) · [MASTER_PRD.md](../MASTER_PRD.md) Module 11, §5 (AR-1…AR-8) |

## Context
The licence audit produced a decisive finding: published deepfake detectors are overwhelmingly
**research-licensed / non-commercial**, and the datasets they are trained and evaluated on —
FaceForensics++ (non-commercial research), Celeb-DF, DFDC (CC BY-NC 4.0) — cannot be used in a
commercial or operational forensic product without separate permission. This is a case where the
licence audit changed the technical design, not just the paperwork.

## Decision
1. **M14 ships no third-party deepfake detection weights.** No pretrained synthetic-media classifier
   is bundled, fetched, or defaulted on.
2. Deepfake analysis is implemented as an ensemble of **classical, weight-free signal-processing
   indicators**:
   - DCT/FFT spectral analysis for GAN/CNN upsampling fingerprints and characteristic grid artifacts
   - face-boundary blending and edge-inconsistency statistics
   - landmark symmetry and reflection/eye/teeth artifact heuristics
   - temporal identity flicker and head-pose jitter across frames
   - lip-motion versus audio-energy correlation mismatch
   - audio vocoder indicators (high-frequency roll-off, harmonic regularity, spectral fingerprints)
3. Indicators aggregate into an **advisory score with a mandatory confidence interval** and
   `requires_human_verification = true`, which no code path can set to false.
4. Every result carries its versioned limitations statement, including the fixed text that no
   deepfake detector is reliable in the wild and that compressed authentic media routinely triggers
   these indicators.
5. Any learned detector added later requires: a verified permissive weight licence, a new ADR, its own
   `models.lock.json` entry, and a measured-performance record on our own evaluation set.
6. Our **internal evaluation set** must be synthetic or self-generated, containing no
   third-party-copyrighted media and no real personal data (TESTING_STRATEGY §12).

## Alternatives considered
| Option | Verdict |
|---|---|
| Bundle a published deepfake classifier | **Rejected** — weights and training datasets are research/non-commercial licensed (W-11, DS-4) |
| Train our own classifier | **Rejected for v1** — requires a licensed dataset we cannot obtain, significant compute, and would produce a model whose generalisation we could not honestly characterise |
| Omit deepfake analysis entirely | Rejected — the brief requires the module, and classical indicators are genuinely informative *when framed as indicators* |

## Rationale
This is the honest design as well as the legally clean one. A classical indicator's behaviour can be
explained, its failure modes enumerated, and its limitations stated precisely — which is exactly what
AR-4 demands. A black-box classifier trained on FaceForensics++ generalises poorly to real casework
(compressed, resized, platform-transcoded media) and **cannot** support a defensible limitations
statement, so it would push the product toward overclaiming.

## Consequences
**Positive:** no licence exposure; no multi-GB weights to manage for this module; indicators are
explainable; CPU-only execution works (no GPU dependency for M14); results are deterministic and
reproducible, which strengthens evidential defensibility.
**Negative / accepted costs:** lower discriminative power than a well-trained classifier on
*in-distribution* media; no ability to name a specific generation method; the advisory score must be
presented with wide intervals to remain honest. These are stated in the UI and the report, not
hidden.

## Licensing implications
OpenCV Apache-2.0, NumPy/SciPy BSD — **all cleared, no weights, no datasets, no open legal item** for
M14. This is the cleanest module in the AI stack from a licence perspective, as a direct result of
auditing artifacts separately from packages.

## Security implications
No model-supply-chain surface for this module (no weights to pin, fetch or verify). Deterministic
execution removes a class of non-reproducibility. The principal risk is **epistemic** — a user
over-trusting the advisory score — mitigated structurally by the interval requirement, the mandatory
limitations text, the verification state, the absence of any verdict field, and the honesty
string-lint test.

## Reversal strategy
Additive. A learned detector can be introduced later as an additional indicator in the same ensemble,
behind a flag, with its own lock entry, ADR and measured-performance record. Because the aggregation
layer already combines heterogeneous indicators with intervals, no redesign is required. Removing it
again is a flag change.

## Verification
- Test: the M14 module imports no model-loading code and reads no file from `MODELS_ROOT`
  (static assertion + runtime check).
- Test: every indicator result includes provenance, confidence **with basis**, an interval, and the
  limitations snapshot.
- Test: a clean authentic fixture produces low indicators, and a heavily re-compressed authentic
  fixture produces **elevated** indicators — proving we surface the false-positive mode rather than
  hiding it.
- Test: `requires_human_verification` cannot be set false by any engine or API path.
- Honesty string-lint: no verdict phrasing anywhere in M14 UI or report copy.
