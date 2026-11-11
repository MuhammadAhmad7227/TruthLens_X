# ADR-0023 — M14 deepfake analysis uses classical weight-free indicators, not a classifier

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 · emerged from the licence audit, not from a D-0NN proposal |
| **Decision ID** | Refines D-001; implements the AI-responsibility requirements |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [AI_ARCHITECTURE §6](../AI_ARCHITECTURE.md), [THIRD_PARTY_LICENSE_AUDIT §5.2](../THIRD_PARTY_LICENSE_AUDIT.md), [DATABASE_DESIGN §8](../DATABASE_DESIGN.md) |

## Context

Deepfake detection is the feature most likely to be over-trusted and the hardest to license cleanly.
Two independent problems were found:

1. **Licensing.** Published deepfake detectors ship weights trained on datasets whose terms are
   frequently research-only or unstated. A permissive Python package does **not** make its weights
   permissive (ADR-0001 §9). No third-party deepfake weights are shipped or downloaded.
2. **Epistemics.** A trained classifier reports a number with no way to interrogate *why*, generalises
   poorly to generators it was not trained on, and invites exactly the overclaiming the owner forbids:
   never fabricate forensic results, never claim guaranteed deepfake detection accuracy.

## Decision

1. M14 implements **classical, weight-free signal indicators**, each independently explainable:
   * **DCT / FFT spectral analysis** — GAN and diffusion generators leave characteristic spectral
     fingerprints and periodic artifacts.
   * **Boundary blending detection** — face-swap compositing leaves seam, colour-temperature and
     noise-floor discontinuities at the blend boundary.
   * **Facial landmark symmetry and geometry** — physiological implausibility in blink rate, pupil
     circularity and landmark jitter.
   * **Temporal flicker / inter-frame consistency** — per-frame generators produce unstable high-
     frequency detail across consecutive frames.
   * **Lip-sync mismatch** — audio-visual correlation between phoneme timing and mouth movement.
   * **Vocoder roll-off** — synthetic speech shows characteristic high-frequency spectral truncation.
2. Output is an **advisory score with an interval** (`score_confidence_low` / `score_confidence_high`)
   and a mandatory `confidence_basis` explaining what the score rests on.
3. **`analysis_results` has no verdict column.** There is no field in which "fake" or "authentic" can
   be stored, so no code path can assert one.
4. `limitations_code` is **NOT NULL** with snapshotted limitation text, and
   `requires_human_verification` defaults to **true with no code path setting it false**.
5. Database `CHECK` constraints enforce honesty: any `advisory_score` requires both confidence bounds;
   any `confidence` requires `confidence_basis`; `confirmed`/`rejected` statuses require
   `verification_notes`; `verified_by` must be NULL while unverified.
6. Each indicator reports **individually** as well as in aggregate, so a reviewer can see which signal
   fired and discount the ones they judge inapplicable to the material.
7. **Only self-measured performance figures are ever displayed.** No published benchmark from a paper
   is shown as though it applied to this deployment.

## Alternatives considered

| Option | Verdict |
|---|---|
| Ship a pretrained deepfake classifier | Rejected — weights licence unverified (finding L-5 class of problem), and a black-box score invites overclaiming. |
| Download a detector at runtime behind a flag | Rejected — `ALLOW_MODEL_DOWNLOAD=false` (ADR-0012) and the loader refuses unaudited weights (ADR-0001 §9). |
| Report a single binary verdict | Rejected — the strongest possible overclaim, and forbidden by the owner's AI-responsibility rules. |
| Omit deepfake analysis from v1 | Rejected — weight-free indicators are genuinely informative and honest about their limits; omitting them would forfeit real value. |

## Rationale

Classical indicators are auditable: an examiner can be shown *which* artifact was found *where*, and
can disagree. A classifier score cannot be cross-examined. Explainability is not a nice-to-have in a
forensic context — it is the difference between an investigative indicator and an unusable assertion.

## Consequences

* Detection is weaker against sophisticated, well-compressed material than a state-of-the-art
  classifier might be. **This is stated in the product, not hidden.**
* Every result carries visible uncertainty, which the UI and reports must render rather than collapse
  into a badge or a colour.
* Indicators are sensitive to re-encoding and compression; the limitations text says so explicitly.

## Licensing implications

**Zero third-party weights.** All indicator code is first-party, built on permissively licensed signal
processing (`numpy`, `scipy`, `opencv-python-headless`, `Pillow` — all BSD/Apache/MIT). No face-
recognition model is used anywhere in the platform, which also avoids the biometric-processing legal
questions a recognition model would raise.

## Security implications

Indicators run in the egress-blocked `isolated` worker network on untrusted media, so a crafted file
cannot exfiltrate. Because no verdict is storable, a compromised analysis path cannot manufacture a
conclusion — it can only produce scores that a human must still verify.

## Reversal strategy

Adding a trained detector later is additive: it becomes another indicator with its own provenance row,
its own licence verification in `models.lock.json`, and the same honesty constraints. The absence of a
verdict column is permanent by design; any future classifier reports a score, never a conclusion.

## Verification

* Synthetic fixtures (a spliced boundary, a spectrally truncated audio clip, a temporally flickered
  frame sequence) produce a **non-zero** indicator response; clean fixtures produce a low one.
* Migration tests assert every honesty `CHECK` constraint rejects a violating row.
* Schema test: `analysis_results` has no column capable of storing a verdict.
* Test: no code path sets `requires_human_verification=false` (asserted by searching for the
  assignment and by a mutation test).
* String-lint test: "confirmed fake", "proven authentic", "is a deepfake", "guilty", "100% accurate"
  and "guaranteed detection" appear in no template, UI string or report — CI-blocking.
* Test: an unpublished benchmark figure never appears in any response payload.
