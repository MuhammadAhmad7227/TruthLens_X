# M9-M21 implementation map

This branch is the bulk implementation pass requested before the error-fixing pass.

| Milestone | Implemented code |
|---|---|
| M9 | image forensic adapters, ELA-safe screening, perceptual digest, annotations schema, workbench |
| M10 | PDF structure adapter, document pipeline, forensic schema |
| M11 | ffprobe + faster-whisper adapter, transcript schema |
| M12 | ffprobe + deterministic frame plan, video pipeline |
| M13 | detector contract, deterministic tracker fallback, ALPR format validation, detections/tracks/plate tables |
| M14 | spectral/deepfake advisory aggregation with interval and disclaimer |
| M15 | exact comparison, cosine similarity, comparison schema |
| M16 | deterministic graph layout, edge inference, timeline assembly/export |
| M17 | grounded assistant guardrails, citation/unsupported behavior |
| M18 | deterministic manifest builder and PDF renderer |
| M19 | admin lifecycle helpers, allowlisted settings, alert controls |
| M20 | negative-control helpers, hardening configuration, security controls, runbooks |
| M21 | release gates, E2E compose target, k6 load baseline, release-assurance workflow |

## Build-first rule

The implementation pass intentionally adds the complete cross-milestone code surface before CI/runtime
repair. The next phase is the comprehensive fixing pass: formatting, strict typing, dependency locks,
migration correctness, integration tests, security gates, E2E, and runtime verification.

All forensic results remain advisory and require human verification. Originals are not modified.
