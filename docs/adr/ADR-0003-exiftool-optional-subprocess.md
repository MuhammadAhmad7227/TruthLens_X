# ADR-0003 — ExifTool as an optional, subprocess-isolated extractor with a pure-Python fallback

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-003 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [THIRD_PARTY_LICENSE_AUDIT §3.1 (finding L-1)](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

ExifTool is the de-facto standard for reading camera, GPS, device and maker-note metadata, and M8
depends on it. Its licence position is genuinely ambiguous and was verified by reading upstream text:

* The distribution `LICENSE` file contains the **full GPLv3** text and GitHub detects `GPL-3.0`.
* The README's *COPYRIGHT AND LICENSE* section states: *"Copyright 2003-2026, Phil Harvey. This is
  free software; you can redistribute it and/or modify it under the same terms as Perl itself
  (either the Perl Artistic License or GPL)."*

A Perl-style dual licence lets the **recipient elect** the Artistic License, which is far less
restrictive than GPL. Recorded as finding **L-1**: the election may substantially reduce exposure,
but this is a legal judgement we are not entitled to make on the owner's behalf.

## Decision

1. `ENABLE_EXIFTOOL=true` is the default **but ExifTool is invoked strictly as an external
   subprocess** (`exiftool -json -G1 -api LargeFileSupport=1`), never linked or imported.
2. A **pure-Python fallback** (Pillow + pikepdf + a minimal EXIF/XMP/ICC reader) is always present
   and is used automatically when the binary is absent. Metadata extraction therefore never hard-fails
   because of a licensing choice.
3. The binary is installed in the `worker-cpu` image only, **not** in `api`.
4. Redistribution status, deployment requirements and the L-1 ambiguity are documented in
   `docs/THIRD_PARTY_LICENSE_AUDIT.md` and in `docs/DEPLOYMENT_GUIDE.md`, including how to build a
   deployment that contains no ExifTool at all.
5. Removing ExifTool is a documented, supported configuration — not a degraded or unsupported mode.
6. Subprocess invocation uses an argument vector (never a shell string), a timeout, output size
   caps and no `shell=True`.

## Alternatives considered

| Option | Verdict |
|---|---|
| Drop ExifTool entirely | Rejected — the pure-Python fallback cannot read most maker notes; M8 quality would drop materially. |
| Rely on the Artistic election and treat it as settled | Rejected — that is legal advice we must not give (owner instruction: never claim compliance without a proper audit). |
| Vendor a modified ExifTool | Rejected — forking increases, not reduces, obligation. |

## Rationale

Subprocess isolation means the platform is not a derivative work of ExifTool under either licence
reading, and the fallback makes the dependency genuinely optional. The ambiguity is disclosed rather
than resolved by assumption.

## Consequences

* Two extraction code paths must both be tested; results must agree on the common subset.
* Slightly slower than an in-process library (process spawn per file); acceptable because M8 runs in
  a background worker.
* The provenance record must state **which** extractor produced each metadata field, so a reviewer
  can assess it.

## Licensing implications

Unresolved-by-design. L-1 is an open item for counsel; the deployment can be made ExifTool-free
without code changes. We do **not** claim compliance — we claim isolation, optionality and disclosure.

## Security implications

ExifTool parses untrusted input and has had CVEs. Mitigations: subprocess isolation, no shell,
resource limits, timeout, output caps, and execution in the egress-blocked `isolated` network. A
compromise is contained to a worker container that holds no secrets and no database credentials
beyond the read-only `tlx_worker` role.

## Reversal strategy

Set `ENABLE_EXIFTOOL=false` to run pure-Python only, or remove the package from the worker image.
Both are configuration changes; no schema or API impact.

## Verification

* A CI job builds and tests the worker image with ExifTool **absent** and asserts metadata extraction
  still succeeds via the fallback.
* Provenance rows record `extractor: exiftool|python` and the version.
* `grep -r "shell=True"` in the metadata module returns nothing (CI-blocking).
