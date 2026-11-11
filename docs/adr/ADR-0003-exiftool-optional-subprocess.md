# ADR-0003 — ExifTool kept optional, subprocess-isolated, dual-licence election pending

| | |
|---|---|
| **Status** | Accepted with an open legal item — 2026-11-10 |
| **Decision ID** | D-003 |
| **Decided by** | Project owner ("Keep ExifTool integration optional. Document its Artistic License/GPL dual-licensing status, distribution requirements, and deployment considerations.") |
| **Related** | [ADR-0001](./ADR-0001-permissive-default-dependency-set.md) · [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §4.1, §10 (L-1) |

## Context
Two upstream sources were retrieved on 2026-11-10 and they differ:
- The repository `LICENSE` file contains the **GNU GPL v3** text; GitHub detects **GPL-3.0**.
- The `README` "COPYRIGHT AND LICENSE" section states: *"Copyright 2003-2026, Phil Harvey. This is
  free software; you can redistribute it and/or modify it under the same terms as Perl itself
  (**either the Perl Artistic License or GPL**)."*

This is the standard Perl dual-licence formulation, so an **Artistic election may be available**,
which would substantially reduce the GPL-3 exposure recorded in D-003.

## Decision
1. ExifTool remains the primary metadata extractor, invoked **only as a separate process**
   (`exiftool -j`, JSON over a pipe, argument list, never a shell).
2. It is **optional and removable**: `ENABLE_EXIFTOOL` (default `true`, but the system must be fully
   functional with it `false`).
3. A **pure-Python permissive fallback** (Pillow + pikepdf + ffprobe + a small EXIF/XMP reader) sits
   behind the same `MetadataEngine` interface and is exercised in CI by hiding the binary.
4. Install from the **distribution package** (`libimage-exiftool-perl`) rather than vendoring the
   tarball, so distro licence metadata and security updates apply.
5. The dual-licence status, distribution requirements and deployment considerations are documented in
   THIRD_PARTY_LICENSE_AUDIT §4.1.
6. Until **L-1** is answered by counsel, we treat ExifTool conservatively as GPL-3.

## Alternatives considered
| Option | Verdict |
|---|---|
| Drop ExifTool entirely, pure-Python only | **Rejected** — materially worse tag coverage across obscure formats; contradicts the brief's explicit requirement |
| ExifTool only, no fallback | **Rejected** — no exit path if the Artistic election is unavailable |
| Vendor the ExifTool tarball into the repo | **Rejected** — worse for updates and for distribution obligations |

## Rationale
ExifTool has no equal for tag coverage, and subprocess invocation is the standard containment for a
GPL tool. Keeping a tested fallback means the licence question can be resolved later without
re-architecting.

## Consequences
**Positive:** best-in-class metadata extraction preserved; a real exit path exists.
**Negative / accepted costs:** the fallback covers common tags only; we must maintain two code paths;
a subprocess per extraction has measurable overhead (batched via ExifTool's `-stay_open` where safe).

## Licensing implications
Elected licence **undetermined pending L-1**. Distribution requirements if bundled: ship the ExifTool
licence text and copyright notice inside the image (`/usr/share/doc/exiftool/`), name the elected
licence in the generated `THIRD_PARTY_LICENSES.md`, state that ExifTool is a separate program invoked
as a subprocess, and pin the version with its SHA-256 recorded in `models.lock.json`.

## Security implications
ExifTool parses hostile input by design. Controls: media-worker container only; read-only working
copy; `--` argument termination; hard timeout; CPU/memory limits; `isolated` network (no egress); no
shell; tag values are **data**, never interpreted as code or used in paths; output parsed as strict
JSON with a size cap.

## Reversal strategy
Set `ENABLE_EXIFTOOL=false` — the fallback is already tested and contract-compatible. Reversal cost:
reduced tag coverage, documented in the result's `extractor` field so consumers know which engine
produced a given record.

## Verification
- Test runs the same fixture through both engines and asserts the normalised schema is populated for
  the documented subset when ExifTool is absent.
- Test asserts `exiftool_version` and `invocation_args` are recorded on every extraction (META-06).
- Test asserts no `shell=True` and no filename interpolation anywhere in the runner.
