# ADR-0011 — Filesystem storage backend only; the S3 interface exists but no S3 code ships in v1

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-011 |
| **Refinement flagged ⚠️** | Yes — the proposal was "interface now, adapter disabled"; the owner's ratification is **interface plus filesystem only, with no S3 implementation at all** in v1. |
| **Related** | [ADR-0005](ADR-0005-single-host-docker-compose-deployment.md), [ADR-0006](ADR-0006-luks2-volume-encryption-only.md) |

## Context

The M0 proposal offered an S3 adapter behind a disabled flag. The owner ratified a narrower position:
**no S3 code in v1.** Shipping a disabled, untested adapter would be a placeholder presented as a
capability — which the owner's standing instructions forbid.

## Decision

1. `StorageBackend` is defined as an **interface** with a single production implementation,
   `FilesystemBackend`.
2. `STORAGE_BACKEND` accepts only `filesystem`. Any other value **aborts startup** with a message
   stating that object storage is not available in v1.
3. **No S3, MinIO or object-store client library is added to the dependency graph**, disabled or not.
4. The interface is deliberately shaped for a future object store:
   * it has **no `overwrite` method** — objects are write-once, matching content-addressed storage;
   * `open_readonly` returns a **handle, not a filesystem path**, so a future backend can stream
     without exposing a local path;
   * all operations are keyed by SHA-256 digest, never by user-supplied filename.
5. Layout: `/srv/truthlens/evidence/originals/<sha256[0:2]>/<sha256[2:4]>/<sha256>` (write-once),
   with `derivatives/{thumbs,frames,heatmaps,transcripts,overlays,audio,reports}`, plus `intake/`,
   `quarantine/`, `anchors/`, `models/`, `backups/`, `config/`.
6. Write path: temp file → `fsync` → `O_EXCL` rename into place → `chmod 0440` → `chattr +i`.
   Originals are mounted **read-only** for every service except the ingest worker.
7. Deduplication is logical: `physical_objects` has `UNIQUE(sha256)` and N `evidence_items` may
   reference one physical object.

## Alternatives considered

| Option | Verdict |
|---|---|
| Ship a disabled S3 adapter | **Rejected** — untested code presented as an available capability. |
| Store originals in PostgreSQL BLOBs | Rejected — 50 TB target is not viable in-database, and it couples evidence availability to DB maintenance. |
| No interface, direct filesystem calls | Rejected — would make the v2 object-store migration a rewrite of every caller. |

## Rationale

An interface costs almost nothing and is testable today. An unimplemented adapter costs a dependency,
a test surface and a false impression of capability.

## Consequences

* v1 is bound to the local filesystem and therefore to the single host (ADR-0005) and its LUKS2
  volume (ADR-0006).
* `O_EXCL` rename plus `chattr +i` gives write-once semantics at the filesystem level, independent of
  application bugs.
* Storage roots must be **absolute and non-overlapping**; overlapping roots abort startup because they
  would let a derivatives purge delete originals.

## Licensing implications

None — first-party. Avoiding an object-store SDK also avoids adding its transitive licence graph.

## Security implications

Write-once originals are the foundation of evidential integrity: even a compromised application
cannot silently alter an original that is `0440` and immutable-flagged on a read-only mount. Content
addressing makes tampering detectable by re-hashing.

## Reversal strategy

v2: implement `S3Backend` against the existing interface, migrate by digest copy, and widen the
`STORAGE_BACKEND` validator. Callers do not change because they never received a filesystem path.

## Verification

* Unit test: `STORAGE_BACKEND=s3` **aborts startup** with an honest "not available in v1" message.
* Unit test: writing the same content twice yields one `physical_objects` row and one file.
* Unit test: a second write to an existing digest is refused (no `overwrite` exists to call).
* Unit test: overlapping and relative storage roots are both refused.
* Integration test: after the write path completes, the file mode is `0440`.
