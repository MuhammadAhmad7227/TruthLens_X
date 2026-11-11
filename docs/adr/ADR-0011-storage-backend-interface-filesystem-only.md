# ADR-0011 — `StorageBackend` interface in v1; filesystem implementation only, S3 adapter deferred

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-011 |
| **Refinement flagged** | ⚠️ My original proposal was "S3 adapter written but disabled". D-005 condition 13 requires interfaces to stay *modular so S3 can be introduced later* — which the interface satisfies without shipping untested code. **Changed to: interface + filesystem implementation only.** Dead-but-shipped code is a liability, not an option. |
| **Related** | [ADR-0005](./ADR-0005-single-host-docker-compose.md) · [SYSTEM_ARCHITECTURE.md](../SYSTEM_ARCHITECTURE.md) §10 |

## Context
D-005 mandates a single-host filesystem deployment now, with storage interfaces modular enough to
adopt S3-compatible storage later without a redesign.

## Decision
1. Define `StorageBackend` as an explicit interface: `put_atomic(stream, key) -> ObjectRef`,
   `open_readonly(key, scope) -> ReadHandle`, `set_immutable(key)`, `verify_sha256(key)`,
   `delete(key, justification)`, `stat(key)`, `signed_url(key, ttl, purpose)`, `scope(org, case)`.
2. Implement **`FilesystemBackend`** only in v1.
3. **Do not implement `S3Backend` in v1.** Document it as a future adapter with the interface it must
   satisfy.
4. `physical_objects.storage_backend` records which backend holds each object, so a future migration
   is per-row and hash-verified.
5. The `scope` parameter exists now (unused beyond validation) so per-organisation storage roots are a
   wiring change when tenancy arrives (ADR-0004).
6. `signed_url` is part of the interface even though the filesystem implementation generates an
   application-level HMAC URL rather than a presigned one — keeping the contract stable.

## Alternatives considered
| Option | Verdict |
|---|---|
| Implement S3 now, disabled | **Rejected** — untested code paths rot; violates "no placeholder features presented as completed" |
| No interface, direct filesystem calls | **Rejected** — would make the later S3 change a rewrite, violating D-005 condition 13 |
| Use an object store locally (MinIO) | Rejected — an extra stateful service on a single host with no v1 benefit |

## Rationale
An interface is cheap and constrains the design correctly today; an unexercised implementation is
expensive and misleading. The abstraction is validated by the filesystem implementation and by tests
that use a second in-memory fake backend, proving the interface is genuinely backend-agnostic.

## Consequences
**Positive:** no dead code; the abstraction is proven by two implementations (filesystem + test fake);
S3 adoption later is additive.
**Negative / accepted costs:** S3 adoption later costs ~5 days instead of ~0; object-lock/WORM
semantics must be designed then (the filesystem path uses `chattr +i` and read-only mounts instead).

## Licensing implications
None in v1. A future S3 adapter would use `boto3` (Apache-2.0) ✅.

## Security implications
The interface makes the write-once property explicit (`set_immutable`, no `overwrite` method exists).
`open_readonly` returns a handle rather than a path, so callers cannot construct arbitrary paths —
which is what makes threat T-08 (path injection) structurally difficult. `signed_url` requires a
`purpose` argument, so the audit record always has one.

## Reversal strategy
Implement `S3Backend` against the existing interface, copy objects with hash verification before and
after, flip `storage_backend` per row, keep the filesystem copy until verification passes. No
application-code change outside the adapter.

## Verification
- Unit tests run the full storage contract suite against both `FilesystemBackend` and the in-memory
  fake, so any interface change must satisfy both.
- Test asserts no `overwrite`-style method exists on the interface.
- Test asserts `open_readonly` cannot be coerced into a write.
