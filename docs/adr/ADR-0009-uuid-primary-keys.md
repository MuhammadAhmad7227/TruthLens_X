# ADR-0009 — UUIDv7 for append-only high-volume tables; UUIDv4 elsewhere

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 (owner approved the proposed default) |
| **Decision ID** | D-009 |
| **Related** | [DATABASE_DESIGN.md](../DATABASE_DESIGN.md) §1.1, §10 |

## Context
`audit_logs`, `custody_events`, `model_invocations`, `integrity_checks`, `detections` and
`transcript_segments` are append-only and grow to millions of rows. Random UUIDv4 primary keys
scatter inserts across the B-tree, causing page splits, cache misses and index bloat.

## Decision
- **UUIDv7** (time-ordered) for: `audit_logs`, `custody_events`, `model_invocations`,
  `integrity_checks`, `detections`, `transcript_segments`, `derivatives`, `analysis_jobs`.
- **UUIDv4** for low-volume, long-lived, externally referenced entities: `users`, `cases`,
  `evidence_items`, `physical_objects`, `ai_models`, `reports`.
- Postgres 16 has no native `uuidv7()`, so a small **PL/pgSQL function** is added by migration
  (CSPRNG random bits, 48-bit millisecond timestamp). Native `uuidv7()` on PG18 would replace it.
- Both are `uuid` type, so no schema or ORM change is required to switch later.

## Alternatives considered
| Option | Verdict |
|---|---|
| UUIDv4 everywhere | Rejected — measurable insert performance and index-bloat penalty on append-only tables at target scale (1M+ items) |
| UUIDv7 everywhere | Rejected — no benefit for low-volume tables, and time-ordering leaks creation time in an id that may appear in URLs and reports |
| Bigserial integers | Rejected — enumerable, and leaks volume information in a forensic context where ids appear in URLs and exports |
| Wait for PG18 native `uuidv7()` | Rejected — pins the DB version to a roadmap item; the PL/pgSQL function is 20 lines and removable |

## Rationale
Time-ordered keys where insert volume is high; opaque keys where ids are externally visible. The
information-leak argument against UUIDv7 in URLs is why externally referenced entities stay v4.

## Consequences
**Positive:** better insert locality, smaller effective index size, BRIN-friendly ordering, cheaper
partition pruning on time-partitioned audit tables.
**Negative / accepted costs:** a custom PL/pgSQL function to maintain; UUIDv7 embeds a millisecond
creation timestamp (accepted for internal-only tables); mixed id semantics require a documented rule
(this ADR).

## Licensing implications
None. The function is our own code (no `uuid6`/`uuid7` extension dependency).

## Security implications
UUIDv4 remains for any id that reaches a URL, report or export, so no creation-time or volume
information leaks externally. Append-only table ids are internal. Unpredictability of v4 ids is
**never** relied on as an access control — the capability gate is (ADR-0004).

## Reversal strategy
Both are `uuid`. Migrating a table from v4 to v7 (or back) affects only *new* rows; existing ids stay
valid. Reversal is a change to the column default in one migration.

## Verification
- Migration test asserts the default for each listed table produces a version-7 UUID
  (`substring(id::text, 15, 1) = '7'`) and version-4 elsewhere.
- Insert-benchmark test on 1M synthetic audit rows records index size for the release notes.
