# ADR-0022 — Redis pinned to 7.2 (BSD-3); upgrading is a licence event

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-001 consequence (licence gate) |
| **Related** | [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §1.4, §8.4 · [ADR-0001](./ADR-0001-permissive-default-dependency-set.md) |

## Context
Redis licensing changed upstream: **Redis 7.2 and earlier are BSD-3-Clause**; Redis 7.3+/8.x moved to
RSALv2/SSPLv1, with AGPLv3 later added as an option. A routine base-image bump would therefore silently
introduce a source-available or copyleft licence into the stack — exactly the failure mode the licence
gate exists to prevent.

## Decision
1. Pin **`redis:7.2-alpine`** by **digest**, not by tag.
2. The CI licence gate **fails on any `redis:8*`, `redis:7.3*` or `redis:latest` reference** anywhere
   in `infra/`, compose files, Dockerfiles, or documentation examples.
3. Redis is used only as a broker, cache, rate-limit counter, token denylist and lock store. It is
   **never** the sole store for anything that must survive: the Celery **result backend is PostgreSQL**.
4. Upgrading Redis past 7.2 is a **licence event** requiring an ADR amendment, a re-audit of
   THIRD_PARTY_LICENSE_AUDIT, and an owner decision — not a patch bump.
5. If an upgrade ever becomes necessary for security reasons, the alternatives to evaluate first are
   **Valkey** (BSD-3, Linux Foundation fork of Redis 7.2) and **KeyDB**, since our usage is
   broker/cache only and Valkey is largely drop-in.

## Alternatives considered
| Option | Verdict |
|---|---|
| Track `redis:latest` | **Rejected** — silent licence change and silent behavioural change |
| Redis 8 with AGPLv3 option selected | Rejected — copyleft in the default stack, contradicting ADR-0001 |
| Valkey from day one | Deferred — Redis 7.2 is already BSD-3 and battle-tested; Valkey becomes the natural path if an upgrade is forced |
| Drop Redis; use Postgres as the broker | Rejected — Celery with a Postgres broker is workable but worse for throughput and adds contention to the system of record |

## Rationale
Our Redis usage is shallow and substitutable, so there is no technical pressure to upgrade — which
means the pin costs nothing and protects a real licence property.

## Consequences
**Positive:** the default stack stays permissive; the broker is replaceable; security updates still
arrive via 7.2.x patch releases.
**Negative / accepted costs:** we forgo Redis 8 features (largely irrelevant to broker/cache use);
eventual migration to Valkey or a licensed Redis is a planned task, not an emergency; 7.2 will
eventually fall out of upstream security support, which is the trigger to revisit.

## Licensing implications
Redis 7.2 = **BSD-3-Clause** ✅. Redis 8 = RSALv2/SSPLv1 (+ AGPLv3 option) ⚠️/🚫. Valkey = BSD-3 ✅.
`redis-py` client 8.1.0 = MIT ✅ (client licence is independent of server licence).

## Security implications
Redis holds the token denylist, rate-limit counters and locks — sensitive but reconstructible. It
requires a password (`requirepass`), is never published to the host, sits on the internal `data`
network, runs with AOF enabled and `maxmemory-policy noeviction` (**never** evict broker messages),
and is included in encrypted backups (BACKUP_RECOVERY §4, B-7). A Redis compromise can disrupt
availability and rate limiting but cannot alter evidence, findings or the audit chain — those are in
PostgreSQL with append-only grants.

## Reversal strategy
Swap the image reference to Valkey (drop-in for our usage) or to a licensed Redis, update the licence
audit, amend this ADR. No application code change is expected because we use only standard
broker/cache primitives; the denylist and lock implementations are simple key operations.

## Verification
- CI licence gate test: a compose file referencing `redis:8` fails the build.
- Test: `redis-server` version reported by `/api/v1/status` starts with `7.2`.
- Test: with Redis flushed, task results remain retrievable from the Postgres result backend
  (proving Redis is not a system of record).
