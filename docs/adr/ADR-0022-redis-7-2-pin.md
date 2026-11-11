# ADR-0022 — Pin redis:7.2-alpine by digest; Redis 8 is excluded by a CI gate

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 · emerged from the licence audit, not from a D-0NN proposal |
| **Decision ID** | Refines D-001 and D-005 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [ADR-0005](ADR-0005-single-host-docker-compose-deployment.md), [THIRD_PARTY_LICENSE_AUDIT §8.4](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

The licence audit found a trap that is easy to walk into during a routine base-image bump:

* **Redis ≤ 7.2 is BSD-3-Clause.**
* **Redis 8 moved to RSALv2 / SSPLv1**, later adding an AGPLv3 option.

RSALv2 and SSPLv1 are **not** open-source licences and restrict offering the software as a service.
A well-intentioned `redis:latest` or `redis:8-alpine` upgrade would silently change the platform's
licensing posture and break the ADR-0001 default-clean guarantee.

## Decision

1. Compose pins **`redis:7.2-alpine` by digest**, not by floating tag. The digest is recorded in the
   compose file and bumped only by a reviewed change.
2. **CI fails the build on any `redis:8*` or `redis:7.3*` reference** anywhere in the repository —
   compose files, Dockerfiles, documentation examples and test fixtures.
3. The Redis **client** library (`redis-py`, MIT) is unaffected and is pinned independently; the gate
   concerns the server image licence, not the client.
4. Upgrading past 7.2 requires either a new ADR accepting the licence change, or a migration to a
   BSD-licensed fork such as **Valkey**. Neither is planned for v1.
5. Redis holds only **ephemeral** data in v1: the Celery broker, the refresh-token `jti` denylist,
   rate-limit counters, short-lived locks and egress confirmation tokens. The **Celery result backend
   is PostgreSQL**, so no evidentially significant data lives in Redis and losing it is recoverable.

## Alternatives considered

| Option | Verdict |
|---|---|
| Redis 8 under RSALv2/SSPLv1 | Rejected — not open source; restricts service offering and contradicts ADR-0001. |
| Redis 8 under its AGPLv3 option | Rejected — network copyleft reaching the platform, the exact outcome ADR-0001 avoids. |
| Valkey (BSD-3, Linux Foundation fork) | **Viable and the preferred upgrade path** if 7.2 ever becomes unsupported. Not adopted now because 7.2 is supported and switching costs a migration for no present benefit. |
| KeyDB / Dragonfly | Considered; Valkey has the clearer governance and licence lineage. |
| Drop Redis, use PostgreSQL for queues | Rejected — Celery needs a low-latency broker; PostgreSQL `LISTEN/NOTIFY` is not a substitute at the target throughput. |

## Rationale

Requirement 5 is what makes this pin low-risk rather than merely conservative: because Redis holds
nothing durable, staying on a supported BSD version costs nothing operationally, and the CI gate
converts a legal judgement into a mechanical check that cannot be forgotten during an upgrade.

## Consequences

* Base-image updates for Redis are a deliberate, reviewed act rather than routine maintenance.
* Security patches must be tracked against the 7.2 branch; if 7.2 reaches end of support before v1
  ships, Valkey becomes the migration path and needs its own ADR.
* Documentation examples must use 7.2 too, or CI fails — which keeps the docs honest.

## Licensing implications

BSD-3-Clause for the server, MIT for the client. Both permissive; no copyleft, no source-disclosure
obligation, no restriction on offering the platform as a service.

## Security implications

Redis is on the `data` network only, never published to a host port (ADR-0005), and requires a
password. Because it holds denylist and lock state, a compromised Redis could revoke or un-revoke
sessions — which is why it is network-isolated and why the authoritative revocation record is also
audited in PostgreSQL.

## Reversal strategy

Migrating to Valkey is a compose image change plus a data-copy for the ephemeral state, which can
simply be allowed to expire. No application code change: the wire protocol is compatible.

## Verification

* CI gate test: scanning every compose file, Dockerfile and doc for `redis:8` or `redis:7.3` returns
  zero matches.
* A negative test injects `redis:8-alpine` into a fixture compose file and asserts the gate **fails**.
* Compose config validation asserts the image reference includes a `@sha256:` digest.
* Test: the Celery result backend is configured as PostgreSQL, not Redis.
