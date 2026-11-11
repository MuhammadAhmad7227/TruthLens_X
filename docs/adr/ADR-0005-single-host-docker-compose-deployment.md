# ADR-0005 — Single on-premises host with Docker Compose; no Kubernetes in v1

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-005 |
| **Related** | [ADR-0006](ADR-0006-luks2-volume-encryption-only.md), [ADR-0011](ADR-0011-filesystem-storage-backend-only.md), [DEPLOYMENT_GUIDE](../DEPLOYMENT_GUIDE.md), [BACKUP_RECOVERY](../BACKUP_RECOVERY.md) |

## Context

The owner directed a **single on-premises host** running all services under Compose, with no
Kubernetes in v1, and required that single-host availability limits be documented **honestly**.
Storage and deployment interfaces must stay modular so S3 and distributed deployment can arrive later.

## Decision

1. All services run via **Docker Compose** on one host. Deployables: `frontend` (Next standalone),
   `api` (`python:3.11-slim`, **no torch, no model weights**), `worker-cpu` (ffmpeg + exiftool),
   `worker-gpu` (CUDA 12.x + PyTorch), `beat`, `pgvector/pgvector:pg16`, **`redis:7.2-alpine`
   digest-pinned**, `nginx:1.27-alpine`, optional ClamAV.
2. **Only nginx publishes ports.** Every other service is reachable solely on internal networks.
3. Three networks: `edge` (nginx ↔ frontend/api), `data` (api/workers ↔ postgres/redis), `isolated`
   (media analysis workers — **no egress**).
4. Evidence originals live on a private filesystem volume **outside any publicly served directory**.
   Derived artifacts are stored separately. **Evidence is never exposed through a public URL**;
   access is via HMAC-signed short-lived URLs streamed by the API (ADR-0004).
5. Persistent named volumes for Postgres, Redis, evidence and models; explicit `resource limits`,
   `restart: unless-stopped`, and health checks on every service.
6. Long-running forensic jobs run in Celery workers and **never block API request handling**; the API
   enqueues and returns immediately.
7. **No Kubernetes, no Helm, no `infra/k8s/` directory** in v1.
8. Availability limits are stated plainly in `docs/BACKUP_RECOVERY.md` §7.1: **no hot standby,
   realistic RTO 4–8 h** against a nominal 4 h target, RPO ≤24 h from nightly backups. The document
   does not claim high availability.

## Alternatives considered

| Option | Verdict |
|---|---|
| Kubernetes | Rejected — a single-host cluster buys no availability and adds substantial operational load. |
| Systemd units instead of Compose | Rejected — loses image immutability and reproducible dependency pinning. |
| Two hosts with streaming replication | Deferred to v2; interface kept modular so it can be added. |

## Rationale

Compose matches the actual failure domain: one machine. Pretending otherwise produces a runbook
nobody can execute at 03:00. Honest RTO/RPO figures let the owner make a real risk decision.

## Consequences

* The host is a single point of failure; recovery depends on backups and documented DR procedures.
* `api` must stay weight-free so it can restart in seconds; GPU work is confined to `worker-gpu`.
* Operators get one `docker compose` command surface instead of cluster tooling — a genuine
  operational win at this scale.

## Licensing implications

All images are built from permissively licensed bases. `redis:7.2-alpine` is BSD-3; Redis 8 moved to
RSALv2/SSPLv1 — see ADR-0022 for the pin and CI gate.

## Security implications

No published ports except nginx; media workers have no network egress, so a malicious evidence file
cannot exfiltrate; volume encryption per ADR-0006; firewall, SSH hardening and restricted service
permissions documented in `DEPLOYMENT_GUIDE.md`.

## Reversal strategy

Service definitions are per-container with explicit networks and volumes, so a later migration to
Kubernetes or a multi-host split is a manifest-generation exercise, not a redesign. The `StorageBackend`
interface (ADR-0011) already abstracts the filesystem.

## Verification

* `docker compose config` validates in CI (the sandbox has no Docker daemon, so this runs in the
  workflow, not locally — risk RR-2).
* A CI check fails on any service other than nginx declaring `ports:`.
* A CI check fails on `redis:8*` or `redis:7.3*` (ADR-0022).
* Load test confirms the API stays responsive while a long forensic job runs.
