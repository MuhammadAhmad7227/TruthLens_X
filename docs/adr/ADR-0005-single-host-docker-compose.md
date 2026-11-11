# ADR-0005 — Single on-premises Linux host with Docker Compose; no Kubernetes in v1

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-005 |
| **Decided by** | Project owner, with 15 attached conditions |
| **Related** | [ADR-0006](./ADR-0006-luks2-volume-encryption.md) · [BACKUP_RECOVERY.md](../BACKUP_RECOVERY.md) · [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) |

## Context
Forensic deployments are frequently on-premises, and evidence data commonly may not leave the
operating organisation's control. The owner confirmed a single on-prem Linux host with Docker Compose
and explicitly excluded Kubernetes from v1.

## Decision
1. All services — frontend, FastAPI API, PostgreSQL, Redis, CPU workers, GPU worker, beat, nginx —
   deploy via Docker Compose on one host.
2. Original evidence lives on a **private filesystem volume** (`/srv/truthlens/evidence/originals`),
   outside any publicly served directory, mounted **read-only** into every container except the
   ingest worker.
3. Derived forensic artifacts live in a **separate** tree (`…/derivatives`) with its own lifecycle.
4. Evidence is **never** exposed through a public URL. Access is only via authenticated, audited,
   rate-limited endpoints or short-lived HMAC-signed URLs. nginx's document root is inside the
   frontend image and never a bind mount of the evidence volume.
5. Persistent Docker/host volumes for PostgreSQL, Redis, and evidence storage.
6. SHA-256 is computed at acquisition and re-verified before analysis and on a nightly sweep.
7. Automated **encrypted** backups cover the database, evidence files, configuration and audit
   records (BACKUP_RECOVERY §4, §6).
8. Restoration and disaster-recovery procedures are documented and **drilled quarterly**.
9. TLS, host firewall, SSH hardening, secret management and restricted service permissions are
   delivered as part of the deployment (DEPLOYMENT_GUIDE §8).
10. Every service has a healthcheck, structured JSON logs, resource limits and a restart policy.
11. Long-running forensic jobs never block API requests: the API only enqueues; workers execute.
    Queues are separated (`ingest`, `analysis.cpu`, `analysis.gpu`, `reports`, `maintenance`).
12. Single-host availability limits are documented **honestly** (BACKUP_RECOVERY §7.1): no hot
    standby, no automatic failover, RTO 4–8 h for host loss.
13. Storage and deployment interfaces stay **modular**: `StorageBackend` (filesystem now, S3-shaped
    later) and a scope-aware `SecretProvider`, so S3-compatible storage and distributed deployment can
    be introduced without a redesign.
14. **No Kubernetes in v1.** `infra/k8s/` is not created; the Helm path remains a documented phase-2
    option only.

## Alternatives considered
| Option | Verdict |
|---|---|
| Cloud-hosted VMs + S3 object storage | **Rejected for v1** — evidence leaves infrastructure the organisation controls; may conflict with data-residency and evidentiary rules |
| Kubernetes from day one | **Rejected by the owner** — materially more operational complexity and a control plane to secure, with no current scale need |
| Bare-metal services without containers | Rejected — loses reproducibility, isolation of hostile parsers (T-07), and the read-only mount enforcement that underpins write-once storage |

## Rationale
For an on-prem forensic unit, compose is usually the *correct* choice rather than a compromise: fewer
moving parts, easier to audit, and easier to describe to a court as a defined system. It also keeps
the blast radius of a parser compromise inside a hardened container.

## Consequences
**Positive:** simple, auditable, portable; no cluster control plane to secure; GPU support via a
compose override; the whole system is describable in one file set.
**Negative / accepted costs:** no HA; single host is a single point of failure; scaling is vertical
plus adding worker replicas; Postgres/Redis are self-managed (backups, upgrades, tuning are our
responsibility). These are stated plainly rather than optimised away.

## Licensing implications
Base images are digest-pinned and audited (THIRD_PARTY_LICENSE_AUDIT §1.4). Notably **Redis is pinned
to 7.2 (BSD-3)** — see ADR-0022. The NVIDIA CUDA runtime image carries a proprietary EULA (L-9).

## Security implications
Only nginx publishes ports; Postgres, Redis, workers and `/metrics` are on internal networks. Media
workers sit on an `isolated` network with **no outbound route**. All containers run non-root,
`read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, with memory/CPU limits. Read-only mounts
on `originals/` are the platform-level enforcement of write-once storage, complementing LUKS2,
`chattr +i`, and the DB trigger.

## Reversal strategy
**To S3 storage:** implement the already-defined `StorageBackend` S3 adapter; `physical_objects`
already records `storage_backend` and `storage_path`, so no schema change; migrate by copying objects
and updating `storage_backend` per row with hash re-verification. ~5 days.
**To Kubernetes:** same images and env contract; add Deployments/StatefulSets or external managed
DBs, Ingress, CSI volumes with `ReadOnlyMany` for originals, NetworkPolicies mirroring the compose
networks, and a pre-upgrade migration Job. ~10 days. Neither reversal changes application code.

## Verification
- Preflight script (BACKUP_RECOVERY §8) blocks startup unless the encrypted volume, permissions,
  nginx config, disk space, NTP and auditd rules are all correct.
- Integration test runs **inside each container** and asserts `originals/` is not writable.
- Test asserts no nginx `root`/`alias` references `/srv/truthlens`.
- Test asserts the API returns within budget while a long GPU job runs (condition 11).
- `docker compose config` validation in CI (no daemon needed) plus a full E2E stack on merge.
