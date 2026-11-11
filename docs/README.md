# TruthLens X — Documentation Index

| | |
|---|---|
| **Status** | **v1.0.0 RATIFIED** — architecture approved 2026-11-10; all 20 decisions are binding ADRs. **No application code implemented yet.** |
| **Last updated** | 2026-11-10 |
| **Start here if you're short on time** | [DECISIONS.md](./DECISIONS.md) — the ratified decision register, then [adr/README.md](./adr/README.md) for the binding records |
| **Legal reviewers start here** | [THIRD_PARTY_LICENSE_AUDIT.md](./THIRD_PARTY_LICENSE_AUDIT.md) — and note it is **not** legal advice and asserts no compliance |

---

## Documents

| # | Document | ID | What it answers |
|---|---|---|---|
| 1 | [MASTER_PRD.md](./MASTER_PRD.md) | TLX-DOC-001 | What are we building, for whom, and to what standard? All 22 modules as testable requirements, the binding AI-responsibility policy, NFRs, and user journeys. |
| 2 | [SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md) | TLX-DOC-002 | How is it structured? Containers, the full repository/folder tree, data flows, storage layout, technology selection with a **verified licence table**, and copyleft containment. |
| 3 | [DATABASE_DESIGN.md](./DATABASE_DESIGN.md) | TLX-DOC-003 | What is persisted and how? Every table, column, constraint, index, enum; the hash-chain design; pgvector; migration and retention strategy. |
| 4 | [API_SPECIFICATION.md](./API_SPECIFICATION.md) | TLX-DOC-004 | How do clients talk to it? Conventions, error model, pagination, the complete endpoint map for all 22 modules, SSE/WebSocket progress, rate limits. |
| 5 | [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) | TLX-DOC-005 | How is it protected? STRIDE threat register (20 threats), cryptographic design, the two-layer authorisation model and capability matrix, AI safety controls, stated limitations. |
| 6 | [IMPLEMENTATION_ROADMAP.md](./IMPLEMENTATION_ROADMAP.md) | TLX-DOC-006 | In what order, with what effort? 22 milestones (M0–M21) with tasks, exit criteria, dependencies, approval gates, and delivery risks. |
| 7 | [TESTING_STRATEGY.md](./TESTING_STRATEGY.md) | TLX-DOC-007 | How do we know it works? The pyramid, synthetic evidence fixtures with ground truth, golden-file and determinism policy, and the four tests that enforce honesty and tamper-evidence. |
| 8 | [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) | TLX-DOC-008 | How is it run? Topology, host sizing, compose services, first-time install, upgrades, backup/restore, the production hardening checklist, monitoring signals, troubleshooting. |
| 9 | [DECISIONS.md](./DECISIONS.md) | TLX-DOC-009 | **What was approved?** v2.0.0 — all 20 decisions **ratified** 2026-11-10, the four conflicts found during ratification, and the ADR each decision became. |
| 10 | [THIRD_PARTY_LICENSE_AUDIT.md](./THIRD_PARTY_LICENSE_AUDIT.md) | TLX-DOC-010 | **What may we ship?** Every dependency, model weight, dataset and base image with its licence, purpose and distribution method; the rejected dependencies; open findings L-1…L-11; and the CI gates that keep the audit true. **Weights are audited separately from their packages.** |
| 11 | [AI_ARCHITECTURE.md](./AI_ARCHITECTURE.md) | TLX-DOC-011 | **How does AI work here?** The provider protocol, why the provider is fixed at startup (making cloud fallback structurally impossible), the external-AI activation and per-request egress confirmation protocol, the model registry and `models.lock.json` loader contract, and how honesty is enforced by database constraints rather than convention. |
| 12 | [BACKUP_RECOVERY.md](./BACKUP_RECOVERY.md) | TLX-DOC-012 | **What happens when it breaks?** What must be recoverable and in what order; why volume encryption does **not** encrypt backups; LUKS2 key custody and the escrow procedure; restore procedures with mandatory verification gates; and honest RTO/RPO figures for a single host with no hot standby. |
| — | [adr/README.md](./adr/README.md) | — | **Why was it decided this way?** 23 Architecture Decision Records, each with context, alternatives considered, consequences, licensing and security implications, a reversal strategy, and the verification that proves it is enforced. |

## Coming in later milestones

| Path | Milestone | Contents |
|---|---|---|
| `docs/compliance/asvs-crosswalk.md` | M20 | Control-by-control OWASP ASVS v4.0 L2 mapping |
| `docs/runbooks/` | M14/M20 | Key rotation, key compromise, incident response, backup/restore, integrity mismatch, chain break, data-subject request, Postgres major upgrade, releases |
| `docs/user-guide/` · `docs/admin-guide/` | M21 | Operator documentation |
| `THIRD_PARTY_LICENSES.md` | M1 | **Generated** licence notice for the whole dependency tree, produced from the inventory in [THIRD_PARTY_LICENSE_AUDIT.md](./THIRD_PARTY_LICENSE_AUDIT.md) |
| `CHANGELOG.md` · `CONTRIBUTING.md` · `DEVELOPMENT.md` | M1 | Project conventions |

**Delivered during M0.5** (no longer pending): `docs/adr/` — 23 ADRs plus an index;
`THIRD_PARTY_LICENSE_AUDIT.md`; `AI_ARCHITECTURE.md`; `BACKUP_RECOVERY.md`.

---

## Reading order by role

**Decision-maker / stakeholder** → DECISIONS.md → MASTER_PRD.md §1, §5, §7 → IMPLEMENTATION_ROADMAP.md §2
**Architect / reviewer** → SYSTEM_ARCHITECTURE.md → DATABASE_DESIGN.md → SECURITY_ARCHITECTURE.md
**Backend engineer** → SYSTEM_ARCHITECTURE.md §4–§6 → DATABASE_DESIGN.md → API_SPECIFICATION.md → TESTING_STRATEGY.md §4–§7
**Forensic-engine engineer** → MASTER_PRD.md §3 (modules 5–14) → SYSTEM_ARCHITECTURE.md §9 → TESTING_STRATEGY.md §5–§6
**Frontend engineer** → API_SPECIFICATION.md → MASTER_PRD.md §3, §6 → TESTING_STRATEGY.md §8–§9
**DevOps / operator** → DEPLOYMENT_GUIDE.md → SYSTEM_ARCHITECTURE.md §10–§11 → SECURITY_ARCHITECTURE.md §5.5
**Security reviewer** → SECURITY_ARCHITECTURE.md (all) → TESTING_STRATEGY.md §7 → DECISIONS.md D-001..D-008, D-010, D-012 → [ADR-0004](./adr/ADR-0004-single-organisation-tenancy-with-capability-rbac.md), [ADR-0006](./adr/ADR-0006-luks2-volume-encryption-only.md), [ADR-0010](./adr/ADR-0010-no-row-level-security-in-v1.md), [ADR-0021](./adr/ADR-0021-external-ai-activation-and-egress-confirmation.md)
**Legal / licence reviewer** → THIRD_PARTY_LICENSE_AUDIT.md (all, especially §5 weights and §10 open findings) → [ADR-0001](./adr/ADR-0001-permissive-default-dependency-set.md) → [ADR-0002](./adr/ADR-0002-pikepdf-default-pdf-stack.md) → [ADR-0003](./adr/ADR-0003-exiftool-optional-subprocess.md) (ExifTool dual licence, finding L-1) → [ADR-0008](./adr/ADR-0008-repository-remains-unlicensed.md) (**the repository is deliberately unlicensed**) → [ADR-0022](./adr/ADR-0022-redis-7-2-pin.md) (the Redis 8 licence trap)
**Operator / SRE** → BACKUP_RECOVERY.md (all, especially §5 key custody and §7 honest RTO/RPO) → DEPLOYMENT_GUIDE.md → [ADR-0005](./adr/ADR-0005-single-host-docker-compose-deployment.md) → [ADR-0006](./adr/ADR-0006-luks2-volume-encryption-only.md)
**AI / ML engineer** → AI_ARCHITECTURE.md (all) → [ADR-0007](./adr/ADR-0007-local-default-ai-with-gated-external-providers.md) → [ADR-0021](./adr/ADR-0021-external-ai-activation-and-egress-confirmation.md) → [ADR-0023](./adr/ADR-0023-weight-free-deepfake-indicators.md) → THIRD_PARTY_LICENSE_AUDIT.md §5

---

## The three rules that shape everything

1. **Originals are sacred.** Write-once, content-addressed, SHA-256 verified at ingest, before every
   analysis, and on a scheduled sweep. No code path mutates an original; derivatives live elsewhere.
2. **AI output is an indicator, never a fact.** Provenance, confidence-with-basis, an interval with any
   score, a versioned limitations statement, and a human verification state are required by the database
   schema itself — a result missing them cannot be persisted. No verdicts, no fabricated accuracy figures.
3. **Everything is attributable and tamper-evident.** Custody and audit records are append-only and
   hash-chained, with `UPDATE`/`DELETE` revoked at the database role level.

If a future change would weaken one of these three, it requires a new ADR and explicit approval.
