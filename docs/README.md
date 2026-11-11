# TruthLens X — Documentation Index

| | |
|---|---|
| **Status** | v1.0.0 — architecture **ratified**. All 20 decisions approved 2026-11-10 and recorded as 23 ADRs. **No application code implemented yet**; M1 is approved and next. |
| **Last updated** | 2026-11-10 |
| **Start here** | [DECISIONS.md §3](./DECISIONS.md) — the ratified decision log · [adr/](./adr/README.md) — the 23 ADRs |

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
| 9 | [DECISIONS.md](./DECISIONS.md) | TLX-DOC-009 | **What was decided.** The 20 decisions with the owner's ratification, attached conditions, and 3 flagged conflicts resolved. |
| 10 | [THIRD_PARTY_LICENSE_AUDIT.md](./THIRD_PARTY_LICENSE_AUDIT.md) | TLX-DOC-010 | Is every dependency cleared? Two registers — **software** and **artifacts** (weights, checkpoints, datasets, binaries) — plus the copyleft containment, substitution register and 11 open legal items. |
| 11 | [AI_ARCHITECTURE.md](./AI_ARCHITECTURE.md) | TLX-DOC-011 | How does AI inference work, and when can anything leave the host? Provider adapters, the never-send list, per-request confirmation, kill switch, citation validation. |
| 12 | [BACKUP_RECOVERY.md](./BACKUP_RECOVERY.md) | TLX-DOC-012 | How is data protected and recovered? LUKS2 provisioning, key custody, backup encryption (separately!), restore procedures, DR, deployment preflight. |
| 13 | [adr/](./adr/README.md) | — | **23 Architecture Decision Records** — each with alternatives, rationale, consequences, licensing and security implications, and a reversal strategy. |

## Coming in later milestones

| Path | Milestone | Contents |
|---|---|---|
| `docs/compliance/asvs-crosswalk.md` | M20 | Control-by-control OWASP ASVS v4.0 L2 mapping |
| `docs/runbooks/` | M20 | The 11 runbooks indexed in BACKUP_RECOVERY §10, plus incident response, chain break, data-subject request |
| `docs/user-guide/` · `docs/admin-guide/` | M21 | Operator documentation |
| `THIRD_PARTY_LICENSES.md` | M1 | **Generated** licence notice for the whole dependency tree (distinct from the audit in doc 10, which is hand-maintained judgement) |
| `CHANGELOG.md` · `CONTRIBUTING.md` | M1 | Project conventions |

---

## Reading order by role

**Decision-maker / stakeholder** → DECISIONS.md → MASTER_PRD.md §1, §5, §7 → IMPLEMENTATION_ROADMAP.md §2
**Architect / reviewer** → SYSTEM_ARCHITECTURE.md → DATABASE_DESIGN.md → SECURITY_ARCHITECTURE.md
**Backend engineer** → SYSTEM_ARCHITECTURE.md §4–§6 → DATABASE_DESIGN.md → API_SPECIFICATION.md → TESTING_STRATEGY.md §4–§7
**Forensic-engine engineer** → MASTER_PRD.md §3 (modules 5–14) → SYSTEM_ARCHITECTURE.md §9 → TESTING_STRATEGY.md §5–§6
**Frontend engineer** → API_SPECIFICATION.md → MASTER_PRD.md §3, §6 → TESTING_STRATEGY.md §8–§9
**DevOps / operator** → DEPLOYMENT_GUIDE.md → SYSTEM_ARCHITECTURE.md §10–§11 → SECURITY_ARCHITECTURE.md §5.5
**Security reviewer** → SECURITY_ARCHITECTURE.md (all) → TESTING_STRATEGY.md §7 → BACKUP_RECOVERY.md → AI_ARCHITECTURE.md §4, §7, §12
**Legal / licensing reviewer** → THIRD_PARTY_LICENSE_AUDIT.md (all) → adr/ADR-0001, 0002, 0003, 0008, 0022, 0023 → DECISIONS.md §3
**Operator / SRE** → BACKUP_RECOVERY.md → DEPLOYMENT_GUIDE.md §5–§10 → adr/ADR-0005, 0006

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
