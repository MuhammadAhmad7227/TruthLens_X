# TruthLens X — Documentation Index

| | |
|---|---|
| **Status** | v0.1.0 DRAFT — architecture and planning complete, **no application code implemented yet** |
| **Last updated** | 2026-11-10 |
| **Start here if you're short on time** | [DECISIONS.md](./DECISIONS.md) — the 20 assumptions needing your approval |

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
| 9 | [DECISIONS.md](./DECISIONS.md) | TLX-DOC-009 | **What needs your approval?** 20 decisions (8 blocking) and 15 informational assumptions, each with options and consequences. |

## Coming in later milestones

| Path | Milestone | Contents |
|---|---|---|
| `docs/adr/` | M1 | One accepted-decision record per approved item from DECISIONS.md |
| `docs/compliance/asvs-crosswalk.md` | M20 | Control-by-control OWASP ASVS v4.0 L2 mapping |
| `docs/runbooks/` | M14/M20 | Key rotation, key compromise, incident response, backup/restore, integrity mismatch, chain break, data-subject request, Postgres major upgrade, releases |
| `docs/user-guide/` · `docs/admin-guide/` | M21 | Operator documentation |
| `THIRD_PARTY_LICENSES.md` | M1 | Generated licence notice for the whole dependency tree |
| `CHANGELOG.md` · `CONTRIBUTING.md` | M1 | Project conventions |

---

## Reading order by role

**Decision-maker / stakeholder** → DECISIONS.md → MASTER_PRD.md §1, §5, §7 → IMPLEMENTATION_ROADMAP.md §2
**Architect / reviewer** → SYSTEM_ARCHITECTURE.md → DATABASE_DESIGN.md → SECURITY_ARCHITECTURE.md
**Backend engineer** → SYSTEM_ARCHITECTURE.md §4–§6 → DATABASE_DESIGN.md → API_SPECIFICATION.md → TESTING_STRATEGY.md §4–§7
**Forensic-engine engineer** → MASTER_PRD.md §3 (modules 5–14) → SYSTEM_ARCHITECTURE.md §9 → TESTING_STRATEGY.md §5–§6
**Frontend engineer** → API_SPECIFICATION.md → MASTER_PRD.md §3, §6 → TESTING_STRATEGY.md §8–§9
**DevOps / operator** → DEPLOYMENT_GUIDE.md → SYSTEM_ARCHITECTURE.md §10–§11 → SECURITY_ARCHITECTURE.md §5.5
**Security reviewer** → SECURITY_ARCHITECTURE.md (all) → TESTING_STRATEGY.md §7 → DECISIONS.md D-001..D-008, D-010, D-012

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
