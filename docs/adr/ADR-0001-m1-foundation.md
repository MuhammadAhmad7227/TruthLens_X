# ADR-0001 — M1 Repository Foundation

- **Status:** Accepted for M1 implementation
- **Scope:** repository foundation only
- **Date:** 2026-11-11

## Decision
Implement the approved M1 scope from IMPLEMENTATION_ROADMAP.md as a modular monorepo with FastAPI, Next.js, PostgreSQL, Redis, Docker Compose and GitHub Actions.

## Constraints
- No real evidence, secrets, or model weights in git.
- Forensic/domain modules remain outside M1.
- Runtime readiness must not claim database/Redis availability until dependency checks are implemented.
- Licensing decisions already recorded in DECISIONS.md remain authoritative.
