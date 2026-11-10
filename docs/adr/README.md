# Architecture Decision Records

Each record captures a decision, the alternatives considered, the rationale, the consequences, the
licensing and security implications, and — importantly — **how to reverse it**.

Status: all records below were accepted on **2026-11-10** following the owner's ratification of
decisions D-001…D-020 in [../DECISIONS.md](../DECISIONS.md).

## Index

| ADR | Decision | Decision ID | Status |
|---|---|---|---|
| [0001](./ADR-0001-permissive-default-dependency-set.md) | Permissive-by-default dependency set; copyleft behind audited flags | D-001 | Accepted |
| [0002](./ADR-0002-pikepdf-pdf-engine.md) | pikepdf (MPL-2.0) is the default PDF engine; PyMuPDF flag-gated | D-002 | Accepted |
| [0003](./ADR-0003-exiftool-optional-subprocess.md) | ExifTool optional, subprocess-isolated, dual-licence election pending (L-1) | D-003 | Accepted, open legal item |
| [0004](./ADR-0004-single-organisation-capability-rbac.md) | Single organisation v1 with capability-based RBAC; tenancy-ready schema | D-004 | Accepted |
| [0005](./ADR-0005-single-host-docker-compose.md) | Single on-prem host with Docker Compose; no Kubernetes in v1 | D-005 | Accepted |
| [0006](./ADR-0006-luks2-volume-encryption.md) | LUKS2 volume encryption; no app-level envelope encryption in v1 | D-006 | Accepted |
| [0007](./ADR-0007-local-first-ai-assistant.md) | Local-first AI assistant; external providers behind audited admin opt-in | D-007 | Accepted |
| [0008](./ADR-0008-repository-remains-unlicensed.md) | Repository remains unlicensed pending a deliberate decision | D-008 | Accepted |
| [0009](./ADR-0009-uuid-primary-keys.md) | UUIDv7 for append-only tables; UUIDv4 elsewhere | D-009 | Accepted |
| [0010](./ADR-0010-no-row-level-security-in-v1.md) | No PostgreSQL Row-Level Security in v1 | D-010 | Accepted — ⚠️ supersedes the original proposal |
| [0011](./ADR-0011-storage-backend-interface-filesystem-only.md) | `StorageBackend` interface in v1; filesystem only, S3 deferred | D-011 | Accepted — ⚠️ refines the original proposal |
| [0012](./ADR-0012-data-residency-no-egress-by-default.md) | Evidence stays on-prem; all external egress disabled by default | D-012 | Accepted |
| [0013](./ADR-0013-alpr-no-default-formats-no-registry.md) | ALPR ships no authoritative formats and no registry integration | D-013 | Accepted |
| [0014](./ADR-0014-clamav-included-disabled.md) | ClamAV available but disabled by default | D-014 | Accepted |
| [0015](./ADR-0015-offline-gazetteer-default-disabled.md) | Offline gazetteer supported; **disabled** pending licence verification (L-7) | D-015 | Accepted — ⚠️ refines the original proposal |
| [0016](./ADR-0016-radix-vendored-ui-components.md) | Radix primitives with vendored in-tree components | D-016 | Accepted |
| [0017](./ADR-0017-faster-whisper-default-asr.md) | faster-whisper default ASR; openai-whisper available | D-017 | Accepted |
| [0018](./ADR-0018-mfa-mandatory-admin-lead.md) | TOTP MFA mandatory for `admin` and `lead_investigator` | D-018 | Accepted |
| [0019](./ADR-0019-report-hash-v1-crypto-signing-optional.md) | Report integrity by manifest + hash; crypto signing optional | D-019 | Accepted |
| [0020](./ADR-0020-retention-defaults-operator-specified.md) | Retention defaults; statutory period is operator-specified | D-020 | Accepted |
| [0021](./ADR-0021-ai-egress-minimisation-no-fallback.md) | AI egress minimisation; **no automatic cloud fallback** | D-007 (cond. 7–10, 17, 18) | Accepted |
| [0022](./ADR-0022-redis-72-version-pin.md) | Redis pinned to 7.2 (BSD-3); upgrading is a licence event | D-001 consequence | Accepted |
| [0023](./ADR-0023-weight-free-deepfake-indicators.md) | Deepfake analysis uses weight-free classical indicators in v1 | D-001 consequence | Accepted |

## Conflicts and refinements flagged during ratification

The owner's instruction was to *"flag any conflict between a proposed default and an approved
decision before proceeding."* Three were found; all are resolved **in favour of the explicit
instruction**, and none is a silent change:

| ADR | Original proposal | Approved instruction | Resolution |
|---|---|---|---|
| [0010](./ADR-0010-no-row-level-security-in-v1.md) | Add RLS in M20 as optional hardening | D-004 condition: *"Do not implement… PostgreSQL Row-Level Security… in v1"* — which includes M20 | **RLS is excluded from v1 entirely, including M20.** Compensating controls documented. |
| [0011](./ADR-0011-storage-backend-interface-filesystem-only.md) | Write the S3 adapter now, disabled | D-005 condition 13: keep interfaces modular so S3 *can be introduced later* | **Interface only; no S3 implementation in v1.** Avoids shipping untested code, consistent with the "no placeholder features" restriction. |
| [0015](./ADR-0015-offline-gazetteer-default-disabled.md) | Offline GeoNames subset enabled by default | Licence-audit condition: verify artefact licences separately; do not claim compliance without an audit | **Default changed to disabled** because the dataset licence (L-7) could not be verified from an allowed host. |

Two further decisions emerged *from* the licence audit rather than from the original register, and are
recorded as ADRs in their own right: **[0022](./ADR-0022-redis-72-version-pin.md)** (Redis 7.2 pin —
Redis 8 changed licence) and **[0023](./ADR-0023-weight-free-deepfake-indicators.md)** (deepfake
detector weights and their training datasets are research/non-commercial licensed, so M14 ships
weight-free classical indicators instead).

## Template

New ADRs copy the structure used above:
**Context → Decision → Alternatives considered → Rationale → Consequences (positive / negative) →
Licensing implications → Security implications → Reversal strategy → Verification.**

A record is numbered sequentially, never renumbered, and superseded rather than deleted — the same
append-only discipline the platform applies to its own evidence.
