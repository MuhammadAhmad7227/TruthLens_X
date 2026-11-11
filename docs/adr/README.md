# Architecture Decision Records

Every architectural decision taken for TruthLens X v1, recorded so it can be understood, challenged
and reversed with a paper trail.

| | |
|---|---|
| **Status** | All 23 ADRs **Accepted** — ratified 2026-11-10 |
| **Source** | [DECISIONS.md](../DECISIONS.md) v2.0.0 (the approval register) |
| **Scope** | v1 only. Items marked *v2 backlog* are explicitly out of scope. |

Decisions `D-001`…`D-020` were proposed in `DECISIONS.md` and ratified by the project owner on
2026-11-10. `ADR-0021`, `ADR-0022` and `ADR-0023` **emerged from the third-party licence and AI
audit** after ratification; each refines an existing decision rather than replacing one, and none
contradicts anything the owner approved.

---

## Index

### Blocking decisions (D-001 … D-008)

| ADR | Decision | Summary |
|---|---|---|
| [ADR-0001](ADR-0001-permissive-default-dependency-set.md) | D-001 | Permissive-by-default dependency set; copyleft behind explicit `ENABLE_*` flags; **weights audited separately from packages** |
| [ADR-0002](ADR-0002-pikepdf-default-pdf-stack.md) | D-002 | `pikepdf` (MPL-2.0) default PDF stack; PyMuPDF (AGPL) behind a flag |
| [ADR-0003](ADR-0003-exiftool-optional-subprocess.md) | D-003 | ExifTool optional, subprocess-isolated, pure-Python fallback; dual-licence ambiguity disclosed as **L-1** |
| [ADR-0004](ADR-0004-single-organisation-tenancy-with-capability-rbac.md) | D-004 | Single organisation, 30 named capabilities, one authorisation gate, denial ⇒ **404**, inert `organisation_id` |
| [ADR-0005](ADR-0005-single-host-docker-compose-deployment.md) | D-005 | Single on-prem host, Docker Compose, only nginx publishes ports, **no Kubernetes**, honest RTO/RPO |
| [ADR-0006](ADR-0006-luks2-volume-encryption-only.md) | D-006 | LUKS2 volume encryption only; **no application envelope encryption in v1**; mandatory preflight |
| [ADR-0007](ADR-0007-local-default-ai-with-gated-external-providers.md) | D-007 | Local inference default; provider fixed at startup so cloud fallback is **structurally impossible** |
| [ADR-0008](ADR-0008-repository-remains-unlicensed.md) | D-008 | **No LICENSE file** — deliberately unlicensed; ⚠️ requires re-review before going public |

### Design defaults (D-009 … D-020)

| ADR | Decision | Summary |
|---|---|---|
| [ADR-0009](ADR-0009-uuid-primary-key-strategy.md) | D-009 | UUIDv7 for append-only event tables, UUIDv4 for entities |
| [ADR-0010](ADR-0010-no-row-level-security-in-v1.md) | D-010 ⚠️ | **No PostgreSQL RLS in v1 — excluded entirely, including M20** |
| [ADR-0011](ADR-0011-filesystem-storage-backend-only.md) | D-011 ⚠️ | Filesystem backend only; **no S3 code ships**, interface shaped for a future object store |
| [ADR-0012](ADR-0012-data-residency-no-default-egress.md) | D-012 | On-prem residency; **one master egress switch** governs every feature flag; no phone-home |
| [ADR-0013](ADR-0013-alpr-examples-only-and-registry-lookup-hard-disabled.md) | D-013 | Plate formats are **examples only**; `unresolved_format` never coerced; registry lookup **hard-disabled, no HTTP client in the module** |
| [ADR-0014](ADR-0014-clamav-included-but-disabled-by-default.md) | D-014 | ClamAV present but disabled; updates gated behind scanning; scan failure **fails closed** |
| [ADR-0015](ADR-0015-offline-gazetteer-disabled-by-default.md) | D-015 ⚠️ | Offline gazetteer **disabled by default** pending licence finding **L-7**; attribution mandatory if enabled |
| [ADR-0016](ADR-0016-radix-primitives-with-vendored-ui-components.md) | D-016 | Radix primitives + vendored shadcn-style components; `dangerouslySetInnerHTML` is an ESLint error |
| [ADR-0017](ADR-0017-faster-whisper-default-asr.md) | D-017 | `faster-whisper` default (code **and** weights MIT); diarisation gated on **L-6** |
| [ADR-0018](ADR-0018-mandatory-mfa-for-privileged-roles.md) | D-018 | TOTP MFA **mandatory** for `admin` + `lead_investigator`; WebAuthn is v2 |
| [ADR-0019](ADR-0019-report-manifest-hashing-with-optional-crypto-signing.md) | D-019 | Deterministic reports, manifest hash, immutable lineage; crypto signing optional and off; **reports cannot read assistant tables** |
| [ADR-0020](ADR-0020-retention-without-a-default-statutory-period.md) | D-020 | **No default retention period** — unset means delete nothing; hard deletion needs two approvers |

### Emerged from the licence and AI audit

| ADR | Refines | Summary |
|---|---|---|
| [ADR-0021](ADR-0021-external-ai-activation-and-egress-confirmation.md) | D-007, D-012 | External AI activation protocol: bound expiring grants, per-request egress confirmation, three kill switches, **empty category allowlist by default** |
| [ADR-0022](ADR-0022-redis-7-2-pin.md) | D-001, D-005 | Pin **`redis:7.2-alpine`** by digest; CI gate fails on `redis:8*` / `redis:7.3*` (RSALv2/SSPLv1 trap) |
| [ADR-0023](ADR-0023-weight-free-deepfake-indicators.md) | D-001 | Deepfake analysis uses **classical weight-free indicators**; no verdict column exists; only self-measured performance shown |

---

## ⚠️ Conflicts and refinements flagged during ratification

The owner instructed that any conflict between a proposed default and an approved decision be flagged
rather than silently resolved. Four were found. **In every case the owner's explicit instruction won.**

| # | Conflict | Resolution | Where |
|---|---|---|---|
| 1 | The M0 proposal said *defer PostgreSQL RLS to M20*. The owner's ratification excluded RLS, `tenant_id`, per-tenant keys and quotas from v1 **entirely**. | Owner's stronger position adopted; RLS removed from the M20 roadmap and re-proposable only for v2. | [ADR-0010](ADR-0010-no-row-level-security-in-v1.md) |
| 2 | The M0 proposal offered an S3 adapter behind a disabled flag. The owner ratified *interface plus filesystem only*. | No S3 code ships. A disabled, untested adapter would be a placeholder presented as a capability, which the owner's standing instructions forbid. | [ADR-0011](ADR-0011-filesystem-storage-backend-only.md) |
| 3 | The M0 proposal had the offline gazetteer **enabled**. Licence finding **L-7** could not verify the dataset's terms. | Default flipped to **disabled**, with mandatory attribution if an operator enables it. Conservative path until counsel resolves L-7. | [ADR-0015](ADR-0015-offline-gazetteer-disabled-by-default.md) |
| 4 | `API_SPECIFICATION.md` listed `FORBIDDEN_CASE_ACCESS` as a **403** code, contradicting the non-enumerability requirement in `SECURITY_ARCHITECTURE.md` §5.5 **and** the alerting requirement in §9 that such denials be detectable. | Resolved in favour of security: HTTP **404** with client-visible `error_code = NOT_FOUND`, while the server records `audit_reason = FORBIDDEN_CASE_ACCESS` for alerting. The API spec table is corrected. | [ADR-0004](ADR-0004-single-organisation-tenancy-with-capability-rbac.md) |

---

## Open licence findings that gate artifacts

These are **unresolved** and are tracked in [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md).
An unresolved finding means the conservative path ships and the capability is flag-gated — an
unverified artifact is never shipped.

| Finding | Subject | Gates | ADR |
|---|---|---|---|
| **L-1** | ExifTool Artistic-vs-GPL election | M8 metadata | [ADR-0003](ADR-0003-exiftool-optional-subprocess.md) |
| **L-2** | torchvision COCO-pretrained detection weights | M13 detection | [ADR-0001](ADR-0001-permissive-default-dependency-set.md) |
| **L-3** | EasyOCR model weights | M10 / M13 OCR | [ADR-0001](ADR-0001-permissive-default-dependency-set.md) |
| **L-5** | Face-detector weights | M9 image forensics | [ADR-0023](ADR-0023-weight-free-deepfake-indicators.md) |
| **L-6** | `pyannote` diarisation weights | M11 audio | [ADR-0017](ADR-0017-faster-whisper-default-asr.md) |
| **L-7** | Gazetteer dataset licence | M8 / M16 location | [ADR-0015](ADR-0015-offline-gazetteer-disabled-by-default.md) |
| **L-11** | Report font embedding & redistribution | M18 reports | [ADR-0019](ADR-0019-report-manifest-hashing-with-optional-crypto-signing.md) |

---

## ADR format

Every record uses the same skeleton, so a reviewer can compare decisions directly:

1. **Metadata table** — status, decision ID, related records, and a *Refinement flagged ⚠️* row where
   ratification changed the original proposal.
2. **Context** — the problem, with verified facts and their sources where licensing is involved.
3. **Decision** — numbered, specific, implementable requirements.
4. **Alternatives considered** — including why each was rejected, so the choice is not re-litigated
   from ignorance.
5. **Rationale** — why this option and not another.
6. **Consequences** — costs and trade-offs stated plainly, including residual risk.
7. **Licensing implications** — separate from security, because a permissive package does not imply
   permissive weights (ADR-0001 §9).
8. **Security implications** — what the decision protects and what it does not.
9. **Reversal strategy** — how to undo it, and what it would cost.
10. **Verification** — the tests and CI gates that prove the decision is actually enforced. A decision
    with no verification step is an aspiration, not an architecture.

## Related documents

* [DECISIONS.md](../DECISIONS.md) — the approval register with the owner's ratification record
* [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) — dependency, weight and dataset inventory
* [AI_ARCHITECTURE.md](../AI_ARCHITECTURE.md) — provider adapters, egress protocol, model registry
* [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) — threat model and controls
* [BACKUP_RECOVERY.md](../BACKUP_RECOVERY.md) — backup, restore and honest DR limits
* [IMPLEMENTATION_ROADMAP.md](../IMPLEMENTATION_ROADMAP.md) — milestones M0…M21
