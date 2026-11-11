# ADR-0006 — LUKS2 full-volume encryption at rest; no application-level envelope encryption in v1

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-006 |
| **Related** | [ADR-0005](ADR-0005-single-host-docker-compose-deployment.md), [BACKUP_RECOVERY](../BACKUP_RECOVERY.md), [SECURITY_ARCHITECTURE §5.2](../SECURITY_ARCHITECTURE.md) |

## Context

The owner directed **disk/volume-level encryption only** for v1 and explicitly excluded
application-level AES-256-GCM envelope encryption. Required: originals, derivatives, Postgres data
and backups all on encrypted storage; evidence never mounted as a public web directory; documented
secure boot-time unlocking and authorized admin access; documented recovery and secure storage of
LUKS recovery keys; deployment verification that the correct encrypted volume is mounted **before**
the application starts.

## Decision

1. **Linux LUKS2 full-volume encryption** protects the evidence volume. Originals, derivatives,
   PostgreSQL data and backups all reside on encrypted storage.
2. **No application-level envelope encryption in v1.** `EVIDENCE_ENCRYPTION` accepts only `disabled`;
   any other value **aborts startup**. The setting exists so the future path is explicit, not so a
   half-built feature can be switched on.
3. Passphrases and recovery keys are **never** stored in GitHub, source, Docker images or ordinary
   env files. They live in a sealed key file with `0400` permissions on a separate unencrypted boot
   partition, or are entered at the console.
4. Mounted directories are further restricted by Linux permissions (`0440` originals, `0700` postgres,
   `0555` models, `0750` backups).
5. A **host preflight check runs before the application starts** and refuses to start if the expected
   encrypted volume is not mounted and unlocked. `PREFLIGHT_REQUIRED=true` is mandatory in production.
6. **Backup encryption is documented separately.** Volume encryption does **not** encrypt exported
   backups once they leave the volume; backups are encrypted independently (age/GPG) before transfer.
7. The threat boundary is stated explicitly and without softening: **volume encryption protects data
   at rest. It does not protect against an attacker who has access to an already-unlocked, running
   server.** Application controls (ADR-0004 RBAC, audit chain, break-glass) are the mitigation there.

## Alternatives considered

| Option | Verdict |
|---|---|
| Application-level AES-256-GCM envelope encryption | Excluded from v1 by the owner. Key management, re-keying and performance cost are significant; deferred to v2 with the multi-tenancy work. |
| eCryptfs / fscrypt per-directory | Rejected — weaker operational story than LUKS2 and no clear recovery-key model. |
| Filesystem-level only, no preflight | Rejected — a silently unmounted volume would write evidence to the unencrypted root filesystem. |

## Rationale

LUKS2 is mature, kernel-native, recoverable and auditable. One mechanism covering everything is
simpler to verify than per-object encryption spread across application code.

## Consequences

* Recovery depends entirely on key custody. A lost passphrase with no escrow means **permanent,
  unrecoverable data loss** — documented in `BACKUP_RECOVERY.md` with an escrow procedure.
* Re-keying means re-encrypting the volume (offline, `cryptsetup reencrypt`), not a code change.
* The preflight check is a hard startup dependency: misconfiguration stops the service rather than
  degrading it. That is intended.

## Licensing implications

`cryptsetup` is GPL-2.0+ and is used as a host-level administrative tool, never linked into the
platform. No copyleft reaches the application.

## Security implications

Strong at-rest protection against device theft, decommissioned-disk leakage and snapshot exposure.
**No** protection against a live-server attacker — stated openly so no one over-trusts it. `auditd`
keys `tlx_cryptdb` → `tlx_crypttab` detect tampering with the mount configuration.

## Reversal strategy

Adding envelope encryption in v2 is additive: a `dek`/`kek` pair per object, `EVIDENCE_ENCRYPTION`
accepting `aes256gcm_envelope`, and a re-encryption migration job. LUKS2 remains as a second layer.

## Verification

* `infra/scripts/verify-encrypted-mount.sh` passes on a correctly mounted host and **fails closed**
  when the volume is absent, unencrypted or mounted at the wrong path (tested both ways).
* Startup aborts when `EVIDENCE_ENCRYPTION` is anything other than `disabled` (unit test).
* Startup aborts in production when `PREFLIGHT_REQUIRED=false` (unit test).
* A documented restore rehearsal proves backups are decryptable **without** the host volume key.
