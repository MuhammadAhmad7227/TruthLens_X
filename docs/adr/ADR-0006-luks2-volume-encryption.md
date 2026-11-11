# ADR-0006 — LUKS2 full-volume encryption at rest; no application-level envelope encryption in v1

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-006 |
| **Decided by** | Project owner, with 12 attached conditions |
| **Related** | [BACKUP_RECOVERY.md](../BACKUP_RECOVERY.md) · [ADR-0005](./ADR-0005-single-host-docker-compose.md) · [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) §3 |

## Context
Evidence at rest must survive disk theft and improper disposal. The alternative — application-level
AES-256-GCM envelope encryption per object — protects against the same threats but introduces a
second, independent catastrophic key-loss mode and a key-management burden disproportionate to a
single-host deployment.

## Decision
1. **Linux LUKS2** full-volume encryption protects the evidence storage volume
   (`aes-xts-plain64`, 512-bit key, SHA-512, argon2id KDF).
2. Originals, derivatives, PostgreSQL data, Redis persistence and backups all reside on the encrypted
   volume.
3. Evidence storage is never mounted as, or served from, a public web directory.
4. Boot-time unlocking and authorised administrator access are documented, with three explicit modes
   (manual console unlock as default; NBDE/Tang; TPM2) and a prohibition on plaintext key storage.
5. LUKS recovery-key generation, custody, rotation and loss-recovery procedures are documented.
   Three key slots with two independent physical custodians are **mandatory** before production.
6. Passphrases and recovery keys are never stored in GitHub, source code, Docker images, or ordinary
   environment files.
7. Mounted evidence directories are restricted by Linux permissions, group ownership, `auditd` rules,
   and `chattr +i` immutability on originals.
8. It is documented explicitly that **volume encryption protects data at rest only**, and does not
   protect against an attacker with access to an already-unlocked, running server.
9. **Backup encryption is documented separately**: a file copied out of an unlocked LUKS volume is
   plaintext, so backups are encrypted by the backup tool (restic AES-256/Poly1305) under a **key
   distinct from the LUKS keys**.
10. Deployment verification steps confirm the correct encrypted volume is mounted **before** the
    application starts, and block startup if not.
11. **Application-level AES-256-GCM envelope encryption is NOT implemented in v1.**

## Alternatives considered
| Option | Verdict |
|---|---|
| Application-level envelope encryption (per-object DEK wrapped by a KEK) | **Rejected for v1** by the owner — adds a second catastrophic way to lose the key, an escrow design, and rotation complexity, without protecting against the dominant threat (a running-system compromise defeats both schemes equally) |
| Both LUKS2 **and** envelope encryption | Rejected for v1 — defence in depth here mostly multiplies key-custody risk |
| No encryption at rest, rely on physical security | **Rejected** — unacceptable for evidence media and for backup media that leaves the building |
| Filesystem-level encryption (fscrypt) instead of LUKS2 | Rejected — per-directory keys complicate custody; LUKS2 protects swap, journals and deleted blocks too |

## Rationale
LUKS2 is mature, auditable, well-understood by operations teams, and protects everything on the
device including free space and swap. Combined with write-once storage, read-only mounts, immutability
flags and hash verification, it addresses the realistic at-rest threats without creating a second
unrecoverable failure mode.

## Consequences
**Positive:** simple to operate and explain; protects stolen/disposed media; no application crypto to
get wrong; no KEK in the app process.
**Negative / accepted costs:** **LUKS key loss = permanent evidence loss** — hence the three-slot,
two-custodian requirement that blocks production go-live. No protection against a running-system
compromise, cold-boot/DMA attacks, or ransomware with host access (mitigated by immutable off-host
backups). Unattended boot requires NBDE or TPM2, each with its own trade-offs. Host root remains an
evidence-custody authority.

## Licensing implications
`cryptsetup` is GPL-2.0+, used as a **host administration tool** invoked by the operator/systemd — not
linked into, imported by, or distributed with TruthLens X. No copyleft exposure to the application.
The LUKS2 on-disk format is a public specification.

## Security implications
Threat **T-01** (original evidence tampering): LUKS2 does not mitigate it — write-once mounts,
`O_EXCL` placement, `chmod 0440`, `chattr +i`, SHA-256 verification and the DB trigger do; LUKS2
protects the media instead. Threat **T-02** (audit rewrite): unaffected by encryption; mitigated by
hash chaining plus **off-host signed anchors**. New risk introduced: **key custody becomes a
single-point-of-failure for the entire evidential corpus**, managed by BACKUP_RECOVERY §5.

## Reversal strategy
Reversible by layering, not by removal. To add envelope encryption later: implement the designed
`physical_objects.encryption`/`wrapped_dek` path, re-ingest or re-wrap objects in place under a
migration job that verifies hashes before and after, and add KEK escrow procedures **first**. The
schema already accommodates it, so this is additive. Removing LUKS2 later would mean migrating data to
a new volume and is not recommended.

## Verification
- `verify-encrypted-mount.sh` (BACKUP_RECOVERY §8) runs as a systemd preflight and **blocks** the
  stack unless the LUKS2 target is present, mounted at the expected path, on the expected device,
  with correct permissions, no key material present, no nginx reference, ≥50 GB free, NTP synced and
  auditd rules loaded.
- Preflight asserts `/srv/truthlens` is on `/dev/mapper/tlxdata`, not on the root device.
- Secret scanner asserts no LUKS or restic key material exists in the repo, images, or on the volume.
- Quarterly restore drill must succeed **using the recovery key**, not the primary passphrase.
