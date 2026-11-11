# TruthLens X — Backup, Restore and Disaster Recovery

| | |
|---|---|
| **Document ID** | TLX-DOC-012 |
| **Version** | 1.0.0 |
| **Last updated** | 2026-11-10 |
| **Status** | Current — ratified |
| **Related** | [ADR-0005](adr/ADR-0005-single-host-docker-compose-deployment.md) · [ADR-0006](adr/ADR-0006-luks2-volume-encryption-only.md) · [ADR-0011](adr/ADR-0011-filesystem-storage-backend-only.md) · [ADR-0020](adr/ADR-0020-retention-without-a-default-statutory-period.md) · [DEPLOYMENT_GUIDE](DEPLOYMENT_GUIDE.md) · [SECURITY_ARCHITECTURE](SECURITY_ARCHITECTURE.md) |

---

## 1. Scope

Automated encrypted backups for **database, evidence, configuration and audit records**, with
documented restore and disaster-recovery procedures, on a **single on-premises host**.

This document is deliberately blunt about what that architecture can and cannot deliver. A runbook
that overstates its own recovery capability is worse than no runbook, because it is believed.

---

## 2. What must be recoverable

| Asset | Location | Volume | Recovery requirement |
|---|---|---|---|
| PostgreSQL (all tables incl. audit + custody chains) | `postgres/` `0700` uid 999 | Small–medium | **RPO ≤ 24 h**; point-in-time desirable |
| Evidence originals (write-once, content-addressed) | `evidence/originals/<aa>/<bb>/<sha256>` | Up to **50 TB** | RPO ≤ 24 h; originals are irreplaceable |
| Derivative artifacts | `derivatives/{thumbs,frames,heatmaps,transcripts,overlays,audio,reports}` | Large | **Reproducible from originals** — lowest priority |
| Model artifacts | `models/` `0555` | Multi-GB | Reprovisionable from `models.lock.json` — **not backed up by default** |
| Configuration | `config/` `0750`, `.env`, compose files | Tiny | **Critical** — without it nothing else can be restored |
| Audit chain anchors | `anchors/` | Tiny | **Critical** — proves the audit chain was not rewritten |
| LUKS2 key material | Sealed key file, separate boot partition | Bytes | **Existential** — see §5 |

**Priority order for a partial restore:** LUKS2 keys → configuration → PostgreSQL → audit anchors →
evidence originals → derivatives → models.

Restoring evidence without the database yields files nobody can attribute to a case. Restoring the
database without the keys yields metadata about files nobody can read. **Configuration and key
material are small and are backed up most frequently for exactly that reason.**

---

## 3. Encryption of backups

> ### ⚠️ Volume encryption does not encrypt your backups
>
> LUKS2 ([ADR-0006](adr/ADR-0006-luks2-volume-encryption-only.md)) protects data **at rest on the
> volume**. The moment a backup is exported, streamed or copied off that volume, **it is plaintext
> unless the backup process encrypts it independently.** Assuming otherwise is the single most common
> way a well-encrypted deployment leaks everything.

Backup encryption is therefore a **separate control**:

| Control | Mechanism |
|---|---|
| Backup payload encryption | **age** (or GPG) with a recipient key held **separately** from the host |
| Key custody | The backup encryption key is **not** the LUKS2 passphrase and is **not** stored on the host, in git, in an image or in an ordinary env file |
| Transfer | Encrypted **before** transfer, always. No plaintext backup ever leaves the volume |
| Verification | A restore rehearsal proves backups are decryptable **without** the host volume key (§9) |

Two independent keys means two independent loss modes. §5 covers both.

---

## 4. Backup schedule

| Asset | Method | Frequency | Retention |
|---|---|---|---|
| PostgreSQL | `pg_basebackup` + continuous WAL archiving | Base nightly; WAL every 5 min | 14 daily, 8 weekly, 12 monthly |
| Configuration + compose | `tar` → age | Nightly **and** on every change (git-hooked) | 90 days |
| Audit anchors | `rsync` → age | Nightly | Indefinite (ADR-0020: never deleted) |
| Evidence originals | Incremental `rsync` of new content-addressed files | Nightly window | Per statutory retention |
| Derivatives | **Not backed up by default** | — | Reproducible; purged at 90 days (ADR-0020) |

**Evidence backups are incremental by construction.** Because originals are content-addressed by
SHA-256 and write-once ([ADR-0011](adr/ADR-0011-filesystem-storage-backend-only.md)), a file present
in the backup can never change. Nightly runs transfer only new digests — no diffing, no change
detection, no risk of copying a partially written file (the `O_EXCL` rename guarantees atomic
appearance).

**Audit and custody records are never deleted in v1** ([ADR-0020](adr/ADR-0020-retention-without-a-default-statutory-period.md));
they are archived after `AUDIT_ARCHIVE_AFTER_DAYS=730`, and archiving preserves hash-chain
verifiability.

---

## 5. LUKS2 key custody and recovery

> ### 🔴 The existential risk
>
> **A lost LUKS2 passphrase with no escrow means permanent, unrecoverable data loss.** There is no
> backdoor, no vendor recovery, and no engineering workaround. Everything in §4 is worthless if the
> key is gone. This is the highest-severity risk in the entire deployment and is treated accordingly.

### 5.1 Key material

| Item | Storage | Permissions |
|---|---|---|
| LUKS2 passphrase | Sealed key file on a **separate unencrypted boot partition**, or entered at the console | `0400`, root only |
| LUKS2 **recovery key** | Escrowed per §5.2 — **never on the host** | Physically secured |
| Backup encryption key (age/GPG) | Escrowed **separately** from the LUKS2 recovery key | Physically secured |

**Never stored in:** GitHub, source code, Docker images, ordinary `.env` files, the evidence volume
itself, or any location that is itself encrypted by the key it protects.

### 5.2 Escrow procedure

1. Generate a LUKS2 recovery key: `cryptsetup luksAddKey` with a high-entropy key file.
2. Split it (Shamir or physical split-envelope) between **at least two authorized administrators** in
   **separate physical locations**.
3. Store the backup encryption key escrow **separately** from the LUKS2 recovery escrow — a single
   compromised location must not yield both.
4. Record the escrow in a paper register: who holds which share, when it was last verified.
5. **Verify escrow annually** by decrypting a test payload with the recovery key. An untested escrow
   is an assumption, not a control.

### 5.3 Boot-time unlocking

* **Interactive:** passphrase at the console during boot. Strongest; requires a person present.
* **Unattended:** sealed key file on the boot partition. Convenient; **the boot partition then becomes
  a critical secret** and must itself be access-controlled, ideally with TPM2 sealing.
* Authorized admin access to the unlocked volume is restricted by Linux permissions on the mount
  (`0440` originals, `0700` postgres, `0555` models, `0750` backups) in addition to volume encryption.

> **Honest limitation.** Unattended unlocking means anyone with physical access to a powered-on host
> can read the evidence. Volume encryption protects **data at rest**, and **does not protect against an
> attacker with access to an already-unlocked, running server.** Application controls
> ([ADR-0004](adr/ADR-0004-single-organisation-tenancy-with-capability-rbac.md) RBAC, the audit chain,
> break-glass with justification) are the mitigation there, and they are a different layer with
> different guarantees.

### 5.4 Preflight verification before start

`infra/scripts/verify-encrypted-mount.sh` runs **before** the application starts and **refuses to
start** if:

* the expected encrypted volume is not mounted;
* the mount is not backed by a LUKS2 device;
* it is mounted at the wrong path;
* evidence directories are writable by the wrong uid, or are group/world-readable;
* any evidence path resolves under a directory served by nginx.

`PREFLIGHT_REQUIRED=true` is **mandatory in production**; setting it false aborts startup. A silently
unmounted volume would write evidence to the unencrypted root filesystem, which is exactly the failure
this check exists to prevent.

`auditd` key `tlx_cryptdb` → `tlx_crypttab` detects tampering with the mount configuration.

---

## 6. Restore procedures

### 6.1 Restore PostgreSQL

```bash
# 1. Stop the application — never restore under a live writer
docker compose -f compose/docker-compose.yml stop api beat worker-cpu worker-gpu

# 2. Verify the backup before touching anything
age --decrypt -i /mnt/escrow/backup-key.age backups/db/latest.tar.age | tar -tf - >/dev/null

# 3. Decrypt and extract
age --decrypt -i /mnt/escrow/backup-key.age backups/db/latest.tar.age | tar -xf - -C /var/tmp/restore

# 4. Restore the base, then replay WAL to the target time
#    (run as tlx_migrator; tlx_app has no DDL rights)
pg_restore --clean --if-exists -U tlx_migrator -d truthlens /var/tmp/restore/base.dump
psql -U tlx_migrator -d truthlens -c "SELECT pg_wal_replay_status();"   # confirm caught up

# 5. VERIFY THE AUDIT CHAIN before declaring success — see §7
# 6. Shred the plaintext working copy
shred -u /var/tmp/restore/base.dump && rm -rf /var/tmp/restore
```

**Step 5 is not optional.** A restore that produces a database whose audit chain does not verify has
produced a database that cannot support evidence. Restore then verify, always in that order.

### 6.2 Restore evidence originals

```bash
# Content-addressed and write-once: restore is additive and idempotent.
age --decrypt -i /mnt/escrow/backup-key.age backups/evidence/incr-2026-11-10.tar.age \
  | tar -xf - -C /srv/truthlens/evidence/

# Re-apply write-once protections that tar does not preserve
find /srv/truthlens/evidence/originals -type f -exec chmod 0440 {} +
find /srv/truthlens/evidence/originals -type f -exec chattr +i {} +

# Verify every restored file against its recorded digest
docker compose exec api python -m app.tools.verify_integrity --scope restored --fail-on mismatch
```

Because filenames **are** SHA-256 digests, verification is self-describing: a file whose content does
not match its name is corrupt by definition. `verify_integrity` re-hashes and compares against
`physical_objects.sha256`. **Any mismatch fails closed** — the item is quarantined, never silently
accepted and never silently passed.

### 6.3 Restore configuration

Configuration restore precedes everything else in a full DR event (§6.4) — without it no service knows
where its data is.

```bash
age --decrypt -i /mnt/escrow/backup-key.age backups/config/latest.tar.age | tar -xf - -C /srv/truthlens/
chmod 600 /srv/truthlens/config/.env
# Then re-run preflight BEFORE starting anything
./infra/scripts/verify-encrypted-mount.sh
```

Secrets in `.env` are **generated by `infra/scripts/genkeys.sh`** and never committed. If the
configuration backup is lost but the host survives, `.env` on the host is authoritative. If both are
lost, **signed-URL and JWT keys change**, which invalidates all sessions and all outstanding signed
URLs — acceptable, because evidence integrity depends on SHA-256 digests, not on those keys.

### 6.4 Full disaster recovery (host loss)

Target: **4–8 hours** (see §7.1 — this exceeds the nominal 4 h RTO, honestly).

| # | Step | Est. | Notes |
|---|---|---|---|
| 1 | Provision replacement hardware; install OS | 1–3 h | Depends entirely on spares availability |
| 2 | Create and unlock the LUKS2 volume | 15 min | Requires the escrowed key (§5.2) |
| 3 | **Run `verify-encrypted-mount.sh`** | 2 min | Must pass before anything is installed |
| 4 | Restore configuration | 10 min | §6.3 |
| 5 | Install Docker + pinned Compose; pull pinned images | 30 min | Images are digest-pinned, so this is reproducible |
| 6 | Start PostgreSQL and Redis **only** | 5 min | Nothing else yet |
| 7 | Restore the database base + WAL replay | 30–60 min | §6.1 |
| 8 | **Verify the audit chain** | 10 min | §7 — gate before continuing |
| 9 | Restore evidence originals | 1–4 h | Scales with volume; incremental sets restore faster |
| 10 | Verify evidence integrity | 30–90 min | §6.2 — re-hash every restored file |
| 11 | Reprovision model artifacts | 30 min | From `models.lock.json`; hash-verified; loader refuses mismatches |
| 12 | Start `api`, then workers, then `frontend` | 10 min | In dependency order |
| 13 | Smoke test: `/healthz`, `/readyz`, `/api/v1/status` | 5 min | All checks must be `ok` |
| 14 | Restore nginx TLS material; verify headers | 15 min | `infra/nginx/security-headers.conf` |
| 15 | Post-incident: re-escrow keys, rotate secrets, write the report | — | Compromise must be assumed until disproven |

**Steps 8 and 10 are gates, not checkpoints.** Do not proceed past either one on a failure.

---

## 7. Recovery objectives — stated honestly

### 7.1 Single-host reality

| Objective | Nominal target | **Realistic on a single host** | Why the gap |
|---|---|---|---|
| **RPO** | ≤ 24 h | **≤ 24 h** (≤ 5 min for the database via WAL) | Evidence is nightly; the database is near-continuous. **Up to 24 h of evidence ingested since the last backup can be lost.** |
| **RTO** | ≤ 4 h | **4–8 h** | Hardware provisioning dominates and is not under software control. With no spares on site it can be **days**. |
| Availability | 99.5% | **Best-effort, no HA** | ~43.8 h of downtime per year is inside the target. A single host has no failover. |
| Hot standby | — | **None** | There is no second host. This is a deliberate scope decision ([ADR-0005](adr/ADR-0005-single-host-docker-compose-deployment.md)), not an oversight. |

> ### What this architecture does **not** provide
>
> * **No failover.** If the host dies, the service is down until it is restored or replaced.
> * **No hot standby, no replica, no automatic promotion.**
> * **No protection against site loss** unless backups are stored off-site — which the owner must
>   arrange; this document specifies *that* backups must be encrypted before leaving the volume, not
>   *where* they go.
> * **No recovery from LUKS2 key loss.** Permanent data loss. §5 exists to make that unlikely.
> * **No protection against a live-server attacker.** §5.3.

These limitations are recorded here rather than softened, per the owner's instruction to *document
single-host availability limitations and recovery honestly*.

### 7.2 Reducing the gap (v2 backlog, not v1)

Streaming replication to a second host; off-site object storage behind the `StorageBackend` interface
([ADR-0011](adr/ADR-0011-filesystem-storage-backend-only.md) — the interface is shaped for this, but
**no S3 code ships in v1**); more frequent evidence backups; RFC 3161 timestamping of audit anchors.

---

## 8. Verification of backups

**An unverified backup is a hypothesis.** Each of these runs on a schedule and alerts on failure:

| Check | Frequency | Fails when |
|---|---|---|
| Backup job exit status | Every run | Any non-zero exit |
| Backup size sanity | Every run | Size deviates from the rolling baseline by more than a configured threshold (catches empty and truncated backups) |
| **Decryptability** | Weekly | A sample cannot be decrypted with the escrowed key |
| **Restore rehearsal** | **Quarterly** | A full restore into an isolated environment does not produce a verified, working system |
| Audit chain verification | Nightly (beat job) **and** after every restore | Any `prev_hash`/`record_hash` link fails |
| Evidence integrity sampling | Nightly | A sampled file's digest does not match its recorded SHA-256 |
| Escrow key verification | **Annually** | The recovery key cannot decrypt a test payload |
| Preflight | **Every startup** | The encrypted volume is absent, unencrypted or mis-mounted |

The **quarterly restore rehearsal is the only check that proves the whole chain works.** Everything
else proves a part of it. A rehearsal that has not happened in more than a quarter is treated as an
incident in its own right.

---

## 9. Restore rehearsal procedure

Run quarterly, into an **isolated environment that is not the production host**.

1. Provision a scratch host or VM with a LUKS2 volume.
2. Run `verify-encrypted-mount.sh` — it must pass.
3. Restore configuration from the **most recent** production backup.
4. Restore the database; replay WAL.
5. **Verify the audit chain end-to-end.** Every `custody_events` and `audit_logs` link must validate.
6. Restore a **representative sample** of evidence (all size classes and types, not just the newest).
7. Verify every restored file's SHA-256 against `physical_objects`.
8. Start the API; assert `/healthz`, `/readyz` and `/api/v1/status` all report healthy.
9. Open a case, view evidence metadata, generate a report — confirm the report's `manifest_hash`
   matches the pre-disaster value for the same inputs ([ADR-0019](adr/ADR-0019-report-manifest-hashing-with-optional-crypto-signing.md) determinism makes this a strong check).
10. **Record the elapsed time** against §7.1. If it exceeds the documented window, update the document
    — do not quietly revise the target.
11. **Securely destroy the rehearsal environment**, including its volume keys. Rehearsal data is real
    evidence and must not persist.

A rehearsal that skips step 5 or step 7 has not tested the property that matters.

---

## 10. Operational scripts

| Script | Purpose |
|---|---|
| `infra/scripts/genkeys.sh` | Generate all application secrets with `openssl rand`; write to `.env` at `0600`; never print to stdout in CI |
| `infra/scripts/verify-encrypted-mount.sh` | §5.4 preflight — **must pass before the app starts** |
| `infra/scripts/backup.sh` | Orchestrate §4: dump, encrypt with age, verify, rotate, alert |
| `infra/scripts/restore.sh` | Guided §6 restore with **mandatory verification gates** at steps 8 and 10 |
| `infra/scripts/fetch-models.sh` | Provision model artifacts on a networked machine against `models.lock.json` |

Every script: `set -euo pipefail`, no secrets in arguments (they leak via `ps` and shell history),
explicit paths, and a non-zero exit on any failure. **No script silently continues past an error** —
in a forensic system, a partial restore reported as success is worse than a failed restore.

---

## 11. Backup retention and legal holds

* `legal_hold` **overrides every retention and purge path**, including backup rotation
  ([ADR-0020](adr/ADR-0020-retention-without-a-default-statutory-period.md)). A held item is not
  deleted, purged or derivative-cleaned regardless of age — and its backups are not rotated out.
* `RETENTION_STATUTORY_DAYS` **has no default**. Until an operator sets it, retention jobs delete
  **nothing** and the admin dashboard shows a persistent warning. This means storage grows; capacity
  planning must assume indefinite growth until the value is set on legal advice.
* Audit and custody records are **never deleted in v1**, so their backups are never pruned.

---

## 12. Threat coverage

| Threat | Mitigated? | By |
|---|---|---|
| Host hardware failure | ✅ | §6.4 full DR |
| Accidental deletion / corruption | ✅ | Backups + write-once originals + immutability triggers |
| Ransomware on the host | ⚠️ **Partially** | Encrypted off-host backups survive; **on-host backups would be encrypted by the attacker.** Off-site copies are essential. |
| Theft of the physical host | ✅ | LUKS2 at rest ([ADR-0006](adr/ADR-0006-luks2-volume-encryption-only.md)) |
| Theft of a backup medium | ✅ | age/GPG encryption before it leaves the volume (§3) |
| **Loss of the LUKS2 key** | ❌ **Not recoverable** | §5.2 escrow is the only defence |
| **Loss of both host and off-site backups** | ❌ **Total loss** | No mitigation exists within a single-host architecture |
| Insider destruction of evidence | ✅ | Two-person hard deletion, permanent audit, chain anchors (§8) |
| Attacker with access to an **unlocked, running** server | ❌ | Explicitly out of scope for volume encryption (§5.3); application RBAC and audit are the compensating controls |
| Site loss (fire, flood) | ⚠️ **Only if backups are off-site** | This document mandates encryption before transfer; **where** they go is the owner's decision |

The ❌ and ⚠️ rows are the honest answer to "what can go wrong that this will not save us from."

---

## 13. Verification

| Requirement | Verified by |
|---|---|
| Preflight blocks startup on an unencrypted or missing volume | `verify-encrypted-mount.sh` tested **both ways** — pass and fail-closed |
| `EVIDENCE_ENCRYPTION` accepts only `disabled` in v1 | Unit test asserts startup aborts on any other value |
| `PREFLIGHT_REQUIRED=true` mandatory in production | Unit test asserts production startup aborts when false |
| Backups are encrypted before transfer | Script test asserts no plaintext artifact is written outside the volume |
| Restored evidence matches its recorded digests | `verify_integrity --scope restored` fails on any mismatch |
| Audit chain survives a restore | Nightly beat job + post-restore gate (§6.1 step 5) |
| Restore rehearsal proves the whole chain | Quarterly, §9 — the only end-to-end proof |
| Retention unset deletes nothing | Unit test asserts zero rows deleted and a warning emitted |
| Legal hold survives purge and rotation | Unit test asserts a held item and its backups persist |
| Backups decryptable without the host volume key | Weekly decryptability check with the **escrowed** key only |

> **Sandbox limitation, recorded honestly.** The development environment has **no Docker daemon and no
> live PostgreSQL or Redis**, so `docker compose config`, the backup scripts and the restore rehearsal
> **cannot be validated locally**. They are validated in CI and on the target host. No claim of local
> end-to-end backup verification is made anywhere in this repository — see risk **RR-2** in
> [IMPLEMENTATION_ROADMAP §7](IMPLEMENTATION_ROADMAP.md).
