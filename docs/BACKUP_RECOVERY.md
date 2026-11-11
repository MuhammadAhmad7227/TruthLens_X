# TruthLens X — Backup, Recovery & Encryption at Rest

| | |
|---|---|
| **Document ID** | TLX-DOC-012 |
| **Version** | 1.0.0 |
| **Status** | ACTIVE — required by decisions **D-005** (conditions 7, 8, 12) and **D-006** (all 12 conditions), recorded in **ADR-0005** and **ADR-0006** |
| **Last updated** | 2026-11-10 |
| **Approved approach** | **Linux LUKS2 full-volume encryption** for evidence, database, and backup storage. **No application-level envelope encryption in v1.** |
| **Related** | [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md) · [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) §3, §5.5 |

---

## 1. The decision and its honest limits

### 1.1 What was approved

> *"Confirm disk/volume encryption only for TruthLens X v1… Use Linux LUKS2 full-volume encryption
> for the evidence storage volume… Do not implement application-level AES-256-GCM envelope
> encryption in v1."* — D-006 approval, 2026-11-10

Accordingly:

- `EVIDENCE_ENCRYPTION=disabled` remains the setting. The envelope-encryption code path
  (`physical_objects.encryption = aes256gcm_envelope`, `wrapped_dek`) is **designed but not
  implemented** in v1. The schema keeps the columns so enabling it later is a migration, not a
  redesign.
- All at-rest protection comes from **LUKS2** at the block-device layer.

### 1.2 What LUKS2 does and does not protect against

This must be stated plainly, because over-claiming encryption is a common and dangerous error.

| Threat | Protected by LUKS2? | Notes |
|---|---|---|
| Stolen physical server / disks | ✅ **Yes** | The primary use case |
| Disks improperly disposed of or RMA'd | ✅ **Yes** | Degaussing/shredding still recommended at end of life |
| Stolen backup media | ✅ **Yes, if the backup is itself encrypted** — see §6.1. This is **not** automatic | A backup copied off an unlocked volume is **plaintext** unless you encrypt it during the copy |
| Cold-boot / DMA attack on a running host | ❌ **No** | Keys are in RAM while unlocked |
| **Attacker with access to an already-unlocked, running server** | ❌ **NO** | Requirement 9. Once mounted, files are readable by the service user. LUKS2 provides **no** protection against an application compromise, a stolen session, an insider with host access, or a container escape |
| Malicious/compromised application code | ❌ **No** | Mitigated by the write-once store, RO mounts, RBAC, and hash chaining — not by encryption |
| Ransomware with host access | ❌ **No** | It can encrypt or delete mounted files. Mitigated by immutable/offline backups (§6.4) and `chattr +i` on originals |
| Accidental deletion by an administrator | ❌ **No** | Mitigated by soft-delete, legal hold, second-approver rule, and backups |

**Conclusion:** LUKS2 is a *physical-media* control. The controls against a running-system compromise
are the ones in SECURITY_ARCHITECTURE — write-once storage, read-only mounts, capability-based RBAC,
hash-chained audit, and integrity sweeps. Encryption does not substitute for them, and this document
does not claim it does.

### 1.3 The single catastrophic risk of this design

> **LUKS2 passphrase and recovery key loss = permanent, unrecoverable evidence loss.**

There is no backdoor and no vendor to call. Therefore §5 (key custody) is not optional paperwork — it
is the most important operational procedure in the platform. Deployment is **not** permitted to
proceed to production until key custody is in place and verified (§5.6).

---

## 2. Volume layout

```
Physical host
├── /                      OS volume            (LUKS2 optional — recommended: LUKS2)
├── /srv/truthlens         ← LUKS2 volume "TLXDATA"  (REQUIRED)
│   ├── evidence/
│   │   ├── originals/     write-once, 0550 root:tlx, chattr +i after write
│   │   ├── derivatives/   0750 tlx:tlx
│   │   ├── intake/        0770 tlx:tlx (transient)
│   │   ├── quarantine/    0750 tlx:tlx
│   │   └── anchors/       0550 root:tlx  (off-DB audit chain anchors)
│   ├── postgres/          0700 999:999 (container uid)
│   ├── redis/             0700 999:999
│   ├── models/            0555 root:root (read-only, checksum-pinned)
│   ├── backups/           ← STAGING ONLY. Encrypted archives; see §6.1
│   └── config/            0750 root:tlx  (.env, compose overrides) — NOT a secret store for keys
└── /mnt/tlx-offsite       separate device / mount for a second backup copy (§6.4)
```

**All four data classes live on the encrypted volume** (requirement 2, 3):
originals ✅ · derivatives ✅ · PostgreSQL data ✅ · backups ✅ (plus Redis persistence).

### 2.1 Never a public web directory (requirement 4)

| Control | Mechanism |
|---|---|
| No web server root inside `/srv/truthlens` | nginx serves only the Next.js static output and proxies `/api`; its document root is inside the frontend image, **never** a bind mount of the evidence volume |
| No static file handler for evidence | The API has no route that maps a URL path to a filesystem path under `evidence/`. Byte access occurs only through `:download-url` (signed, short-lived, audited) and `/content` (authenticated, audited, rate-limited) |
| Path construction is hash-only | Storage paths are derived from SHA-256 hex, never from user input; `resolve_within_root()` is the sole path builder and is property-tested |
| Directory permissions | `originals/` is `0550` — not world-readable, not group-writable |
| nginx config assertion | A deployment verification step (§8) greps the effective nginx config for any `root`/`alias` pointing into `/srv/truthlens` and **fails** if found |
| Firewall | Only 443 (and SSH) are reachable; the storage host port range is not published |

---

## 3. LUKS2 provisioning

```bash
# ── One-time setup on the host (performed by an authorised administrator) ──────
# 1. Identify the device CAREFULLY. Wrong device = data loss.
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
DEV=/dev/nvme1n1                        # ← the DEDICATED evidence device

# 2. Create the encrypted volume (LUKS2, argon2id KDF — the same algorithm family we use for passwords)
sudo cryptsetup luksFormat --type luks2 \
  --cipher aes-xts-plain64 --key-size 512 \
  --hash sha512 --iter-time 5000 \
  --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 \
  --label TLXDATA --subsystem truthlens \
  "$DEV"
#    Enter the PRIMARY passphrase when prompted. It is never written to a file, shell
#    history, or env var. Type it; do not paste from a document on the same machine.

# 3. Add a RECOVERY key slot (slot 1) — a 64+ char random passphrase, generated offline
sudo cryptsetup luksAddKey --pbkdf argon2id --iter-time 5000 "$DEV"    # → slot 1

# 4. Optional: an escrow/offline key slot (slot 2) held by a second custodian
sudo cryptsetup luksAddKey "$DEV"

# 5. Open and create the filesystem
sudo cryptsetup open --type luks2 "$DEV" tlxdata
sudo mkfs.xfs -L TLXDATA -m crc=1 /dev/mapper/tlxdata      # XFS: large files, many inodes

# 6. Mount with hardening options
sudo mkdir -p /srv/truthlens
# /etc/fstab — use the LUKS UUID, not the device name:
#   UUID=<fs-uuid>  /srv/truthlens  xfs  defaults,noatime,nosuid,nodev,noexec  0 2
# /etc/crypttab:
#   tlxdata  UUID=<luks-uuid>  none  luks,discard
sudo mount /srv/truthlens

# 7. Directory structure and permissions
sudo install -d -m 0750 root:tlx        /srv/truthlens/{evidence,config}
sudo install -d -m 0550 root:tlx        /srv/truthlens/evidence/originals
sudo install -d -m 0750 10001:tlx       /srv/truthlens/evidence/{derivatives,quarantine}
sudo install -d -m 0770 10001:tlx       /srv/truthlens/evidence/intake
sudo install -d -m 0550 root:tlx        /srv/truthlens/evidence/anchors
sudo install -d -m 0555 root:root       /srv/truthlens/models
sudo install -d -m 0700 999:999         /srv/truthlens/{postgres,redis}
sudo install -d -m 0750 root:tlx        /srv/truthlens/backups
```

### 3.1 Boot-time unlocking (requirement 5)

Three modes. **Choose one deliberately and record it in the deployment manifest.**

| Mode | How | Security | Availability | Recommended for |
|---|---|---|---|---|
| **A — Manual unlock at boot (default)** | Host boots, an administrator enters the passphrase at the console or over an SSH session with `systemd-ask-password` / `cryptsetup open` | **Highest** — no key material on the host at all | Requires a human at every reboot | Production (our default) |
| B — Network-bound disk encryption (NBDE/Tang) | `clevis` + a Tang server on a separate host; auto-unlock when the Tang server is reachable | High — key never stored on the evidence host; needs the Tang host reachable | Automatic | Production with a second machine available |
| C — TPM2-bound key | `systemd-cryptenroll --tpm2-device=auto`, optionally with a PIN | Medium — key sealed to the TPM; **survives disk theft but not a boot-path compromise** | Automatic | Only where unattended boot is mandatory |

**Prohibited:** storing the passphrase in `/etc/crypttab` as plaintext, in a `.env` file, in a
Docker image layer, in git, in a cloud-init script, or in any shell history.

For mode A, the boot procedure is:

```bash
# After reboot, before starting the stack:
sudo systemctl start systemd-cryptsetup@tlxdata     # prompts for the passphrase
sudo mount /srv/truthlens
sudo /srv/truthlens/config/verify-encrypted-mount.sh   # §8 — MUST pass
cd /opt/truthlens && sudo docker compose up -d
```

A systemd unit `truthlens-preflight.service` runs §8 and **blocks** `docker-compose` from starting
until it succeeds (`Before=docker.service` dependency + `ExecStartPre`). The application cannot start
on an unmounted or wrong volume — this is requirement 11, enforced by the unit rather than by
operator memory.

### 3.2 Administrator access to the unlocked volume (requirement 5, 8)

| Principal | Access | Grant |
|---|---|---|
| `root` | Full | Inherent — treat host root as evidence-custody authority; log host sessions via `auditd` |
| `tlx` group (service group) | Read `originals`, RW `derivatives`/`intake` | Group membership managed by the host admin; changes logged by `auditd` |
| Container UID `10001` | RW on `derivatives`, `intake`; **RO** on `originals` | Enforced by the compose `:ro` mount flag, not just by mode bits |
| Container UID `999` | RW on `postgres/`, `redis/` only | Bind-mount scoped |
| Named human administrators | Via `sudo` with individual accounts, **never a shared login** | `auditd` rules on `/srv/truthlens/evidence/originals` record every open/read by a human shell |

`auditd` rules (deployed by `infra/scripts/install-auditd-rules.sh`):

```
-w /srv/truthlens/evidence/originals -p wa -k tlx_originals_write     # any write = CRITICAL alert
-w /srv/truthlens/evidence/originals -p r  -k tlx_originals_read
-w /etc/crypttab -p wa -k tlx_crypttab
-w /srv/truthlens/config/.env -p wa -k tlx_secrets_change
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F dir=/srv/truthlens -k tlx_deletion
```

### 3.3 Immutable originals (defence beyond encryption)

After a successful ingest, the object file is set `chmod 0440` and (where the filesystem supports it)
`chattr +i`. An immutable file cannot be modified, renamed, or deleted **even by root** without first
removing the flag — which `auditd` records. This is the strongest available protection against
ransomware and against a compromised root, and it complements the DB-level write-once trigger.
The nightly integrity sweep verifies that the flag is still set and reports any exception.

---

## 4. What is backed up

| # | Asset | Location | Method | Frequency | Encrypted? |
|---|---|---|---|---|---|
| B-1 | PostgreSQL (base + WAL for PITR) | `/srv/truthlens/postgres` | `pg_basebackup` + continuous `archive_command` to `/srv/truthlens/backups/wal` | base weekly, WAL continuous | ✅ §6.1 |
| B-2 | Evidence originals | `/srv/truthlens/evidence/originals` | Incremental, content-addressed (restic — dedup maps naturally onto our hash-keyed store) | nightly + post-ingest hook | ✅ restic's own AES-256 + §6.1 |
| B-3 | Evidence derivatives | `…/derivatives` | Incremental (restic) | nightly | ✅ |
| B-4 | Audit chain anchors | `…/evidence/anchors` | Signed digest export, **copied off-host** | nightly | ✅ + signed |
| B-5 | Application configuration | `…/config/.env`, compose files, nginx conf | restic + a separate encrypted copy | on change (git hook for non-secret parts) | ✅ |
| B-6 | Model weights + `models.lock.json` | `…/models` | Copy, or re-fetch from pinned source and verify checksum | on change | ✅ |
| B-7 | Redis persistence (AOF/RDB) | `/srv/truthlens/redis` | File copy | nightly | ✅ |
| B-8 | `auditd` logs | `/var/log/audit` | restic | nightly | ✅ |
| B-9 | Docker image digests + SBOMs | registry / release artifacts | Recorded in the release log | per release | n/a |

**Not backed up:** `intake/` (transient; GC'd), container logs beyond retention, `__pycache__`, and
anything in `.git`.

---

## 5. LUKS key custody (requirement 6, 7) — **the critical procedure**

### 5.1 Key inventory

| Slot | Purpose | Custodian | Format | Stored where |
|---|---|---|---|---|
| 0 | **Primary passphrase** | Operations lead | Human-memorable-but-strong (≥ 4 random words + digits, ≥ 25 chars) | Memorised **and** sealed in the organisation's password manager |
| 1 | **Recovery key** | Organisation | 64+ chars of `openssl rand -base64 48` | Password manager **+** a printed copy in a sealed envelope in a physically separate locked location |
| 2 | **Escrow key** | A second, independent custodian (e.g. legal/compliance officer) | As slot 1 | Separate password manager vault **+** sealed envelope in a **different** physical location |
| — | Tang private key (mode B only) | Tang server admin | — | On the Tang host, itself encrypted |
| — | TPM-sealed key (mode C only) | Hardware | — | TPM; **requires a recovery key anyway** for hardware failure |

### 5.2 Prohibited storage locations (requirement 7 — explicit)

A LUKS passphrase or recovery key must **never** be stored in:

- ❌ GitHub — any repository, any branch, any issue, any PR, any gist, any Actions secret
- ❌ Source code, comments, docstrings, or documentation (this document describes *where* keys live,
  never *what* they are)
- ❌ Docker images, layers, build args, `docker history`, or compose files
- ❌ Ordinary environment files (`.env`, `.env.example`, `/etc/environment`, `/etc/default/*`)
- ❌ `/etc/crypttab` as a plaintext key, or `keyfile=` pointing at an unencrypted file on the same host
- ❌ Shell history, command-line arguments (visible in `ps` and process accounting), or TTY scrollback
- ❌ Cloud storage without its own encryption and access control
- ❌ A single custodian's personal device as the only copy
- ❌ Any backup that is not itself encrypted (§6.1)
- ❌ An AI assistant prompt, a support ticket, or a chat channel

A CI/secret-scanner rule and a pre-commit hook both search for LUKS-shaped material and
`cryptsetup`-adjacent secrets. The deployment verification (§8) asserts no key file exists under
`/srv/truthlens` or in the repository.

### 5.3 Handling procedure

```bash
# Generating a recovery key — do this OFFLINE, on a machine that is not the server:
openssl rand -base64 48        # type it into the password manager by hand; do not pipe to a file
                               # if you must use a file, shred it: shred -u -z keyfile

# Entering it into a LUKS slot — cryptsetup prompts; never pass it as an argument:
sudo cryptsetup luksAddKey --pbkdf argon2id /dev/nvme1n1

# Verify every slot can actually open the volume (do this BEFORE relying on it):
sudo cryptsetup luksOpen --test-passphrase /dev/nvme1n1
sudo cryptsetup luksDump /dev/nvme1n1 | grep -A2 "Keyslots:"
```

### 5.4 Rotation

| Trigger | Action |
|---|---|
| Custodian departure | Rotate immediately; revoke their slot (`cryptsetup luksKillSlot`) and re-issue |
| Suspected exposure | Rotate the affected slot **and** treat the volume as compromised until re-verified |
| Scheduled | Annually, or per organisational policy |
| After a restore from backup onto new hardware | Re-provision LUKS with fresh keys; never reuse keys from a decommissioned host |

Rotation procedure: add a new slot → verify it opens → kill the old slot → update the key inventory →
record the rotation in the operations log (date, slots affected, custodians, authoriser). **No key
value is ever written to the log.**

### 5.5 Recovery when keys are lost

1. **Locate the escrow** (slot 2) or the printed sealed envelope. This is why two independent
   custodians in two locations are required.
2. If all key material is lost: **the data is unrecoverable.** Restore from the most recent encrypted
   backup **whose key is separately held** (§6.1). If that key is also lost, the loss is total.
3. Record the incident, notify the case leads and (where required) the data controller, and treat it
   as a reportable data-loss event affecting evidential continuity.
4. Post-incident: revise key custody to remove the single point of failure that caused it.

> This is why §5.1 requires **three** key slots with **two** independent physical custodians, and why
> production deployment is blocked until §5.6 passes.

### 5.6 Key custody verification gate (blocks production go-live)

- [ ] Slot 0, 1 and 2 all exist and each has been **tested** with `--test-passphrase`
- [ ] Recovery key recorded in the password manager **and** sealed physically, in two locations
- [ ] Escrow key held by a custodian independent of operations
- [ ] No key material found by the secret scanner in the repo, images, or `/srv/truthlens`
- [ ] Rotation procedure rehearsed once on a **test** volume, and the rehearsal documented
- [ ] A **restore drill** (§7.4) completed successfully using the recovery key
- [ ] Two named individuals can independently attest to key custody

---

## 6. Backup encryption (requirement 10) — treated **separately**

### 6.1 Volume encryption does NOT encrypt exported backups

This is the most commonly misunderstood point in the whole design, and requirement 10 exists to
prevent it:

> A file copied **out** of an unlocked LUKS2 volume is **plaintext**. Volume encryption protects the
> blocks on that device only. Once `cryptsetup open` has run, everything under `/srv/truthlens` is
> readable by the service user, and any copy made from it is unencrypted unless you encrypt it
> **during the copy**.

Therefore backups are encrypted **at the application layer of the backup tool**, independently:

| Layer | Mechanism | Key custody |
|---|---|---|
| restic repository encryption | restic encrypts every blob with **AES-256** and authenticates with Poly1305 before writing. The repository key is derived from `RESTIC_PASSWORD`. | **Separate** from the LUKS keys, held by the same three-custodian process (§5.1). Losing it loses all backups. |
| Transport encryption | SFTP/TLS/rsync-over-SSH to the off-host target | Host keys pinned (`known_hosts`), key-based auth |
| Target-side encryption | If the off-host target supports it (another LUKS volume, or object storage with SSE), enable it | Target-managed |
| PostgreSQL dump encryption | `pg_basebackup` output goes into the restic repository (thus encrypted); if a standalone dump is taken, pipe through `age`/`gpg` to a recipient key held per §5.1 | Separate key pair |
| Configuration backup | `.env` contains application secrets → must be restic-encrypted **and** access-restricted; never a plaintext copy | As above |

**Key separation rule:** the backup encryption key must **not** be the LUKS passphrase. If an attacker
obtains the host and its LUKS key, they must still not obtain the ability to read off-host backups —
and vice versa.

```bash
# Example: encrypted backup to an off-host target
export RESTIC_REPOSITORY=sftp:backup@backuphost:/srv/tlx-backups/case-evidence
export RESTIC_PASSWORD_FILE=/run/secrets/restic_password    # tmpfs, mode 0400, from the secret store
restic init                                                   # once
restic backup /srv/truthlens/evidence \
  --tag truthlens,evidence,nightly \
  --exclude /srv/truthlens/evidence/intake \
  --exclude-caches
restic forget --keep-daily 7 --keep-weekly 8 --keep-monthly 24 --keep-yearly 10 --prune
restic check --read-data-subset=5%                            # verify a sample every run
```

`RESTIC_PASSWORD_FILE` points into `/run/secrets` (tmpfs, never persisted, never in the image, never
in git). The systemd unit that runs backups has `LoadCredential=restic_password:/run/secrets/restic_password`
or uses a Docker secret — never an environment variable in a compose file.

### 6.2 Backup integrity

A backup that cannot be restored is not a backup. Every run:

- `restic check --read-data-subset=5%` (rotating, so all data is verified over ~20 runs)
- Records the repository snapshot ID, byte count, and file count into the operations log
- Alerts on any check failure
- Weekly: `restic ls latest | wc -l` compared against a live count, alerting on > 0.5% divergence

### 6.3 Backup of the audit chain anchors (off-host, signed)

The nightly chain-anchor export writes a signed digest of the custody/audit hash chains to
`/srv/truthlens/evidence/anchors/`. These are copied **off-host** so that an attacker who rebuilds
the in-database chain cannot also forge the already-published digests (mitigates threat T-02). The
signing key is separate from both the LUKS and backup keys.

### 6.4 Backup topology (3-2-1, adapted for a single host)

| Copy | Location | Ransomware-resistant? |
|---|---|---|
| 1 — live data | `/srv/truthlens` (LUKS2) | No |
| 2 — on-host backup repository | `/srv/truthlens/backups` (restic, encrypted) | Partially (encrypted, but on the same host) |
| 3 — off-host backup repository | Separate machine or separate physical device, restic/SFTP, **append-only** where possible | **Yes** — this is the copy that matters |
| 4 — offline/cold copy (recommended) | Detached drive or write-once media, stored in a separate building, refreshed quarterly | **Yes** |

Where the off-host target supports it, enable **immutable/append-only** mode (restic's
`append-only` SFTP configuration, or object-lock on S3-compatible storage) so a compromised
TruthLens host cannot delete or rewrite the backups. This is the single highest-value hardening step
for a single-host deployment.

---

## 7. Restoration & disaster recovery

### 7.1 Recovery objectives (single host — stated honestly per D-005 condition 12)

| Scenario | RPO | RTO | Notes |
|---|---|---|---|
| PostgreSQL corruption / accidental destructive change | ≤ 5 min (WAL archiving) | 1–2 h | Point-in-time recovery to just before the bad change |
| Single evidence file corrupted | 0 (originals are write-once and hash-verified) | minutes | Restore from backup; verify hash matches the DB record |
| Host disk failure | ≤ 24 h (nightly) / ≤ 5 min (WAL) | 4–8 h | New host → LUKS provision → restore → verify |
| Total host loss (theft/fire) | ≤ 24 h | 8–24 h | Requires the off-host backup **and** the LUKS/recovery keys |
| Ransomware | ≤ 24 h | 8–24 h | Requires the **immutable off-host** copy; the on-host copy may be encrypted/deleted by the attacker |
| LUKS key loss, backups intact | as backups | 4–8 h | Restore onto a newly provisioned volume |
| LUKS key loss **and** backup key loss | **unrecoverable** | ∞ | Prevented by §5.1 three-slot custody |

**Availability limitation (honest statement):** a single-host deployment has **no** hot standby.
During any of the above, the platform is unavailable to users. Evidence already ingested remains
protected by the write-once store and backups, but investigative work stops. If continuous
availability is a requirement, that is a change to D-005 and needs a second host plus replication —
which is explicitly **not** in v1.

### 7.2 Restore: PostgreSQL point-in-time

```bash
# 1. STOP the application — never restore under a running system
cd /opt/truthlens && sudo docker compose down

# 2. Snapshot the current (possibly corrupt) state for forensic examination FIRST
sudo mv /srv/truthlens/postgres /srv/truthlens/postgres.incident.$(date -u +%Y%m%dT%H%M%SZ)

# 3. Restore the base backup into a fresh data directory
sudo -u 999 pg_restore_base --from /srv/truthlens/backups/pg/base/<latest> \
                            --to   /srv/truthlens/postgres

# 4. Configure the recovery target
sudo -u 999 tee /srv/truthlens/postgres/postgresql.auto.conf <<'EOF'
restore_command = 'restic dump --path /srv/truthlens/backups/wal %f %p'
recovery_target_time = '2026-11-09 18:00:00+00'
recovery_target_action = 'pause'
EOF
sudo touch /srv/truthlens/postgres/recovery.signal

# 5. Start Postgres alone, inspect at the pause point, then promote
sudo docker compose up -d postgres
sudo docker compose exec postgres psql -U tlx_admin -c "SELECT pg_last_wal_replay_lsn();"
sudo docker compose exec postgres psql -U tlx_admin -c "SELECT pg_wal_replay_resume();"

# 6. VERIFY before starting the app
sudo docker compose exec postgres psql -U tlx_admin -d truthlens -c \
  "SELECT count(*) FROM evidence_items;"
```

### 7.3 Restore: evidence store

```bash
# 1. Application down (as above)
# 2. Restore
restic restore latest --target /srv/truthlens/restore-evidence --tag evidence
# 3. Reconcile: every physical_object row must exist on disk AND hash correctly
sudo docker compose up -d postgres api
sudo docker compose exec api python -m app.cli integrity-sweep --full \
    --report /srv/truthlens/backups/reports/sweep.$(date -u +%F).json
# 4. Any mismatch or missing object is a CRITICAL finding — do not resume casework on it
sudo docker compose exec api python -m app.cli audit-chain verify --all
# 5. Re-apply immutability
sudo /srv/truthlens/config/reapply-immutability.sh   # chmod 0440 + chattr +i on all originals
```

### 7.4 Restore drill (scheduled — requirement 8)

A backup is a hypothesis until restored. **Quarterly**, and after any significant change:

1. Provision a clean test host (or a VM) with a fresh LUKS2 volume using the **recovery key** (§5.6).
2. Restore Postgres and a sample of ≥ 100 evidence objects from the off-host repository.
3. Run `integrity-sweep --full` — every restored object must hash to its recorded SHA-256.
4. Run `audit-chain verify --all` — must report `valid`.
5. Run `python -m app.cli smoke-test` — ingest a fixture, verify, analyse (stub engine), report.
6. Record: date, participants, duration, snapshot IDs, sweep result, chain result, discrepancies,
   corrective actions. File it in `docs/runbooks/restore-drills/`.
7. **A failed drill is a critical operational incident**, tracked to closure.

### 7.5 Full disaster recovery sequence

```
Declare incident → preserve forensic state of the failed host (do NOT wipe)
  → provision replacement host (OS, Docker, NVIDIA if GPU)
  → install auditd rules, firewall, SSH hardening
  → provision LUKS2 volume with FRESH keys (§3) using the escrow process
  → retrieve backup keys from custody (§5.1)
  → restore Postgres (§7.2) and evidence (§7.3)
  → restore config and models; re-verify model checksums against models.lock.json
  → integrity-sweep --full  AND  audit-chain verify --all   ← MUST both pass
  → smoke-test
  → notify case leads; record the outage window in each affected case's audit trail
  → post-incident review within 5 business days
```

**Note on evidential continuity:** after any restore, the affected cases must record that a recovery
occurred, with the window and the verification results. An unexplained gap in a custody record is
worse than a documented one. The platform writes this automatically as a case-level `custody_event`
of type `integrity_alert` with `detail.recovery = true` (implemented in M19).

---

## 8. Deployment verification (requirement 11) — **blocks application start**

`/srv/truthlens/config/verify-encrypted-mount.sh`, run by `truthlens-preflight.service` before
`docker compose up`. **Every check must pass or the stack does not start.**

```bash
#!/usr/bin/env bash
set -euo pipefail
fail(){ echo "PREFLIGHT FAIL: $*" >&2; exit 1; }

# 1. The device-mapper target exists and is LUKS2
[ -e /dev/mapper/tlxdata ] || fail "/dev/mapper/tlxdata not present — volume not unlocked"
cryptsetup status tlxdata | grep -q "type:\s*LUKS2" || fail "tlxdata is not a LUK2 device"

# 2. It is actually mounted at the expected path
findmnt -no TARGET /dev/mapper/tlxdata | grep -qx "/srv/truthlens" \
  || fail "tlxdata is not mounted at /srv/truthlens"

# 3. The filesystem is the expected one and is NOT mounted read-write world-accessible
findmnt -no FSTYPE,OPTIONS /dev/mapper/tlxdata | grep -q "^xfs" || fail "unexpected filesystem type"
findmnt -no OPTIONS /dev/mapper/tlxdata | grep -q "nosuid" || fail "volume not mounted nosuid"

# 4. We are not accidentally writing to the unencrypted root device
df --output=source /srv/truthlens | tail -1 | grep -q "/dev/mapper/tlxdata" \
  || fail "/srv/truthlens is NOT on the encrypted volume"

# 5. Directory permissions and ownership
[ "$(stat -c %a /srv/truthlens/evidence/originals)" = "550" ] || fail "originals must be 0550"
[ "$(stat -c %a /srv/truthlens/postgres)" = "700" ]           || fail "postgres dir must be 0700"

# 6. No key material lying around on the volume or in the repo
! find /srv/truthlens -maxdepth 3 -name "*luks*key*" -o -name "*recovery*key*" | grep -q . \
  || fail "possible LUKS key file found on the volume — remove it (§5.2)"
! grep -RIl --exclude-dir=.git -e "luksAddKey" -e "RESTIC_PASSWORD=" /srv/truthlens/config /opt/truthlens 2>/dev/null | grep -q . \
  || fail "possible secret material in config/repo — see §5.2"

# 7. nginx does not serve anything from the evidence volume
! grep -REq "(root|alias)\s+/srv/truthlens" /opt/truthlens/infra/nginx/ \
  || fail "nginx config references the evidence volume — §2.1 violation"

# 8. Sufficient free space (a full disk during ingest can truncate a file)
avail=$(df -BG --output=avail /srv/truthlens | tail -1 | tr -dc '0-9')
[ "$avail" -ge 50 ] || fail "less than 50 GB free on the encrypted volume"

# 9. Clock synchronisation (timestamps are evidence)
timedatectl show -p NTPSynchronized --value | grep -q yes || fail "NTP not synchronised"

# 10. auditd rules loaded
auditctl -l | grep -q tlx_originals_write || fail "auditd rules not installed (§3.2)"

echo "PREFLIGHT OK: LUKS2 volume tlxdata mounted at /srv/truthlens, permissions and controls verified."
```

The same checks are exposed as `python -m app.cli verify-deployment` so they can be re-run on demand
and reported in `/api/v1/status`.

---

## 9. Operational schedule

| Task | Frequency | Owner | Evidence produced |
|---|---|---|---|
| Incremental evidence backup | Nightly + post-ingest hook | Automated (systemd timer) | restic snapshot ID in the ops log |
| PostgreSQL WAL archiving | Continuous | Automated | WAL segments |
| PostgreSQL base backup | Weekly | Automated | base backup ID |
| Backup verification (`restic check`) | Every run (5% subset) | Automated | check result |
| Audit chain anchor export off-host | Nightly | Automated | signed digest |
| Integrity sweep (application) | Nightly | Beat job | `integrity_checks` rows + report |
| Audit chain verification | Nightly + on demand | Beat job | `valid` / `broken_at` |
| Disk usage review | Weekly | Operator | alert thresholds 75% / 85% |
| **Restore drill** | **Quarterly** | Operator + witness | Drill record (§7.4) |
| LUKS key custody review | Annually + on personnel change | Custodians | Attestation record |
| Key rotation | Annually or on trigger | Custodians | Rotation log |
| Preflight verification | Every boot + on demand | Automated | `PREFLIGHT OK` |

---

## 10. Runbook index (delivered in M20)

| Runbook | Trigger |
|---|---|
| `runbooks/host-boot-unlock.md` | Host reboot — mode A/B/C procedures |
| `runbooks/luks-key-rotation.md` | Scheduled or triggered key rotation |
| `runbooks/luks-key-loss.md` | Key material lost or compromised |
| `runbooks/restore-postgres-pitr.md` | Database corruption or destructive change |
| `runbooks/restore-evidence.md` | Evidence store loss or corruption |
| `runbooks/full-disaster-recovery.md` | Host loss |
| `runbooks/ransomware-response.md` | Suspected ransomware — **preserve before remediating** |
| `runbooks/integrity-mismatch.md` | Sweep or pre-analysis hash mismatch |
| `runbooks/chain-break.md` | Audit/custody chain verification failure |
| `runbooks/restore-drill.md` | Quarterly drill checklist and record template |
| `runbooks/decommission-host.md` | End of life — crypto-erase + physical destruction of media |

---

## 11. What is deliberately NOT in v1

| Item | Reason | Revisit |
|---|---|---|
| Application-level AES-256-GCM envelope encryption of originals | Approved decision D-006. LUKS2 covers data at rest; envelope encryption would add a second catastrophic key-loss mode with no additional protection against the threats that matter here (a running-system compromise defeats both) | If per-object key revocation or multi-host key isolation becomes a requirement |
| Per-tenant encryption keys | No multi-tenancy in v1 (D-004) | With multi-tenancy |
| HSM-backed key storage | Operational complexity disproportionate for a single host | Phase 2 / high-assurance deployments |
| Continuous replication to a second host | Out of scope for single-host v1 (D-005) | If availability becomes a hard requirement |
| Automated offsite failover | Same | Same |
| Kubernetes volume encryption (CSI secrets) | **No Kubernetes in v1** (D-005 condition 14) | Phase 2 |

---

*End of BACKUP_RECOVERY.md v1.0.0. No backup tooling exists yet; the scripts, systemd units and
preflight checks described here are delivered in M1 (compose + volumes) and M19–M21 (automation,
drills, runbooks).*
