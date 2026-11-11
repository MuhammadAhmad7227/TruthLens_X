# ADR-0018 — TOTP MFA mandatory for admin and lead_investigator; WebAuthn deferred to v2

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-018 |
| **Related** | [ADR-0004](ADR-0004-single-organisation-tenancy-with-capability-rbac.md), [SECURITY_ARCHITECTURE §4](../SECURITY_ARCHITECTURE.md) |

## Context

`admin` can grant case membership, enable external AI (ADR-0021), approve hard deletion of an
original (ADR-0020) and break glass into evidence content. `lead_investigator` manages case
membership and can close or reopen cases. Credential theft against either role is a
platform-integrity event, not merely an account compromise.

## Decision

1. **TOTP-based MFA is mandatory** for `admin` and `lead_investigator`. An account in either role
   cannot complete enrolment-free login; the second factor is required at authentication, not offered
   as a preference.
2. MFA is **optional but encouraged** for `investigator`, `analyst`, `reviewer` and `auditor`.
3. Enrolment uses a server-generated secret shown once as a URI plus manual-entry string. The secret
   is stored hashed, never in logs, and the redaction processor treats `totp`/`mfa_secret` keys as
   sensitive.
4. **Recovery codes** are issued at enrolment: single-use, hashed at rest, each consumption
   audit-recorded.
5. Rate limiting applies to both password and TOTP verification, with lockout and audit events on
   repeated failure.
6. **WebAuthn/passkeys are v2 backlog**, not v1. TOTP is chosen because it is deployable on a single
   on-premises host with no TLS-certificate-origin dependency for platform-authenticator ceremonies
   and no hardware procurement.
7. Session model: JWT access tokens 15 min, rotating refresh tokens in `httpOnly`/`Secure`/
   `SameSite=Strict` cookies scoped to `path=/api/v1/auth`, refresh-family rotation with **reuse
   detection**, and a Redis `jti` denylist for revocation.

## Alternatives considered

| Option | Verdict |
|---|---|
| WebAuthn in v1 | Deferred — stronger, but adds authenticator provisioning and origin/certificate complexity to a single-host deployment. Correct choice for v2. |
| MFA optional for everyone | Rejected — the roles with platform-altering powers are exactly the ones that must not be opt-out. |
| SMS or email OTP | Rejected — SIM-swap and mail-account compromise make these weaker than TOTP, and email OTP adds an egress dependency (ADR-0012). |
| MFA enforced by the reverse proxy | Rejected — authorisation must live in the application (ADR-0004), and a proxy-level factor cannot be tied to role. |

## Rationale

TOTP is offline-capable, standard, well-understood by investigators, and imposes no egress — which
matters because ADR-0012 forbids default outbound calls. Making it mandatory only for the two roles
that can alter platform state concentrates the friction where the risk is.

## Consequences

* Enrolment is a blocking step for new admins and case leads; the runbook documents it.
* Lost device plus lost recovery codes is an account-recovery event requiring another admin, and is
  documented rather than solved by a backdoor.
* Refresh-token reuse detection means a stolen-and-used refresh token invalidates the whole family,
  which will occasionally log out a legitimate user. That is the intended trade-off.

## Licensing implications

`argon2-cffi` (Apache-2.0/MIT) for password hashing and `pyotp`-class TOTP (MIT). **`passlib` was
explicitly rejected**: BSD-licensed but unmaintained since 2020 and broken against `bcrypt>=4.1`.
No copyleft.

## Security implications

Password hashing is **argon2id with `m=64MiB, t=3, p=4`**. Combined with short-lived access tokens,
rotating refresh families, reuse detection and a revocation denylist, a stolen session has a narrow
window. MFA on privileged roles raises the cost of the highest-impact attack path.

## Reversal strategy

Adding WebAuthn in v2 is additive: a new credential table and a second factor type, with TOTP retained
as a recovery path. Making MFA optional for more roles is a policy-row change in `rbac_matrix`.

## Verification

* Test: an `admin` or `lead_investigator` account without an enrolled second factor **cannot
  authenticate**.
* Test: a valid TOTP succeeds; a replayed or expired code fails; lockout engages after N failures.
* Test: each recovery code is single-use and its consumption writes an audit row.
* Test: refresh-token reuse invalidates the entire family.
* Log-redaction test: the TOTP secret never appears in any captured log output.
