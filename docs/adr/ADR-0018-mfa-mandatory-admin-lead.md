# ADR-0018 — TOTP MFA mandatory for `admin` and `lead_investigator`, optional elsewhere

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-018 |
| **Related** | [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) §3, §5 · [ADR-0004](./ADR-0004-single-organisation-capability-rbac.md) |

## Context
`admin` and `lead_investigator` hold the most consequential powers: user and role management, case
lifecycle, external-AI enablement, and verification of findings. A compromised password at either
level is a serious incident. Field investigators, however, may operate under time pressure and poor
connectivity, where mandatory MFA creates lockout risk.

## Decision
1. TOTP MFA is **mandatory** for `admin` and `lead_investigator` (`MFA_ENFORCEMENT=admin,lead_investigator`).
2. Optional but encouraged for all other roles; a per-role policy can require it.
3. TOTP secrets are encrypted with the application KEK at rest and are **never** stored in plaintext,
   logged, or returned after enrolment (the QR/secret is shown exactly once).
4. Enrolment is confirmed with a live code before activation. Administrators may reset a user's MFA,
   which forces re-enrolment and is audited.
5. Login lockout uses exponential backoff; administrators can unlock. Refresh-token rotation with
   **reuse detection** revokes the whole token family and raises a security alert.
6. `admin` cannot set verification status (separation of duties, ADR-0004) — so MFA plus that
   separation both limit what a compromised admin can do epistemically.

## Alternatives considered
| Option | Verdict |
|---|---|
| Mandatory for everyone | Rejected for v1 — field lockout risk and support burden; can be tightened per role by policy |
| Optional for everyone | **Rejected** — unacceptable for the two roles that can enable external AI egress and change roles |
| WebAuthn/passkeys | Deferred to v2 — better UX and phishing resistance, but a larger implementation surface than v1 warrants |

## Rationale
Concentrate the strongest authentication where the most consequential powers are, and keep the field
workflow usable. The policy is data-driven, so tightening it later is a configuration change.

## Consequences
**Positive:** the highest-privilege accounts resist credential theft; MFA reset is auditable; the
policy is per-role and adjustable.
**Negative / accepted costs:** admin/lead lockouts require an administrator or the recovery-code path;
TOTP is weaker than WebAuthn against real-time phishing (accepted for v1, recorded as residual).

## Licensing implications
`argon2-cffi` MIT, `pyjwt` MIT, a TOTP implementation from the standard library/HMAC primitives.
`passlib` is deliberately **not** used (unmaintained; incompatible with bcrypt ≥ 4.1).

## Security implications
Mitigates T-05 (credential stuffing) and T-06 (stolen refresh token) together with short access-token
TTL, httpOnly/Secure/SameSite=Strict path-scoped cookies, rotation with reuse detection, and the Redis
`jti` denylist. Residual: TOTP codes are phishable in real time; WebAuthn is the v2 answer.

## Reversal strategy
Change `MFA_ENFORCEMENT` — the mechanism is generic per role. Tightening to all roles is a config
change; moving to WebAuthn is additive (a second factor type), not a replacement.

## Verification
- Tests: login without MFA for an enrolled admin → `MFA_REQUIRED`; wrong code → failure + counter;
  lockout and admin unlock; enrolment confirm flow; MFA reset forces re-enrolment.
- Test: the TOTP secret never appears in any log, response or DB column in plaintext (canary test).
- Test: refresh-token reuse revokes the family and writes a security audit event.
