# ADR-0008 — The repository carries no LICENSE file until a deliberate decision is made

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 · **requires re-review before the repository is made public** |
| **Decision ID** | D-008 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [THIRD_PARTY_LICENSE_AUDIT](../THIRD_PARTY_LICENSE_AUDIT.md) |

## Context

The owner directed: **no LICENSE file; keep the repository unlicensed until a deliberate decision.**
This ADR records that instruction and its consequences so the absence of a licence is never mistaken
for an oversight.

## Decision

1. The repository contains **no `LICENSE`, `COPYING` or equivalent file**, and no licence header is
   added to source files.
2. No licence is implied anywhere in the documentation. `README.md` states explicitly that the
   project is deliberately unlicensed and points here.
3. OpenAPI metadata published by the API **omits** `license` and `contact` fields, so a generated
   client cannot infer terms that were never granted.
4. Third-party obligations are still met independently of our own licence: `THIRD_PARTY_LICENSES.md`
   and an SBOM are generated per release, and copyleft notices for MPL-2.0 / LGPL / GPL tooling are
   reproduced as those licences require. **Not licensing our own code does not remove upstream
   obligations.**
5. This decision **must be revisited before the repository is made public.** Unlicensed public code
   is, by default copyright, fully rights-reserved: nobody may legally copy, modify, redistribute or
   contribute. That is a legitimate choice, but it must be a *chosen* one, and it materially affects
   whether outside contribution or reuse is possible.

## Alternatives considered

| Option | Verdict |
|---|---|
| Apache-2.0 | Strong candidate for a later decision — patent grant, compatible with the permissive dependency posture in ADR-0001, and unproblematic alongside MPL-2.0 and LGPL subprocess tooling. **Not adopted now.** |
| AGPL-3.0 | Rejected — would impose network copyleft on anyone operating a fork, and contradicts the care taken in ADR-0001 to *avoid* AGPL in the dependency graph. |
| Proprietary / all-rights-reserved notice | Effectively what "unlicensed" already means; an explicit notice would be clearer but was not requested. |
| Dual licence (AGPL + commercial) | Rejected for v1 — requires legal infrastructure the project does not have. |

## Rationale

Choosing a licence is an ownership and legal decision, not an engineering one. Recording the absence
deliberately prevents a well-meaning contributor from adding a `LICENSE` file and changing the
project's legal posture by accident.

## Consequences

* No third party may legally reuse the code as things stand.
* Contributors submit work under no explicit grant; a CLA or DCO decision accompanies any future
  licence choice.
* Dependency obligations are unaffected and still enforced by CI (`tools/license-check/`).

## Licensing implications

This ADR **is** the licensing implication: default copyright, all rights reserved. It makes no
compliance claim about third-party code — that lives in `THIRD_PARTY_LICENSE_AUDIT.md`, which
explicitly does not assert legal compliance and lists open findings L-1…L-11 for counsel.

## Security implications

None directly. Indirectly, an unlicensed repository receives fewer external security reviews, so the
project must not rely on community audit for its security posture.

## Reversal strategy

Adding a licence is a single-file change plus a `README` and `CONTRIBUTING` update. It is **not**
retroactively clarifying: code already published unlicensed stays under default copyright for anyone
who obtained it before the licence was added, so the decision is best made early rather than late.

## Verification

* CI asserts no `LICENSE`/`COPYING` file exists while this ADR is in `Accepted` status, so an
  accidental addition fails the build and forces a conscious update to this ADR.
* `README.md` contains an explicit unlicensed statement linking here.
* Generated OpenAPI contains no `license` key (asserted by a contract test).
