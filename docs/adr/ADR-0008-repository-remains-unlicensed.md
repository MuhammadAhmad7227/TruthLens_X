# ADR-0008 — The repository remains unlicensed pending a deliberate decision

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-008 |
| **Decided by** | Project owner ("Do not add a LICENSE file or claim that the project is open source yet.") |
| **Related** | [ADR-0001](./ADR-0001-permissive-default-dependency-set.md) · [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md) §10 (L-10) |

## Context
The choice of project licence interacts directly with the copyleft decisions: an AGPL project licence
would make ADR-0001/0002/0003 moot, while a permissive licence would make the copyleft flags
unusable in the default set.

## Decision
1. **No `LICENSE` file is added.** The repository remains unlicensed.
2. No documentation, README or artifact claims the project is open source.
3. The default dependency set stays permissive-only (ADR-0001), which preserves **all** future
   licence options — permissive, AGPL, or proprietary.
4. `THIRD_PARTY_LICENSES.md` (generated at build) still lists every third-party component and its
   licence, because that obligation arises from *their* licences regardless of ours.
5. A CI licence gate keeps the tree free of unexpected copyleft so the choice stays open.
6. The decision is tracked as legal item **L-10** and revisited before any external distribution.

## Alternatives considered
| Option | Verdict |
|---|---|
| Add MIT/Apache-2.0 now | Rejected — would make AGPL components permanently unusable and forecloses options before the product is validated |
| Add AGPL-3.0 now | Rejected — a significant, hard-to-reverse strategic commitment made without counsel |
| Add a proprietary "all rights reserved" notice | Deferred — reasonable, but the owner wants a deliberate decision, not a default |

## Rationale
Under copyright law, no licence means **no** grant: the work is fully reserved by default. That is the
most conservative position and costs nothing to reverse, whereas adding a licence and later removing
it does not retract grants already given.

## Consequences
**Positive:** maximum optionality; no accidental grant; the dependency set stays clean.
**Negative / accepted costs:** third parties have no right to use, fork or contribute under a clear
licence, which may slow external collaboration; contributors should be asked for an explicit
assignment/CLA before any licence is chosen.

## Licensing implications
This *is* the licensing implication. Note that our choice does not affect obligations arising from
**dependencies**: AGPL components remain gated off by default, GPL binaries remain subprocess-isolated,
and MPL file-level obligations apply if we ever modify pikepdf (we do not).

## Security implications
Indirect: a clear licence is a prerequisite for external security review and for accepting community
vulnerability reports. Until then, security disclosure is handled privately.

## Reversal strategy
Trivially reversible **forward**: adding a `LICENSE` file at any time grants rights from that moment.
**Not reversible backward**: once published under a licence, copies already distributed retain those
rights. This asymmetry is precisely why the conservative default was chosen.

## Verification
- CI test asserts no `LICENSE`/`COPYING` file exists at the repository root while this ADR is Accepted.
- README states the licence is undecided and links here.
