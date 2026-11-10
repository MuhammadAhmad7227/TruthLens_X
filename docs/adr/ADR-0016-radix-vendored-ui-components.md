# ADR-0016 — Radix UI primitives with vendored, in-tree components

| | |
|---|---|
| **Status** | Accepted — 2026-11-10 |
| **Decision ID** | D-016 |
| **Related** | [SYSTEM_ARCHITECTURE.md](../SYSTEM_ARCHITECTURE.md) §7.3 · [TESTING_STRATEGY.md](../TESTING_STRATEGY.md) §8 |

## Context
The UI must meet WCAG 2.1 AA (NFR-09) for keyboard-navigable graph and timeline views, colour-blind-safe
heat-maps, and screen-reader-labelled indicator cards. It must also render forensic-specific components
no library provides.

## Decision
1. Use **Radix UI primitives (MIT)** for accessible behaviour (focus trapping, keyboard handling,
   ARIA) and **Tailwind CSS 4 (MIT)** for styling.
2. **Vendor** the composed components into `frontend/src/components/ui/` (shadcn-style: copy the code
   into our tree) rather than installing a component library as a dependency.
3. Domain components (evidence viewer, waveform, graph, timeline, finding card, egress modal) live in
   `frontend/src/components/features/`.
4. Design tokens are CSS custom properties so classification banners, verification states and
   colour-blind-safe palettes are themeable and testable.
5. `dangerouslySetInnerHTML` is an ESLint **error**, with a documented exception process requiring review.

## Alternatives considered
| Option | Verdict |
|---|---|
| Ant Design / MUI | Rejected — larger bundles, weaker control over forensic-viewer a11y, and styling that fights Tailwind |
| Install shadcn/ui as a dependency | Not applicable — it is a copy-in pattern by design; installing it as a dependency would defeat the auditability benefit |
| Hand-roll all primitives | Rejected — accessibility bugs are easy to introduce and hard to test |

## Rationale
Vendoring puts the code we ship in our tree, where it is reviewable, patchable and auditable — which
matters for a forensic product that must be describable to a third party. Radix supplies the hard
accessibility work; Tailwind supplies consistent, token-driven styling.

## Consequences
**Positive:** full control; accessible by default; no upstream styling churn; small bundle; every
component is reviewable in-PR.
**Negative / accepted costs:** we own upgrades and patches to vendored code; more initial setup than
installing a library; requires discipline to keep `components/ui` generic and `components/features`
domain-specific.

## Licensing implications
Radix MIT, Tailwind MIT, Cytoscape MIT, WaveSurfer BSD-3, TanStack MIT — **zero copyleft** in the
frontend tree (THIRD_PARTY_LICENSE_AUDIT §1.3), enforced by the CI licence gate. Vendored code
retains upstream attribution headers.

## Security implications
Strict CSP with no `unsafe-inline`; `dangerouslySetInnerHTML` banned by lint; derived forensic images
served with `Content-Disposition: attachment` where they could be interpreted as markup; **SVG
rendering disabled** (an XSS vector) — forensic overlays are raster or canvas. The egress-confirmation
modal (ADR-0007) is a server-enforced control, so a UI bypass cannot cause transmission.

## Reversal strategy
Components are in-tree; replacing a primitive means editing our own file. Reversal to a library-based
approach would be a refactor of `components/ui` only — `components/features` consumes our own API.

## Verification
- `@axe-core/playwright` runs on every journey screen; WCAG 2.1 AA violations fail CI.
- Keyboard-only completion of journey J3 is an explicit E2E spec.
- ESLint rule test: a file using `dangerouslySetInnerHTML` fails lint.
- Contrast tests on heat-map palettes for deuteranopia/protanopia simulation.
