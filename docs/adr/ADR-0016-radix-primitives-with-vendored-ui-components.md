# ADR-0016 — Radix UI primitives with vendored shadcn-style components

| | |
|---|---|
| **Status** | Accepted — ratified 2026-11-10 |
| **Decision ID** | D-016 |
| **Related** | [ADR-0001](ADR-0001-permissive-default-dependency-set.md), [MASTER_PRD §4 (WCAG 2.1 AA)](../MASTER_PRD.md) |

## Context

The frontend needs accessible dialogs, menus, tabs, selects and tooltips. Building these correctly
(focus trapping, ARIA, keyboard navigation, screen-reader semantics) is where most accessibility
defects originate. The owner's WCAG 2.1 AA requirement makes this a compliance obligation, not a
polish item.

## Decision

1. Use **Radix UI primitives** (MIT) for behaviour and accessibility; they are unstyled and
   headless, so all visual design is ours via Tailwind 4.
2. Component source is **vendored** into `frontend/src/components/ui/` in the shadcn style — copied
   into the repository, not installed as a dependency.
3. **No component-library package** (MUI, Chakra, Ant Design) is added. They bring theme systems that
   conflict with Tailwind, large bundle weight, and licence/telemetry variance.
4. Vendored components are **first-party code after copying**: we may modify them freely, and changes
   are not lost on upgrade because there is no upgrade mechanism to lose them to.
5. Additional libraries, all MIT/BSD/Apache and all verified during the audit: TanStack Query 5 and
   TanStack Table, Zustand 5, Cytoscape 3.34 for the relationship graph, WaveSurfer.js 8 for audio
   waveforms.
6. **`dangerouslySetInnerHTML` is an ESLint error**, not a warning.
7. **SVG rendering of untrusted content is disabled.** User-supplied SVG can carry script; evidence
   images are rasterised to safe formats before display.
8. The frontend uses **same-origin relative URLs only** — no absolute API host in client code.
9. Accessibility is tested with `@axe-core/playwright` in the E2E suite, not by manual review alone.

## Alternatives considered

| Option | Verdict |
|---|---|
| Install `shadcn` as a dependency | Rejected — it is a code-distribution CLI, not a runtime library; vendoring is the intended usage and makes ownership explicit. |
| MUI or Chakra | Rejected — heavier, opinionated theming that fights Tailwind 4, larger attack and licence surface. |
| Hand-build all primitives | Rejected — accessibility correctness is exactly where hand-rolling fails, and WCAG 2.1 AA is a stated requirement. |

## Rationale

Radix solves the hard, standards-bound part (behaviour and ARIA) under MIT; vendoring solves ownership
and bundle control. Together they give accessible components we fully control with zero copyleft.

## Consequences

* Security fixes in upstream Radix require a deliberate re-copy, not an automatic bump. A tracking
  issue convention is documented in `CONTRIBUTING.md`.
* The `components/ui` directory is ours to edit, which removes the usual "don't touch generated code"
  ambiguity.
* Bundle size stays small because only the primitives actually used are present.

## Licensing implications

Radix UI, TanStack, Zustand, Cytoscape and WaveSurfer.js are **MIT**; verified individually during the
licence audit with zero copyleft in the frontend graph. Vendored component source retains upstream
copyright notices in file headers as MIT requires.

## Security implications

`dangerouslySetInnerHTML` as an error closes the main React XSS vector. Disabling untrusted SVG
rendering closes a second one that is easy to overlook in a forensic tool that displays arbitrary
user-supplied media. Same-origin relative URLs prevent a misconfigured client from calling an
unintended host.

## Reversal strategy

Components are isolated in `components/ui` behind a stable prop interface, so a primitive could be
swapped without touching feature code. Reversing to a component library would be a large, unnecessary
migration and is not anticipated.

## Verification

* ESLint fails the build on any `dangerouslySetInnerHTML` occurrence.
* `@axe-core/playwright` runs on every primary view in the E2E suite; WCAG 2.1 AA violations fail CI.
* A test asserts no `<svg>` is rendered from evidence-derived content.
* CI greps the built bundle for absolute API hosts and for any `NEXT_PUBLIC_*` secret (ADR-0007).
