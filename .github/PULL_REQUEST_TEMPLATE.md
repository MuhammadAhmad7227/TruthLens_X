<!--
This template is deliberately blunt about one thing: what you did NOT do. TruthLens X handles
evidence that may be presented in a legal proceeding, so an unverified code path is a fact a
reviewer needs, not an omission to be discovered later. The "What was NOT done or verified"
section below is mandatory — it must be filled in, including when the honest answer is "nothing;
every path was exercised". An empty section reads as "the author did not think about it".
-->

## Summary

<!-- One or two sentences: what changes, and which problem or milestone task it closes. -->

Closes #

## Milestone and decisions

| | |
|---|---|
| Milestone | <!-- e.g. M1 — Repository foundation --> |
| ADRs touched | <!-- cite by number AND title, e.g. ADR-0008 repository-remains-unlicensed. Guessing a number is worse than leaving this blank. --> |
| Legal gates cleared | <!-- L-1 … L-11 from docs/THIRD_PARTY_LICENSE_AUDIT.md, or "none" --> |

## Definition of done

Check every box that applies. If a box does not apply, say so in the notes rather than leaving it
unchecked and unexplained.

- [ ] `pytest` passes locally, and any new behaviour has a test that would fail without the change
- [ ] `ruff check` and `ruff format --check` are clean (Ruff owns line length; `E501` is ignored by design)
- [ ] `mypy --strict` is clean — no new `# type: ignore`, and no `ignore_missing_imports` added to config
- [ ] `bandit` is clean; any `# nosec` is scoped to a specific test ID and carries a reason
- [ ] Negative control: for any new CI gate or security check, the deliberately-broken case was run
      and **did** fail. A gate that has never been seen to fire is not evidence of anything.
- [ ] `.env.example` lists every variable this change reads, **and** each one's aliases were checked.
      Pydantic Settings matches aliases case-insensitively, so an alias map that upper-cases names
      (e.g. `ENABLE_AGPL_PYMuPDF`) will silently stop matching the documented spelling.
- [ ] Every copyleft or unverified-licence flag this change adds defaults to **off** in `.env.example`
      (ADR-0001, ADR-0014, ADR-0015) — the CI gate `Copyleft and unverified-licence flags default to off` enforces this
- [ ] Licence gate: no `project.license` field and no `License ::` classifier were introduced in any
      package manifest, and **no `LICENSE` file was added** (ADR-0008 — the repository stays
      unlicensed until the owner records a decision)
- [ ] New dependencies are declared in the right place: default set only if permissive or
      file-level-copyleft; anything AGPL/SSPL/RSAL goes in the opt-in `agpl` extra behind an `ENABLE_*` flag
- [ ] `ai_services/` gained **no** third-party runtime dependency and imports nothing from `backend/`
      (SYSTEM_ARCHITECTURE §4.1 rule 5; enforced by `backend/tests/architecture/`)
- [ ] Module boundaries respected (§4.1) — `backend/tests/architecture/test_module_boundaries.py` passes
- [ ] Compose changes keep the ratified rules: only `nginx` publishes ports; any change to the
      internal network range updates `FORWARDED_ALLOW_IPS` in `api.Dockerfile` to match
- [ ] Docs updated where behaviour changed: `docs/DECISIONS.md`, the relevant ADR, `backend/README.md`
- [ ] `CHANGELOG.md` entry added — **N/A until that file exists**; it does not yet, so record notable
      changes in the PR description instead

## What was NOT done or verified

**Mandatory.** Be specific about what you did not run, what you could not test in this environment,
and what a reviewer should check by hand. Known examples worth stating honestly:

- No Docker daemon available, so `docker compose config` could not be run — compose changes are
  reviewed by reading, not validated by the tool.
- No Postgres/Redis available, so integration paths were exercised with injected fakes and probes
  report `unavailable` rather than succeeding.
- A check was run only against one distribution and not the other.

<!-- Write it here. "Nothing — all paths exercised and every gate run locally" is an acceptable
     answer, but only if it is true. -->

## Screenshots / output

<!-- For UI changes, before and after. For backend changes, paste the relevant gate output
     (pytest summary line, ruff/mypy/bandit results) rather than describing it as "passing". -->
