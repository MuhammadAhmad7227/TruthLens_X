# `ai_services` — forensic engine contract and registry

Separate installable package for TruthLens X's forensic engines, per
[SYSTEM_ARCHITECTURE §4](../docs/SYSTEM_ARCHITECTURE.md). It exists so the heavy and licence-gated
dependency graph stays away from the API process, and so an engine can be tested without a database,
a queue or FastAPI.

> **Status: foundation only.** What is implemented here is the *contract* and the *registry* —
> `Engine`, `EngineContext`, `EngineInput`, `EngineResult`, `EngineStatus`, `EngineRegistry` — plus
> their tests. **No forensic engine exists yet.** There is no image, audio, video, document,
> metadata, detection, deepfake, similarity or LLM code in this package, no model weights, and
> nothing here analyses evidence. Engines arrive from M8 onwards; see the milestone table in
> [IMPLEMENTATION_ROADMAP §3](../docs/IMPLEMENTATION_ROADMAP.md).

## Layout

```
ai_services/
├── pyproject.toml        # separate distribution: truthlens-ai-services
├── README.md             # this file
├── engines/
│   ├── __init__.py       # the import surface both sides of the boundary use
│   ├── base.py           # Engine ABC + the context/input/result dataclasses
│   └── registry.py       # registration, lookup, discovery, probing, version pins
├── models/               # NOT in git, does not exist yet — weights are pinned by checksum
├── eval/                 # does not exist yet — labelled evaluation sets + scoring harness
└── tests/
```

`models/` and `eval/` are listed so the intended shape is not reinvented later. Both are created by
the milestone that needs them, and `models/` will stay outside version control: weights are pinned by
checksum in `models.lock.json` and loaded fail-closed
([AI_ARCHITECTURE §15](../docs/AI_ARCHITECTURE.md)).

## Install and test

```bash
# From the repository root. The package has no runtime dependencies.
python3 -m venv .venv-ai
.venv-ai/bin/pip install --upgrade pip setuptools wheel
.venv-ai/bin/pip install -e './ai_services[dev]'

cd ai_services
../.venv-ai/bin/python -m pytest -q                      # contract + registry tests
../.venv-ai/bin/ruff check engines tests                 # lint
../.venv-ai/bin/ruff format --check engines tests        # formatting is checked, not applied
../.venv-ai/bin/python -m mypy engines tests             # strict
```

It installs as the top-level package `engines`, mirroring how `backend/` installs as `app`, so from
inside this directory (or with the distribution installed) the import is
`from engines import Engine`. A namespaced `ai_services.engines` install was tried and hatchling
cannot do it for editable installs; the reasoning and the residual collision risk are recorded in
`pyproject.toml`.

Wiring these four commands into CI is a separate change to `.github/workflows/` and is deliberately
not part of this package.

## Writing an engine

```python
from engines import Engine, EngineContext, EngineInput, EngineResult, EngineStatus


class ExampleEngine(Engine):
    name = "example.dqt"
    version = "0.1.0"

    def supports(self, media_type: str) -> bool:
        return media_type == "image/jpeg"

    def probe(self, context: EngineContext) -> EngineStatus:
        # Report DISABLED when a flag switches this engine off, UNAVAILABLE when a dependency or a
        # model checksum is missing. Do not raise: probe_all() treats a raising probe as UNAVAILABLE.
        return EngineStatus.AVAILABLE

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        # Raise freely on failure — execute() contains it and records the reason as a limitation.
        return EngineResult(
            engine=self.name,
            engine_version=self.version,
            status=EngineStatus.AVAILABLE,
            requires_human_verification=True,
            findings=({"indicator": "double_compression", "confidence": 0.42},),
            limitations=("Quantisation tables only; no ELA corroboration.",),
            model_checksum=None,
        )
```

Orchestration calls `execute()`, never `run()` directly. `execute()` owns timing, exception
containment and identity, so an engine cannot produce a result that claims to come from a different
engine, or that omits when it ran.

### Rules that are not negotiable

1. **Never import `backend.app`.** The only coupling is this contract
   ([SYSTEM_ARCHITECTURE §4.1](../docs/SYSTEM_ARCHITECTURE.md) rule 5).
2. **Never read configuration or the environment directly.** Policy arrives through
   `EngineContext`. An engine that reads `os.environ` cannot be tested in isolation and can silently
   disagree with the API process about whether external egress is permitted
   ([ADR-0012](../docs/adr/ADR-0012-data-residency-no-egress-by-default.md),
   [ADR-0021](../docs/adr/ADR-0021-ai-egress-minimisation-no-fallback.md)).
3. **`requires_human_verification` is required and has no permissive default**
   ([ADR-0023](../docs/adr/ADR-0023-weight-free-deepfake-indicators.md)). An advisory output is never
   presented as a conclusion. A result that reports `AVAILABLE` with no findings is downgraded to
   `UNAVAILABLE` with a limitation, because "found nothing" and "could not look" are different
   claims.
4. **Do not modify the input file.** Originals live on write-once storage; derivatives go elsewhere
   ([DATABASE_DESIGN §5](../docs/DATABASE_DESIGN.md)).
5. **If it uses model weights, return their checksum** from `model_checksum()` and let the loader be
   fail-closed. A finding that cannot name the weights that produced it is not reproducible.
6. **Put what you could not check in `limitations`.** An empty list asserts nothing was missed,
   which is almost never true.

## Registering and discovering engines

```python
from engines import EngineRegistry

registry = EngineRegistry(required_names=("example.dqt",))
registry.register(ExampleEngine())

# Or let installed distributions declare themselves under the "truthlens.engines" entry-point group:
report = registry.discover()
report.registered   # engines that loaded
report.failures     # entry points that raised while loading or constructing — reported, not swallowed
report.invalid      # entry points that resolved to something that is not a usable engine

registry.missing_required()                      # readiness fails while this is non-empty
registry.for_media_type("image/jpeg", context)   # only engines that support it AND probe available
registry.probe_all(context)                      # name -> EngineStatus, for the readiness probe
registry.verify_pins({"example.dqt": "0.1.0"})   # exact-version pins; both directions are violations
```

Registration fails closed: a duplicate name raises rather than overwriting, because silently swapping
the code that produced past findings breaks provenance. `replace=True` exists for a deliberate,
logged upgrade.

## Dependencies

None at runtime, deliberately. The `media`, `ml` and `agpl` extras are documented in `pyproject.toml`
but **not declared**: a pin with no consumer puts an unaudited package into the graph that `pip-audit`
and the licence gate scan. Each extra is added by the milestone that needs it, with the licence
obligation recorded in [THIRD_PARTY_LICENSE_AUDIT](../docs/THIRD_PARTY_LICENSE_AUDIT.md). AGPL
dependencies are opt-in and never installed by default
([ADR-0001](../docs/adr/ADR-0001-permissive-default-dependency-set.md)).
