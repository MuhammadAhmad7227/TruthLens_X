"""A stand-in for a third-party engine distribution, used only by the discovery tests.

Nothing imports this module directly. ``EngineRegistry.discover()`` reaches it through an
``importlib.metadata.EntryPoint`` and calls ``load()``, exactly as it would for a real plugin
distribution, so the failure modes tested here are the real ones: a plugin that loads, one whose
constructor needs arguments nobody supplied, one that raises while being constructed, and one whose
entry point names an attribute that does not exist.

This works because ``tests/`` has no ``__init__.py``: pytest's default prepend import mode puts this
directory on ``sys.path``, which is what makes ``fake_engine_plugin`` importable by name.
"""

from __future__ import annotations

from engines.base import Engine, EngineContext, EngineInput, EngineResult, EngineStatus


class FakePluginEngine(Engine):
    """The happy path: an installable engine that discovery can register."""

    name = "plugin.fake"
    version = "3.1.4"

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        del context, item
        return EngineResult(
            engine=self.name,
            engine_version=self.version,
            status=EngineStatus.AVAILABLE,
            requires_human_verification=True,
            findings=({"indicator": "from-plugin"},),
        )


#: An entry point that resolves to an already-constructed instance — the other shape discovery
#: accepts, alongside a class it can construct with no arguments.
PLUGIN_INSTANCE = FakePluginEngine()


class NeedsArgsEngine(Engine):
    """Cannot be constructed without arguments, so discovery must report it instead of guessing."""

    name = "plugin.needs-args"
    version = "0.1.0"

    def __init__(self, weights_path: str) -> None:
        self.weights_path = weights_path

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        del context, item
        return EngineResult(
            engine=self.name,
            engine_version=self.version,
            status=EngineStatus.AVAILABLE,
            requires_human_verification=True,
            findings=(),
        )


class BrokenAtConstructEngine(Engine):
    """Fails while being constructed — the shape of a missing native dependency."""

    name = "plugin.broken"
    version = "0.1.0"

    def __init__(self) -> None:
        msg = "native dependency libfoo is not installed"
        raise RuntimeError(msg)

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        del context, item
        raise NotImplementedError


#: An entry point that resolves to something that is not an engine at all — a packaging mistake
#: rather than a broken dependency, reported separately so the fix is obvious.
NOT_AN_ENGINE = object()
