"""Engine discovery, registration and version pinning.

The registry is the only place that knows *which* engines exist. Orchestration asks it for an engine
by name and receives a result; it never imports an engine module directly (SYSTEM_ARCHITECTURE §4.1
rule 4). That indirection is what allows a GPU worker image to ship engines the API process does not
have installed, and what makes an engine swap a configuration change rather than a code change.

Everything here fails closed:

* registering two engines under one name is an error, not a last-write-wins;
* a pin naming an engine that is not registered is a violation, not a no-op;
* an entry point that fails to load is reported, never swallowed, and never takes the registry down.
"""

from __future__ import annotations

import inspect
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points
from typing import Final

from .base import Engine, EngineContext, EngineStatus

#: Distribution entry-point group engines register under. A third-party or internal engine package
#: declares ``[project.entry-points."truthlens.engines"]`` and is discovered without any change
#: here. The group name is part of the contract, so it is a constant rather than a parameter.
ENTRY_POINT_GROUP: Final = "truthlens.engines"


class RegistryError(RuntimeError):
    """Base class for registry misuse. These are programming or packaging errors, not runtime luck."""


class UnknownEngineError(RegistryError, KeyError):
    """Raised by :meth:`EngineRegistry.require` when no engine has that name."""


class DuplicateEngineError(RegistryError):
    """Raised when a name is registered twice. Overwriting an engine silently changes provenance."""


@dataclass(frozen=True, slots=True)
class PinViolation:
    """One way the installed engines disagree with the declared pins."""

    engine: str
    expected: str
    actual: str | None
    reason: str

    def __str__(self) -> str:
        return f"{self.engine}: {self.reason} (pinned {self.expected}, installed {self.actual})"


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    """What discovery found, including what it could not load.

    Loading is best-effort per entry point: one broken engine package must not make every other
    engine undiscoverable. But "best-effort" means *reported*, not ignored — ``failures`` is
    surfaced to the caller, which logs it into the audit trail and fails readiness if an engine that
    was expected is missing.
    """

    registered: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()
    #: Entry points that resolved to something that is not a usable :class:`Engine`. Kept separate
    #: from load failures because the fix is different: a packaging mistake, not a broken dependency.
    invalid: tuple[str, ...] = ()


@dataclass(slots=True)
class EngineRegistry:
    """A mutable collection of engines, keyed by name."""

    #: Engines that must be present for this deployment to be considered healthy. Set from
    #: configuration by the caller, not by the registry: which engines are mandatory depends on
    #: which capabilities are enabled.
    required_names: Sequence[str] = field(default_factory=tuple)

    _engines: dict[str, Engine] = field(default_factory=dict, init=False, repr=False)

    def __len__(self) -> int:
        return len(self._engines)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._engines

    def __iter__(self) -> Iterator[Engine]:
        return iter(self._engines.values())

    @property
    def names(self) -> tuple[str, ...]:
        """Registered engine names, in registration order."""
        return tuple(self._engines)

    def register(self, engine: Engine, *, replace: bool = False) -> None:
        """Add ``engine``.

        ``replace=True`` exists for tests and for a deliberate, logged engine upgrade. It is not the
        default because silently swapping the code that produced past findings breaks provenance.
        """
        # Bound to `object` before the isinstance check on purpose. The parameter is typed Engine, so
        # for a typed caller mypy correctly considers the guard unreachable — but plugin code is not
        # type-checked, and an entry point can hand us anything. This keeps the runtime check without
        # weakening the signature callers see.
        candidate: object = engine
        if not isinstance(candidate, Engine):
            msg = f"expected an Engine instance, got {type(candidate).__name__}"
            raise RegistryError(msg)
        if not candidate.name or not candidate.version:
            msg = "engine must declare both a name and a version before registration"
            raise RegistryError(msg)
        existing = self._engines.get(candidate.name)
        if existing is not None and not replace:
            msg = (
                f"engine {candidate.name!r} is already registered at version {existing.version!r}; "
                f"refusing to overwrite it with version {candidate.version!r}"
            )
            raise DuplicateEngineError(msg)
        self._engines[candidate.name] = candidate

    def get(self, name: str) -> Engine | None:
        """The engine called ``name``, or ``None``."""
        return self._engines.get(name)

    def require(self, name: str) -> Engine:
        """The engine called ``name``, or :class:`UnknownEngineError`.

        Use this on a path where a missing engine is a configuration defect rather than a normal
        outcome, so the error names the engine instead of surfacing later as ``None``.
        """
        engine = self._engines.get(name)
        if engine is None:
            raise UnknownEngineError(name)
        return engine

    def for_media_type(self, media_type: str, context: EngineContext) -> tuple[Engine, ...]:
        """Engines that accept ``media_type`` and report themselves available.

        Probing happens here so a caller does not dispatch work to an engine whose weights failed a
        checksum or whose feature flag is off.
        """
        selected = []
        for engine in self._engines.values():
            if not engine.supports(media_type):
                continue
            if engine.probe(context) is EngineStatus.AVAILABLE:
                selected.append(engine)
        return tuple(selected)

    def probe_all(self, context: EngineContext) -> dict[str, EngineStatus]:
        """Status of every registered engine, for the readiness probe and the admin view.

        A probe that raises is recorded as UNAVAILABLE rather than propagating: one broken engine
        must not make the whole platform report unready, and the distinction stays visible in the
        returned mapping.
        """
        statuses: dict[str, EngineStatus] = {}
        for name, engine in self._engines.items():
            try:
                statuses[name] = engine.probe(context)
            except Exception:  # a broken probe is a status, not a crash
                statuses[name] = EngineStatus.UNAVAILABLE
        return statuses

    def missing_required(self) -> tuple[str, ...]:
        """Names in :attr:`required_names` that are not registered.

        Readiness fails when this is non-empty. An absent engine is a deployment defect, and
        reporting it as "no findings" would be the exact failure mode the platform exists to avoid.
        """
        return tuple(name for name in self.required_names if name not in self._engines)

    def verify_pins(self, pins: Mapping[str, str]) -> tuple[PinViolation, ...]:
        """Compare installed engine versions against ``pins`` (name → exact version).

        Both directions are violations: a pinned engine that is missing, and an installed engine
        whose version differs from the pin. Exact matching is intentional — a forensic result has to
        be attributable to the code that produced it, so a range would permit two different engines
        to answer to the same pin.
        """
        violations: list[PinViolation] = []
        for name, expected in pins.items():
            engine = self._engines.get(name)
            if engine is None:
                violations.append(
                    PinViolation(
                        engine=name,
                        expected=expected,
                        actual=None,
                        reason="pinned engine is not registered",
                    )
                )
            elif engine.version != expected:
                violations.append(
                    PinViolation(
                        engine=name,
                        expected=expected,
                        actual=engine.version,
                        reason="installed version does not match the pin",
                    )
                )
        return tuple(violations)

    def discover(self, *, group: str = ENTRY_POINT_GROUP) -> DiscoveryReport:
        """Load engines declared by installed distributions under ``group``.

        Returns a report rather than raising: discovery runs at worker start-up, when the useful
        outcome is "these engines loaded, these did not, here is why".
        """
        registered: list[str] = []
        failures: list[str] = []
        invalid: list[str] = []

        for entry_point in _entry_points_for(group):
            label = f"{entry_point.name}={entry_point.value}"
            try:
                loaded = entry_point.load()
                # Construction sits inside the same guard as loading. A plugin whose ``__init__``
                # raises — a missing native library, an unreadable config file — must be reported as
                # a failure, and must not take the rest of discovery down with it.
                engine = _coerce_to_engine(loaded)
            except Exception as exc:  # one broken package must not stop discovery
                failures.append(f"{label}: {exc!r}")
                continue

            if engine is None:
                invalid.append(label)
                continue
            try:
                self.register(engine)
            except RegistryError as exc:
                failures.append(f"{label}: {exc}")
                continue
            registered.append(engine.name)

        return DiscoveryReport(
            registered=tuple(registered), failures=tuple(failures), invalid=tuple(invalid)
        )


def _entry_points_for(group: str) -> tuple[EntryPoint, ...]:
    """Entry points in ``group``, isolated so the packaging API does not leak through discovery.

    ``importlib.metadata.entry_points`` has accepted the ``group`` keyword since Python 3.10, which
    this project requires; the call is still isolated because it is the one place where a
    packaging-API change would otherwise ripple through the whole registry.
    """
    return tuple(entry_points(group=group))


def _coerce_to_engine(loaded: object) -> Engine | None:
    """Accept an instance, or a class that can be constructed with no arguments.

    Both forms appear in the wild. ``None`` means "this entry point is not a usable engine, and that
    is a packaging mistake rather than a runtime failure" — a class whose constructor needs arguments
    nobody supplied, or an object that is not an engine at all. Constructing it with fabricated
    arguments would produce an engine whose configuration nobody chose.

    Whether the constructor can be called with no arguments is decided from its signature, not by
    catching ``TypeError``. Guessing from the exception would misreport a plugin that raises
    ``TypeError`` for an unrelated reason as a packaging mistake, and would hide the real error.
    """
    if isinstance(loaded, Engine):
        return loaded
    if isinstance(loaded, type) and issubclass(loaded, Engine):
        if not _constructible_without_arguments(loaded):
            return None
        # Any exception from here propagates to discover(), which records it as a failure.
        return loaded()
    return None


def _constructible_without_arguments(engine_class: type[Engine]) -> bool:
    """Whether ``engine_class()`` is a legal call, judged from the signature.

    ``inspect.signature`` on a class reports ``__init__`` without ``self``, so "every parameter has a
    default, or is *args/**kwargs" is exactly the condition. A class whose signature cannot be
    introspected (some C-implemented callables) is treated as not constructible, which reports it as
    invalid rather than attempting a call that cannot be reasoned about.
    """
    try:
        signature = inspect.signature(engine_class)
    except (TypeError, ValueError):
        return False
    return all(
        parameter.default is not inspect.Parameter.empty
        or parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        for parameter in signature.parameters.values()
    )


__all__ = [
    "ENTRY_POINT_GROUP",
    "DiscoveryReport",
    "DuplicateEngineError",
    "EngineRegistry",
    "PinViolation",
    "RegistryError",
    "UnknownEngineError",
]
