"""Registration, lookup, discovery, availability probing and version pinning.

The registry is the single place that decides *which* engines exist, so its failure modes are the
interesting part: a duplicate name, a pin that no longer matches, an engine that is switched off
versus one that is broken, and a plugin distribution that will not load. Every one of those has to
surface as information rather than as a silent default.
"""

from __future__ import annotations

import dataclasses
from importlib.metadata import EntryPoint
from typing import Any

import pytest

from engines import registry as registry_module
from engines.base import Engine, EngineContext, EngineInput, EngineResult, EngineStatus
from engines.registry import (
    ENTRY_POINT_GROUP,
    DiscoveryReport,
    DuplicateEngineError,
    EngineRegistry,
    RegistryError,
    UnknownEngineError,
)


def _pin(name: str, expected: str) -> dict[str, str]:
    return {name: expected}


def _one_entry_point(monkeypatch: pytest.MonkeyPatch, value: str, name: str = "plugin") -> None:
    """Point discovery at a single entry point in ``tests/fake_engine_plugin.py``.

    The trailing comma matters: ``EntryPoint`` is a tuple subclass, so a parenthesised single entry
    point would be iterated into its fields instead of being treated as one item.
    """
    monkeypatch.setattr(
        registry_module,
        "entry_points",
        lambda group: (EntryPoint(name=name, value=value, group=group),),
    )


# ── Registration and lookup ───────────────────────────────────────────────────


def test_register_then_get(recording: Engine) -> None:
    registry = EngineRegistry()
    registry.register(recording)

    assert registry.get(recording.name) is recording
    assert registry.names == (recording.name,)
    assert len(registry) == 1
    assert recording.name in registry
    assert list(registry) == [recording]


def test_get_returns_none_for_an_unknown_name() -> None:
    """Lookup that can legitimately miss returns None; `require` is the one that raises."""
    assert EngineRegistry().get("does.not.exist") is None


def test_contains_is_false_for_a_non_string() -> None:
    """`in` is used with values that come from configuration, which are not always strings."""
    assert object() not in EngineRegistry()
    assert None not in EngineRegistry()


def test_names_preserve_registration_order(recording: Engine, jpeg_only: Engine) -> None:
    """Order is what makes `for_media_type` deterministic, so it is asserted rather than assumed."""
    registry = EngineRegistry()
    registry.register(jpeg_only)
    registry.register(recording)

    assert registry.names == (jpeg_only.name, recording.name)


def test_a_duplicate_name_is_refused(recording: Engine) -> None:
    """Last-write-wins would silently change which code produced past findings."""
    registry = EngineRegistry()
    registry.register(recording)

    with pytest.raises(DuplicateEngineError, match="already registered"):
        registry.register(SameNameShim())

    # The original is still the one registered: a refused registration changes nothing.
    assert registry.get(recording.name) is recording


def test_a_duplicate_can_be_replaced_when_that_is_explicit(recording: Engine) -> None:
    """The escape hatch exists for a deliberate, logged upgrade — and only when asked for."""
    registry = EngineRegistry()
    registry.register(recording)
    replacement = SameNameShim(version="9.9.9")

    registry.register(replacement, replace=True)

    assert registry.get(recording.name) is replacement
    assert len(registry) == 1


def test_registering_something_that_is_not_an_engine_is_refused() -> None:
    """Plugin code is not type-checked, so the runtime guard is the real protection here."""
    with pytest.raises(RegistryError, match="expected an Engine instance"):
        EngineRegistry().register(object())  # type: ignore[arg-type]


def test_an_engine_without_identity_cannot_be_registered(unnamed: Engine) -> None:
    """A result whose engine name is empty cannot be attributed, so it is refused at the door."""
    with pytest.raises(RegistryError, match="name and a version"):
        EngineRegistry().register(unnamed)


def test_require_raises_naming_the_missing_engine(recording: Engine) -> None:
    registry = EngineRegistry()
    registry.register(recording)

    with pytest.raises(UnknownEngineError) as excinfo:
        registry.require("analysis.deepfake")

    assert "analysis.deepfake" in str(excinfo.value)
    # It is also a KeyError, so callers that already handle missing-key lookups keep working.
    assert isinstance(excinfo.value, KeyError)


def test_require_returns_the_registered_engine(recording: Engine) -> None:
    registry = EngineRegistry()
    registry.register(recording)

    assert registry.require(recording.name) is recording


def test_required_names_report_what_is_missing(recording: Engine) -> None:
    """Readiness fails on this, so an absent engine cannot present itself as "no findings"."""
    registry = EngineRegistry(required_names=(recording.name, "analysis.deepfake", "metadata.exif"))
    registry.register(recording)

    assert registry.missing_required() == ("analysis.deepfake", "metadata.exif")


def test_missing_required_is_empty_when_the_deployment_is_complete(recording: Engine) -> None:
    registry = EngineRegistry(required_names=(recording.name,))
    registry.register(recording)

    assert registry.missing_required() == ()


# ── Selection and probing ─────────────────────────────────────────────────────


def test_for_media_type_filters_on_support_and_availability(
    recording: Engine, jpeg_only: Engine, probe_factory: Any, context: EngineContext
) -> None:
    """An engine that cannot take this input, or cannot run at all, is not handed the work."""
    registry = EngineRegistry()
    registry.register(recording)  # supports anything, available
    registry.register(jpeg_only)  # jpeg only
    registry.register(probe_factory(EngineStatus.DISABLED, "test.off"))

    images = registry.for_media_type("image/jpeg", context)
    assert {engine.name for engine in images} == {recording.name, jpeg_only.name}

    audio = registry.for_media_type("audio/wav", context)
    assert [engine.name for engine in audio] == [recording.name]


def test_probe_all_reports_every_engine(context: EngineContext, recording: Engine) -> None:
    registry = EngineRegistry()
    registry.register(recording)
    registry.register(ExplodingProbeShim())

    statuses = registry.probe_all(context)

    assert statuses[recording.name] is EngineStatus.AVAILABLE
    # A probe that raises is a status, not a crash: one broken engine must not make the platform
    # report unready, and the difference has to stay visible in the mapping.
    assert statuses["test.exploding-probe-shim"] is EngineStatus.UNAVAILABLE


def test_probe_all_on_an_empty_registry_is_empty(context: EngineContext) -> None:
    assert EngineRegistry().probe_all(context) == {}


# ── Version pins ──────────────────────────────────────────────────────────────


def test_verify_pins_accepts_an_exact_match(recording: Engine) -> None:
    registry = EngineRegistry()
    registry.register(recording)

    assert registry.verify_pins(_pin(recording.name, recording.version)) == ()


def test_verify_pins_reports_a_version_mismatch(recording: Engine) -> None:
    """Exact matching is the point: a finding must be attributable to the code that produced it."""
    registry = EngineRegistry()
    registry.register(recording)

    violations = registry.verify_pins(_pin(recording.name, "99.0.0"))

    assert len(violations) == 1
    assert violations[0].expected == "99.0.0"
    assert violations[0].actual == recording.version
    assert "does not match the pin" in violations[0].reason


def test_verify_pins_reports_a_pinned_engine_that_is_absent() -> None:
    """A pin nobody installed is a violation, not a no-op — otherwise a missing engine is invisible."""
    violations = EngineRegistry().verify_pins(_pin("analysis.deepfake", "1.0.0"))

    assert len(violations) == 1
    assert violations[0].actual is None
    assert "not registered" in violations[0].reason


def test_verify_pins_checks_every_pin(recording: Engine) -> None:
    registry = EngineRegistry()
    registry.register(recording)

    violations = registry.verify_pins(
        {recording.name: recording.version, "analysis.deepfake": "1.0.0"}
    )

    assert [violation.engine for violation in violations] == ["analysis.deepfake"]


def test_pin_violation_renders_as_a_readable_line(recording: Engine) -> None:
    """The violation is logged and shown to operators, so its str() has to be self-explanatory."""
    registry = EngineRegistry()
    registry.register(recording)

    text = str(registry.verify_pins(_pin(recording.name, "0.0.1"))[0])

    assert recording.name in text
    assert "pinned 0.0.1" in text
    assert f"installed {recording.version}" in text


# ── Discovery ─────────────────────────────────────────────────────────────────


def test_the_entry_point_group_is_part_of_the_contract() -> None:
    """A plugin distribution declares this exact group name, so it is pinned and documented."""
    assert ENTRY_POINT_GROUP == "truthlens.engines"


def test_discovery_with_no_plugins_is_an_empty_report_not_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No engines ship yet. Discovering nothing must be normal, not a failure."""
    monkeypatch.setattr(registry_module, "entry_points", lambda group: ())

    report = EngineRegistry().discover()

    assert report == DiscoveryReport()
    assert report.registered == ()
    assert report.failures == ()
    assert report.invalid == ()


def test_discovery_loads_a_class_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercises the real ``EntryPoint.load()`` path, not a mock standing in for it."""
    _one_entry_point(monkeypatch, "fake_engine_plugin:FakePluginEngine")
    registry = EngineRegistry()

    report = registry.discover()

    assert report.registered == ("plugin.fake",)
    assert report.failures == ()
    loaded = registry.get("plugin.fake")
    assert loaded is not None
    assert loaded.version == "3.1.4"


def test_discovery_accepts_an_instance_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other plugin shape: an already-constructed engine, which must not be built again."""
    _one_entry_point(monkeypatch, "fake_engine_plugin:PLUGIN_INSTANCE")
    registry = EngineRegistry()

    report = registry.discover()

    assert report.registered == ("plugin.fake",)
    assert report.invalid == ()


def test_discovery_reports_a_plugin_that_needs_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing it with invented arguments would give an engine nobody configured."""
    _one_entry_point(monkeypatch, "fake_engine_plugin:NeedsArgsEngine")

    report = EngineRegistry().discover()

    assert report.registered == ()
    assert len(report.invalid) == 1
    assert "NeedsArgsEngine" in report.invalid[0]


def test_discovery_reports_a_plugin_that_raises_while_constructing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing native dependency is a failure to report, not a packaging mistake to shrug at."""
    _one_entry_point(monkeypatch, "fake_engine_plugin:BrokenAtConstructEngine")

    report = EngineRegistry().discover()

    assert report.registered == ()
    assert report.invalid == ()
    assert len(report.failures) == 1
    assert "libfoo" in report.failures[0]


def test_discovery_reports_an_entry_point_that_is_not_an_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _one_entry_point(monkeypatch, "fake_engine_plugin:NOT_AN_ENGINE")

    report = EngineRegistry().discover()

    assert report.registered == ()
    assert len(report.invalid) == 1


def test_discovery_reports_a_missing_attribute(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo in an entry point value is a packaging defect and must be named, not skipped."""
    _one_entry_point(monkeypatch, "fake_engine_plugin:NoSuchEngine")

    report = EngineRegistry().discover()

    assert report.registered == ()
    assert len(report.failures) == 1
    assert "NoSuchEngine" in report.failures[0]


def test_one_broken_plugin_does_not_stop_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery is best-effort per entry point — but "best-effort" means reported, never ignored."""
    monkeypatch.setattr(
        registry_module,
        "entry_points",
        lambda group: (
            EntryPoint(
                name="broken", value="fake_engine_plugin:BrokenAtConstructEngine", group=group
            ),
            EntryPoint(name="fake", value="fake_engine_plugin:FakePluginEngine", group=group),
            EntryPoint(name="junk", value="fake_engine_plugin:NOT_AN_ENGINE", group=group),
        ),
    )
    registry = EngineRegistry()

    report = registry.discover()

    assert report.registered == ("plugin.fake",)
    assert len(report.failures) == 1
    assert len(report.invalid) == 1
    assert len(registry) == 1


def test_discovering_the_same_plugin_twice_is_a_reported_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two distributions claiming one engine name is a real deployment defect."""
    same = EntryPoint(
        name="fake", value="fake_engine_plugin:FakePluginEngine", group=ENTRY_POINT_GROUP
    )
    monkeypatch.setattr(registry_module, "entry_points", lambda group: (same, same))

    report = EngineRegistry().discover()

    assert report.registered == ("plugin.fake",)
    assert len(report.failures) == 1
    assert "already registered" in report.failures[0]


def test_discovery_honours_an_explicit_group(monkeypatch: pytest.MonkeyPatch) -> None:
    """The group is a parameter so a worker can load a subset — GPU engines only, for example."""
    seen: list[str] = []

    def fake_entry_points(group: str) -> tuple[EntryPoint, ...]:
        seen.append(group)
        return ()

    monkeypatch.setattr(registry_module, "entry_points", fake_entry_points)

    EngineRegistry().discover(group="truthlens.engines.gpu")

    assert seen == ["truthlens.engines.gpu"]


def test_discovery_report_is_frozen() -> None:
    """A report records what happened at start-up; it is not edited afterwards."""
    report = DiscoveryReport(registered=("a",))

    with pytest.raises(dataclasses.FrozenInstanceError):
        report.registered = ("b",)  # type: ignore[misc]


# ── Shims used only by this module ────────────────────────────────────────────


class SameNameShim(Engine):
    """Same name as the `recording` fixture, so registration collides on purpose."""

    name = "test.recording"
    version = "0.0.1"

    def __init__(self, *, version: str | None = None) -> None:
        if version is not None:
            self.version = version

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        del context, item
        return EngineResult(
            engine=self.name,
            engine_version=self.version,
            status=EngineStatus.AVAILABLE,
            requires_human_verification=True,
            findings=({"indicator": "shim"},),
        )


class ExplodingProbeShim(Engine):
    name = "test.exploding-probe-shim"
    version = "0.0.1"

    def probe(self, context: EngineContext) -> EngineStatus:
        msg = "the model volume disappeared"
        raise OSError(msg)

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        del context, item
        raise NotImplementedError
