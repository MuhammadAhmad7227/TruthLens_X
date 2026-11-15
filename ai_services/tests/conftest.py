"""Shared fixtures: engines that exercise each branch of the contract.

Every fake here is tiny and single-purpose. They exist so a test can assert what the contract does
when an engine misbehaves — raises, probes unavailable, forgets its identity, returns nothing — which
is the part of ``base.py`` that actually protects a pipeline.

Tests receive these as fixtures rather than importing the classes, so the fakes stay an
implementation detail of the suite and every test signature can be fully typed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from engines.base import Engine, EngineContext, EngineInput, EngineResult, EngineStatus


class RecordingEngine(Engine):
    """The well-behaved case: records its arguments, returns one finding."""

    name = "test.recording"
    version = "1.2.3"

    def __init__(self, *, findings: tuple[Mapping[str, Any], ...] | None = None) -> None:
        self.calls: list[tuple[EngineContext, EngineInput]] = []
        self._findings: tuple[Mapping[str, Any], ...] = (
            findings if findings is not None else ({"indicator": "present"},)
        )

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        self.calls.append((context, item))
        return EngineResult(
            engine=self.name,
            engine_version=self.version,
            status=EngineStatus.AVAILABLE,
            requires_human_verification=True,
            findings=self._findings,
        )


class RaisingEngine(RecordingEngine):
    """An engine whose analysis fails. ``execute()`` must contain this, not propagate it."""

    name = "test.raising"
    version = "0.1.0"

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        msg = "the decoder rejected this file"
        raise RuntimeError(msg)


class ProbeEngine(RecordingEngine):
    """Reports a fixed probe status, and records whether ``run`` was reached."""

    def __init__(self, status: EngineStatus, *, name: str = "test.probe") -> None:
        super().__init__()
        self.name = name
        self.status = status
        self.run_called = False

    def probe(self, context: EngineContext) -> EngineStatus:
        return self.status

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        self.run_called = True
        return super().run(context, item)


class ExplodingProbeEngine(RecordingEngine):
    """A probe that raises — e.g. it tried to stat a model file on a disconnected volume."""

    name = "test.exploding-probe"
    version = "0.1.0"

    def probe(self, context: EngineContext) -> EngineStatus:
        msg = "model directory is not mounted"
        raise OSError(msg)


class UnnamedEngine(RecordingEngine):
    """A registration defect: no name, no version."""

    name = ""
    version = ""


class IdentityLiarEngine(Engine):
    """Returns a result claiming to be a different engine, on a stale contract version."""

    name = "test.identity"
    version = "9.9.9"

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        del context, item
        return EngineResult(
            engine="some.other.engine",
            engine_version="0.0.1",
            status=EngineStatus.AVAILABLE,
            requires_human_verification=True,
            findings=({"indicator": "misattributed"},),
            contract_version="0.0.1",
        )


class ModelledEngine(RecordingEngine):
    """An engine with weights, so ``model_checksum`` has to survive the failure paths too."""

    name = "test.modelled"
    version = "2.0.0"

    def model_checksum(self) -> str | None:
        return "sha256:" + "ab" * 32


class ModelledWithBrokenProbeEngine(ModelledEngine):
    """Has weights, and a probe that fails — the checksum must still reach the result."""

    name = "test.modelled-broken-probe"
    version = "2.0.0"

    def probe(self, context: EngineContext) -> EngineStatus:
        msg = "weights directory is not mounted"
        raise OSError(msg)


class TimedEngine(RecordingEngine):
    """Reports its own timings, which ``execute()`` must leave alone."""

    name = "test.timed"
    version = "1.0.0"
    SELF_START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    SELF_DURATION_MS = 7

    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        del context, item
        return EngineResult(
            engine=self.name,
            engine_version=self.version,
            status=EngineStatus.AVAILABLE,
            requires_human_verification=True,
            findings=({"indicator": "present"},),
            started_at=self.SELF_START,
            finished_at=self.SELF_START,
            duration_ms=self.SELF_DURATION_MS,
        )


class JpegOnlyEngine(RecordingEngine):
    """Narrows ``supports()`` so registry selection can be tested."""

    name = "test.jpeg-only"
    version = "1.0.0"

    def supports(self, media_type: str) -> bool:
        return media_type == "image/jpeg"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def context() -> EngineContext:
    return EngineContext(request_id="req-0001", case_id="case-0001", deadline_seconds=30.0)


@pytest.fixture
def item(tmp_path: Path) -> EngineInput:
    path = tmp_path / "evidence.jpg"
    path.write_bytes(b"\xff\xd8\xff\xe0synthetic")
    return EngineInput(
        path=str(path),
        sha256="a" * 64,
        media_type="image/jpeg",
        size_bytes=path.stat().st_size,
    )


@pytest.fixture
def recording() -> RecordingEngine:
    return RecordingEngine()


@pytest.fixture
def empty_findings() -> RecordingEngine:
    """An engine that succeeds but finds nothing — the case the contract refuses to treat as clean."""
    return RecordingEngine(findings=())


@pytest.fixture
def raising() -> RaisingEngine:
    return RaisingEngine()


@pytest.fixture
def exploding_probe() -> ExplodingProbeEngine:
    return ExplodingProbeEngine()


@pytest.fixture
def unnamed() -> UnnamedEngine:
    return UnnamedEngine()


@pytest.fixture
def identity_liar() -> IdentityLiarEngine:
    return IdentityLiarEngine()


@pytest.fixture
def modelled() -> ModelledEngine:
    return ModelledEngine()


@pytest.fixture
def modelled_broken_probe() -> ModelledWithBrokenProbeEngine:
    return ModelledWithBrokenProbeEngine()


@pytest.fixture
def timed() -> TimedEngine:
    return TimedEngine()


@pytest.fixture
def jpeg_only() -> JpegOnlyEngine:
    return JpegOnlyEngine()


@pytest.fixture
def probe_factory() -> Callable[[EngineStatus, str], ProbeEngine]:
    """Build an engine that reports a chosen probe status under a chosen name."""

    def make(status: EngineStatus, name: str = "test.probe") -> ProbeEngine:
        return ProbeEngine(status, name=name)

    return make
