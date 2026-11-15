"""The engine contract.

This module is the *only* thing the backend is allowed to know about a forensic engine, and the only
thing an engine is allowed to know about how it will be called. SYSTEM_ARCHITECTURE §4.1 rule 5
forbids ``ai_services`` from importing ``backend.app``; the coupling is this contract instead, so an
engine stays testable on its own and a worker image can be built without the API.

Two properties are deliberate and should not be "simplified" later:

1. **Nothing raises out of an engine.** :meth:`Engine.execute` converts every exception into a
   result with ``status=UNAVAILABLE`` and a recorded limitation. A forensic pipeline that crashes on
   one malformed file loses the other findings for that item; one that reports the failure keeps
   them and keeps the audit trail honest.
2. **``requires_human_verification`` has no permissive default.** ADR-0023 makes honesty a schema
   property: a result that does not say whether a human must check it is not a complete result, so
   the field is required and the dataclass is frozen. An engine cannot forget it, and a caller
   cannot mutate it away after the fact.

Only the standard library is used here on purpose. The heavy, licence-gated dependencies (Pillow,
pikepdf, ffmpeg, torch and the rest) belong to the individual engines that arrive from M8 onwards,
and are isolated in the ``media`` and ``ml`` extras — see ``pyproject.toml``.
"""

from __future__ import annotations

import abc
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

#: Version of *this contract*, not of any engine. An orchestrator refuses a result whose contract
#: version it does not recognise, which is what makes engines independently deployable.
CONTRACT_VERSION: Final = "1.0.0"

#: Upper bound on how much text an engine may put into a limitation string. Limitations are stored
#: in the audit trail and surfaced in reports; an unbounded blob from a failing library is neither.
MAX_LIMITATION_CHARS: Final = 500


class EngineStatus(StrEnum):
    """Outcome of an engine invocation, or of probing whether it can run at all."""

    #: The engine ran and produced findings. This says nothing about whether the findings are
    #: conclusive — see ``EngineResult.limitations``.
    AVAILABLE = "available"

    #: The engine could not run: a dependency is missing, a model failed its checksum, the input
    #: could not be decoded, or the engine raised. Never a silent skip.
    UNAVAILABLE = "unavailable"

    #: The engine is present and functional but switched off by configuration — an ``ENABLE_*``
    #: flag is false, or a licence obligation for its dependencies has not been accepted
    #: (ADR-0001). Distinguished from UNAVAILABLE so an operator can tell "broken" from "off".
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class EngineContext:
    """How the engine is being called. Engines must not read configuration directly.

    An engine that reads ``os.environ`` cannot be tested in isolation and can silently disagree
    with the API process about whether egress is allowed. Everything policy-shaped is passed in.
    """

    #: Correlates logs and audit entries across the API, the queue and the engine. Propagated from
    #: the request that started the work (SECURITY_ARCHITECTURE §5); never generated here.
    request_id: str

    #: The case being worked on. ``None`` for maintenance and self-test runs, which must not be
    #: able to read case evidence.
    case_id: str | None = None

    #: Wall-clock budget. ``None`` means no engine-level deadline, which is not the same as
    #: unlimited: the worker still enforces a task time limit.
    deadline_seconds: float | None = None

    #: Whether this run may contact anything outside the host. Defaults to ``False`` and must be
    #: derived from the full external-egress conjunction in the backend, never assumed here:
    #: all egress is disabled by default (ADR-0012) and there is no silent fallback to an external
    #: provider when the local one is unavailable (ADR-0021).
    external_egress_allowed: bool = False

    #: Per-case capability switches resolved by the backend's single authorisation gate. An engine
    #: consults these; it does not re-derive them.
    capability_overrides: Mapping[str, bool] = field(default_factory=dict)

    def capability_enabled(self, name: str, *, default: bool = False) -> bool:
        """Return whether a capability is on, falling back to ``default`` when it is not listed.

        Fail-closed: an unlisted capability is off unless the caller states otherwise.
        """
        return bool(self.capability_overrides.get(name, default))


@dataclass(frozen=True, slots=True)
class EngineInput:
    """The item to analyse, already validated by the ingest path."""

    #: Absolute path inside the evidence mount. Engines treat it as read-only; write-once storage is
    #: enforced below them (DATABASE_DESIGN §5), and an engine that modifies an original has broken
    #: the integrity guarantee.
    path: str

    #: SHA-256 of the bytes at ``path``, computed by ingest before the engine is called. An engine
    #: that cannot trust its own input can verify it; one that recomputes it silently accepts a
    #: substituted file.
    sha256: str

    #: Normalised media type, e.g. ``image/jpeg``, ``audio/wav``, ``application/pdf``.
    media_type: str

    size_bytes: int

    #: Engine-specific options (a DPI, a confidence floor, a language hint). Opaque here on
    #: purpose: the contract cannot anticipate every engine, and an engine must validate what it
    #: is given rather than trust it.
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EngineResult:
    """What an engine produced. Frozen: a result is a record, not a mutable object."""

    engine: str
    engine_version: str
    status: EngineStatus

    #: Whether a human must verify these findings before they are relied on. **Required, with no
    #: default.** ADR-0023: an advisory output is never presented as a conclusion, and the flag is
    #: never silently false.
    requires_human_verification: bool

    #: Machine-readable findings. Shape is defined per engine and validated by the consumer against
    #: the JSON-schema contracts in ``backend/app/forensics/contracts/`` (arrives with the
    #: orchestration milestone); this module deliberately does not constrain it.
    findings: Sequence[Mapping[str, Any]] = ()

    #: Human-readable statements of what this result does not establish. Shown next to findings in
    #: reports. Empty is a claim that nothing is missing, so engines should say what they could not
    #: check rather than return nothing.
    limitations: Sequence[str] = ()

    #: Checksum of the model weights used, when the engine uses any. ``None`` for algorithms with no
    #: learned component. A result that used a model but cannot name its checksum is not
    #: reproducible, which AI_ARCHITECTURE §15 treats as a failure.
    model_checksum: str | None = None

    #: Version of the contract this result was written against.
    contract_version: str = CONTRACT_VERSION

    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None

    def limitation_text(self) -> str:
        """Limitations joined for display, each truncated.

        Truncation happens here rather than at construction so the stored values stay verbatim, and
        the bound exists because limitation strings come from third-party libraries that can emit
        arbitrarily long tracebacks into an audit record.
        """
        parts = [str(item)[:MAX_LIMITATION_CHARS] for item in self.limitations if str(item).strip()]
        return " | ".join(parts)


def _utcnow() -> datetime:
    """Current time as an aware UTC datetime.

    ``TZ=UTC`` is enforced in every container and all stored timestamps are UTC with source offsets
    preserved (DECISIONS.md I-12); an engine that produced a naive or local timestamp would make
    cross-engine timelines ambiguous.
    """
    return datetime.now(UTC)


class Engine(abc.ABC):
    """Base class for every forensic engine.

    Subclasses implement :meth:`run` and declare :attr:`name` and :attr:`version`. Orchestration
    calls :meth:`execute`, which owns timing, exception containment and result construction — an
    engine should not reimplement that, because the guarantees above live there.
    """

    #: Stable identifier used in results, logs, the model registry and pinned-version checks. It
    #: must not change between releases of the same engine; bump :attr:`version` instead.
    name: str = ""

    #: Engine version, independent of the platform version. Recorded with every result so a finding
    #: can be tied to the code that produced it.
    version: str = ""

    @abc.abstractmethod
    def run(self, context: EngineContext, item: EngineInput) -> EngineResult:
        """Analyse ``item`` and return a result.

        Implementations may raise: :meth:`execute` contains the failure. Raising is preferred over
        returning a half-built result, because a fabricated result is worse than a reported failure.
        """

    def supports(self, media_type: str) -> bool:
        """Whether this engine handles ``media_type``. Override to narrow it.

        The default accepts anything so that an engine which is media-type agnostic (a metadata
        normaliser, say) does not have to enumerate every type; engines that care must override.
        """
        del media_type
        return True

    def model_checksum(self) -> str | None:
        """Checksum of the weights this engine would load, or ``None`` if it has no model.

        Engines with learned components override this and return the value pinned in
        ``models.lock.json``. The loader is fail-closed: a mismatch means the engine does not run
        (AI_ARCHITECTURE §15).
        """
        return None

    def probe(self, context: EngineContext) -> EngineStatus:
        """Cheap availability check, called before work is dispatched.

        The default reports AVAILABLE. Engines with dependencies, weights or gated features override
        this so an unavailable engine is discovered before an item is routed to it, instead of after
        a queue slot has been consumed.
        """
        del context
        return EngineStatus.AVAILABLE

    def execute(self, context: EngineContext, item: EngineInput) -> EngineResult:
        """Run the engine, containing every failure into a result.

        This is the only entry point orchestration should use.
        """
        started = _utcnow()
        started_mono = time.monotonic()

        if not self.name or not self.version:
            # A misconfigured engine is a programming error, and reporting it as a result keeps the
            # pipeline alive while making the defect visible in the audit trail.
            return self._failure(
                started,
                started_mono,
                "engine is missing a name or version and cannot be registered",
            )

        # Probing and running are guarded separately on purpose: "the availability probe could not
        # even complete" and "the analysis raised" are different facts, and an operator reading the
        # audit trail needs to tell a broken mount from a broken decoder.
        try:
            probe_status = self.probe(context)
        except Exception as exc:  # contained by design, recorded as a limitation
            return self._failure(started, started_mono, f"availability probe failed: {exc!r}")

        if probe_status is not EngineStatus.AVAILABLE:
            return self._skipped(started, started_mono, probe_status)

        try:
            result = self.run(context, item)
        except Exception as exc:  # contained by design, recorded as a limitation
            return self._failure(started, started_mono, f"{self.name} raised: {exc!r}")

        return self._normalise(result, started, started_mono)

    def _skipped(
        self, started: datetime, started_mono: float, status: EngineStatus
    ) -> EngineResult:
        """A result for an engine that did not run, saying so explicitly.

        DISABLED and UNAVAILABLE are kept distinct: one is an operator or licensing decision, the
        other is a defect, and collapsing them would make a gated engine look broken.
        """
        return EngineResult(
            engine=self.name,
            engine_version=self.version,
            status=status,
            requires_human_verification=True,
            limitations=(f"{self.name} did not run: probe reported {status.value}",),
            model_checksum=self.model_checksum(),
            started_at=started,
            finished_at=_utcnow(),
            duration_ms=_elapsed_ms(started_mono),
        )

    def _normalise(
        self, result: EngineResult, started: datetime, started_mono: float
    ) -> EngineResult:
        """Fill in identity and timing an engine omitted, and enforce ADR-0023's honesty floor.

        An engine may return a result with its own timings; those win. What is not trusted is the
        engine identity (a result claiming to be from another engine breaks provenance) or an
        ``AVAILABLE`` status with nothing to show for it.
        """
        replacements: dict[str, Any] = {}
        if result.engine != self.name:
            replacements["engine"] = self.name
        if result.engine_version != self.version:
            replacements["engine_version"] = self.version
        if result.contract_version != CONTRACT_VERSION:
            replacements["contract_version"] = CONTRACT_VERSION
        if result.started_at is None:
            replacements["started_at"] = started
        if result.finished_at is None:
            replacements["finished_at"] = _utcnow()
        if result.duration_ms is None:
            replacements["duration_ms"] = _elapsed_ms(started_mono)
        if result.model_checksum is None:
            declared = self.model_checksum()
            if declared is not None:
                # Fill in what the engine declared but did not report. An engine that supplies its
                # own checksum wins: it may name the weights it actually loaded, which is more
                # precise than the declaration. Without this, a successful result — the kind that
                # gets stored, cited in a report and relied on — would carry weaker provenance than
                # the skipped and failed results, which already fill it in.
                replacements["model_checksum"] = declared
        if result.status is EngineStatus.AVAILABLE and not result.findings:
            # "Available with no findings" and "found nothing" are different claims. Rather than
            # invent a finding, downgrade to UNAVAILABLE with an explicit limitation so a consumer
            # cannot read an empty result as a clean one.
            replacements["status"] = EngineStatus.UNAVAILABLE
            replacements["limitations"] = (
                *result.limitations,
                f"{self.name} produced no findings; an empty result is not a clean result",
            )
        if not replacements:
            return result
        return replace(result, **replacements)

    def _failure(self, started: datetime, started_mono: float, reason: str) -> EngineResult:
        return EngineResult(
            engine=self.name or self.__class__.__name__,
            engine_version=self.version or "0.0.0",
            status=EngineStatus.UNAVAILABLE,
            requires_human_verification=True,
            limitations=(reason[:MAX_LIMITATION_CHARS],),
            model_checksum=self.model_checksum(),
            started_at=started,
            finished_at=_utcnow(),
            duration_ms=_elapsed_ms(started_mono),
        )


def _elapsed_ms(started_mono: float) -> int:
    """Elapsed whole milliseconds since ``started_mono``.

    ``time.monotonic`` rather than a wall-clock difference: a clock step mid-analysis would
    otherwise produce a negative or absurd duration in the audit record.
    """
    return int((time.monotonic() - started_mono) * 1000)


__all__ = [
    "CONTRACT_VERSION",
    "MAX_LIMITATION_CHARS",
    "Engine",
    "EngineContext",
    "EngineInput",
    "EngineResult",
    "EngineStatus",
]
