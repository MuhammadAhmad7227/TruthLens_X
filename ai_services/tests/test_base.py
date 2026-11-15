"""The engine contract: what it guarantees, and what it does when an engine breaks it.

These tests are about the guarantees, not about covering ``base.py``. Each one names the property it
defends — containment, provenance, honesty, fail-closed policy — because that is what a reviewer
needs in order to judge whether a change to the contract is safe.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from datetime import UTC
from typing import Any

import pytest

from engines.base import (
    CONTRACT_VERSION,
    MAX_LIMITATION_CHARS,
    Engine,
    EngineContext,
    EngineInput,
    EngineResult,
    EngineStatus,
)

# ── The dataclasses are records, not mutable objects ──────────────────────────


def test_engine_result_is_frozen() -> None:
    """A result cannot be edited after the fact — including its honesty flag."""
    result = EngineResult(
        engine="x",
        engine_version="1",
        status=EngineStatus.AVAILABLE,
        requires_human_verification=True,
        findings=({"a": 1},),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.requires_human_verification = False  # type: ignore[misc]


def test_context_and_input_are_frozen(context: EngineContext, item: EngineInput) -> None:
    """An engine cannot rewrite the policy it was handed, or the identity of its input."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.external_egress_allowed = True  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        item.sha256 = "b" * 64  # type: ignore[misc]


def test_requires_human_verification_has_no_default() -> None:
    """ADR-0023: an engine must state this explicitly. Omitting it is a construction error."""
    with pytest.raises(TypeError, match="requires_human_verification"):
        EngineResult(  # type: ignore[call-arg]
            engine="x",
            engine_version="1",
            status=EngineStatus.AVAILABLE,
        )


def test_option_defaults_are_not_shared_between_instances() -> None:
    """A mutable default shared across instances would leak one item's options into another."""
    first = EngineInput(path="/a", sha256="a" * 64, media_type="image/jpeg", size_bytes=1)
    second = EngineInput(path="/b", sha256="b" * 64, media_type="image/jpeg", size_bytes=1)
    assert first.options == {}
    assert second.options == {}
    assert first.options is not second.options

    one = EngineContext(request_id="r1")
    two = EngineContext(request_id="r2")
    assert one.capability_overrides == {}
    assert one.capability_overrides is not two.capability_overrides


# ── Policy fails closed ───────────────────────────────────────────────────────


def test_unlisted_capability_is_off_by_default() -> None:
    """Fail-closed: a capability nobody granted is not granted."""
    context = EngineContext(request_id="r1", capability_overrides={"export.original": True})
    assert context.capability_enabled("export.original") is True
    assert context.capability_enabled("export.redacted") is False


def test_capability_default_is_stated_by_the_caller_not_assumed() -> None:
    """An engine that is safe by default may say so, but the choice is explicit at the call site."""
    context = EngineContext(request_id="r1", capability_overrides={})
    assert context.capability_enabled("analysis.local", default=True) is True
    assert context.capability_enabled("analysis.local") is False


def test_external_egress_defaults_to_denied() -> None:
    """ADR-0012: egress is off unless the backend derived that it is on."""
    assert EngineContext(request_id="r1").external_egress_allowed is False


def test_capability_flags_are_coerced_on_read_not_on_construction() -> None:
    """A truthy non-boolean from a config layer becomes a real bool at the point of use."""
    context = EngineContext(request_id="r1", capability_overrides={"export.original": 1})  # type: ignore[dict-item]

    assert context.capability_enabled("export.original") is True
    # Construction does not rewrite what it was handed: the mapping stays a record of the input, and
    # the coercion happens where the decision is made.
    assert context.capability_overrides["export.original"] == 1


# ── execute() contains failures ───────────────────────────────────────────────


def test_a_raising_engine_becomes_an_unavailable_result(
    raising: Engine, context: EngineContext, item: EngineInput
) -> None:
    """One malformed file must not take the pipeline down, and must not be reported as clean."""
    result = raising.execute(context, item)

    assert result.status is EngineStatus.UNAVAILABLE
    assert result.findings == ()
    assert result.requires_human_verification is True
    assert raising.name in result.limitation_text()
    assert "the decoder rejected this file" in result.limitation_text()
    # A run failure is labelled as such, not as a probe failure: they have different causes.
    assert "raised" in result.limitation_text()


def test_an_unnamed_engine_is_contained_rather_than_crashing(
    unnamed: Engine, context: EngineContext, item: EngineInput
) -> None:
    """A missing name or version is a programming error; it surfaces as a result, not a crash."""
    result = unnamed.execute(context, item)

    assert result.status is EngineStatus.UNAVAILABLE
    assert "name or version" in result.limitation_text()


def test_a_raising_probe_is_contained_and_labelled(
    exploding_probe: Engine, context: EngineContext, item: EngineInput
) -> None:
    """A probe that touches the filesystem can fail; that is a status, not an exception."""
    result = exploding_probe.execute(context, item)

    assert result.status is EngineStatus.UNAVAILABLE
    assert "availability probe failed" in result.limitation_text()
    assert "model directory is not mounted" in result.limitation_text()


@pytest.mark.parametrize("status", [EngineStatus.DISABLED, EngineStatus.UNAVAILABLE])
def test_a_non_available_probe_skips_the_analysis_entirely(
    probe_factory: Callable[[EngineStatus, str], Any],
    status: EngineStatus,
    context: EngineContext,
    item: EngineInput,
) -> None:
    """Work is not dispatched to an engine that said it cannot run, and the reason stays legible.

    DISABLED means an operator or a licence gate switched it off; UNAVAILABLE means it is broken.
    Collapsing the two would make a licensing gate look like a crash.
    """
    engine = probe_factory(status, "test.gated")

    result = engine.execute(context, item)

    assert result.status is status
    assert engine.run_called is False
    assert "did not run" in result.limitation_text()
    assert status.value in result.limitation_text()


def test_the_model_checksum_survives_a_failure_path(
    modelled_broken_probe: Engine, context: EngineContext, item: EngineInput
) -> None:
    """A failed run still has to say which weights it would have used (AI_ARCHITECTURE §15)."""
    result = modelled_broken_probe.execute(context, item)

    assert result.status is EngineStatus.UNAVAILABLE
    assert result.model_checksum == "sha256:" + "ab" * 32


def test_a_successful_run_reports_its_model_checksum(
    modelled: Engine, context: EngineContext, item: EngineInput
) -> None:
    result = modelled.execute(context, item)

    assert result.status is EngineStatus.AVAILABLE
    assert result.model_checksum == "sha256:" + "ab" * 32


# ── Honesty: an empty result is not a clean result ────────────────────────────


def test_available_with_no_findings_is_downgraded(
    empty_findings: Engine, context: EngineContext, item: EngineInput
) -> None:
    """ADR-0023: "found nothing" and "could not look" must not be the same output."""
    result = empty_findings.execute(context, item)

    assert result.status is EngineStatus.UNAVAILABLE
    assert "empty result is not a clean result" in result.limitation_text()


def test_a_successful_run_keeps_its_findings_and_status(
    recording: Engine, context: EngineContext, item: EngineInput
) -> None:
    result = recording.execute(context, item)

    assert result.status is EngineStatus.AVAILABLE
    assert result.findings == ({"indicator": "present"},)
    assert result.requires_human_verification is True


# ── Provenance: a result must be attributable ─────────────────────────────────


def test_a_result_claiming_another_engine_is_corrected(
    identity_liar: Engine, context: EngineContext, item: EngineInput
) -> None:
    """Provenance lives in the result. An engine cannot attribute its output to something else."""
    result = identity_liar.execute(context, item)

    assert result.engine == identity_liar.name
    assert result.engine_version == identity_liar.version
    assert result.contract_version == CONTRACT_VERSION
    # The findings themselves are untouched: correcting provenance is not editing the analysis.
    assert result.findings == ({"indicator": "misattributed"},)


def test_an_honest_result_is_not_rewritten(
    recording: Engine, context: EngineContext, item: EngineInput
) -> None:
    """Normalisation must be a no-op when there is nothing to normalise."""
    result = recording.execute(context, item)

    assert result.engine == recording.name
    assert result.engine_version == recording.version
    assert result.contract_version == CONTRACT_VERSION


def test_execute_passes_context_and_item_through_untouched(
    recording: Any, context: EngineContext, item: EngineInput
) -> None:
    """The engine sees exactly what the orchestrator handed it — no silent defaults injected."""
    recording.execute(context, item)

    assert len(recording.calls) == 1
    seen_context, seen_item = recording.calls[0]
    assert seen_context is context
    assert seen_item is item


# ── Timing and timestamps ─────────────────────────────────────────────────────


def test_timestamps_are_aware_and_utc(
    recording: Engine, context: EngineContext, item: EngineInput
) -> None:
    """DECISIONS I-12: every stored timestamp is UTC. A naive one makes timelines ambiguous."""
    result = recording.execute(context, item)

    assert result.started_at is not None
    assert result.finished_at is not None
    assert result.started_at.tzinfo is not None
    assert result.started_at.utcoffset() == UTC.utcoffset(None)
    assert result.finished_at >= result.started_at


def test_duration_is_filled_in_and_non_negative(
    recording: Engine, context: EngineContext, item: EngineInput
) -> None:
    result = recording.execute(context, item)

    assert isinstance(result.duration_ms, int)
    assert result.duration_ms >= 0


def test_engine_supplied_timings_are_not_overwritten(
    timed: Any, context: EngineContext, item: EngineInput
) -> None:
    """An engine that measures itself more precisely keeps its own numbers."""
    result = timed.execute(context, item)

    assert result.started_at == timed.SELF_START
    assert result.finished_at == timed.SELF_START
    assert result.duration_ms == timed.SELF_DURATION_MS


# ── Engine defaults ───────────────────────────────────────────────────────────


def test_engine_is_abstract() -> None:
    """The base class cannot be registered or executed by accident."""
    with pytest.raises(TypeError, match="abstract"):
        Engine()  # type: ignore[abstract]


def test_supports_accepts_anything_unless_narrowed(recording: Engine, jpeg_only: Engine) -> None:
    assert recording.supports("application/pdf") is True
    assert jpeg_only.supports("image/jpeg") is True
    assert jpeg_only.supports("audio/wav") is False


def test_probe_defaults_to_available(recording: Engine, context: EngineContext) -> None:
    assert recording.probe(context) is EngineStatus.AVAILABLE


def test_model_checksum_defaults_to_none(recording: Engine) -> None:
    """An algorithmic engine has no weights, and must not invent a checksum."""
    assert recording.model_checksum() is None


def test_limitation_text_joins_truncates_and_skips_blanks() -> None:
    """Limitations go into reports and the audit trail, so they are bounded and readable."""
    long_text = "x" * (MAX_LIMITATION_CHARS + 100)
    result = EngineResult(
        engine="x",
        engine_version="1",
        status=EngineStatus.UNAVAILABLE,
        requires_human_verification=True,
        limitations=("first", "   ", long_text, "last"),
    )

    text = result.limitation_text()

    # Compared exactly rather than counted: the blank entry must be dropped, not rendered as an
    # empty segment, and the long entry must be cut at the bound.
    assert text.split(" | ") == ["first", long_text[:MAX_LIMITATION_CHARS], "last"]
    assert long_text not in text


def test_contract_version_is_pinned() -> None:
    """Consumers refuse results whose contract version they do not recognise, so it is explicit."""
    assert CONTRACT_VERSION == "1.0.0"


def test_engine_status_values_are_the_wire_format() -> None:
    """These strings are stored and served; changing one is a schema change, not a rename."""
    assert [status.value for status in EngineStatus] == ["available", "unavailable", "disabled"]


def test_the_limitation_bound_applies_to_every_entry() -> None:
    """Each entry is bounded separately, so several long ones cannot combine into one huge record.

    That bound is what keeps a third-party traceback out of the audit trail, so it is asserted as
    behaviour rather than as a number that a future change would have to remember to update here.
    """
    entries = ("y" * (MAX_LIMITATION_CHARS * 2), "z" * (MAX_LIMITATION_CHARS * 2))
    result = EngineResult(
        engine="x",
        engine_version="1",
        status=EngineStatus.UNAVAILABLE,
        requires_human_verification=True,
        limitations=entries,
    )

    text = result.limitation_text()

    assert len(text) <= (MAX_LIMITATION_CHARS * len(entries)) + (len(" | ") * (len(entries) - 1))
    assert "y" * (MAX_LIMITATION_CHARS + 1) not in text
