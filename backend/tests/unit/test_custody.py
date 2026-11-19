from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from uuid import uuid4

from sqlalchemy.orm import Session

import pytest

from app.core.errors import ValidationError
from app.models.enums import CustodyEventType
from app.models.evidence import CustodyEvent
from app.services import custody


class FakeSession:
    def __init__(self) -> None:
        self.added: list[Any] = []

    def execute(self, *args: Any, **kwargs: Any) -> None:
        return None

    def add(self, value: Any) -> None:
        self.added.append(value)


def _evidence() -> Any:
    return SimpleNamespace(
        id=uuid4(),
        case_id=uuid4(),
        physical_object=SimpleNamespace(sha256="a" * 64),
    )


def _actor() -> Any:
    return SimpleNamespace(id=uuid4(), global_role=SimpleNamespace(value="investigator"))


def test_canonical_digest_is_deterministic() -> None:
    event = SimpleNamespace(
        id=uuid4(),
        case_id=uuid4(),
        evidence_id=uuid4(),
        sequence=1,
        event_type=CustodyEventType.INGESTED,
        actor_id=uuid4(),
        system_actor=None,
        acted_at="2026-11-18T00:00:00+00:00",
        sha256_at_event="a" * 64,
        purpose="acquisition",
        ip=None,
        user_agent=None,
        request_id=None,
        recipient_id=None,
        detail={"z": 2, "a": 1},
        prev_hash="0" * 64,
        record_hash="b" * 64,
    )
    first = custody.record_digest(cast(CustodyEvent, event))
    second = custody.record_digest(cast(CustodyEvent, event))
    assert first == second
    assert len(first) == 64


def test_append_event_creates_genesis_record() -> None:
    session = FakeSession()
    evidence = _evidence()
    actor = _actor()
    event = custody.append_event(
        cast(Session, session),
        actor=actor,
        case_id=evidence.case_id,
        evidence=evidence,
        event_type=CustodyEventType.INGESTED,
        purpose="acquisition",
    )

    assert event.sequence == 1
    assert event.prev_hash == "0" * 64
    assert event.record_hash == custody.record_digest(cast(CustodyEvent, event))
    assert session.added == [event]


def test_append_event_rejects_missing_actor() -> None:
    with pytest.raises(ValidationError, match="requires"):
        custody.append_event(
            cast(Session, FakeSession()),
            actor=None,
            case_id=uuid4(),
            evidence=_evidence(),
            event_type=CustodyEventType.INGESTED,
            purpose="acquisition",
        )


def test_append_event_requires_purpose_for_download() -> None:
    with pytest.raises(ValidationError, match="purpose"):
        custody.append_event(
            cast(Session, FakeSession()),
            actor=_actor(),
            case_id=_evidence().case_id,
            evidence=_evidence(),
            event_type=CustodyEventType.DOWNLOADED,
            purpose=None,
        )


def test_append_event_rejects_cross_case_evidence() -> None:
    evidence = _evidence()
    with pytest.raises(ValidationError, match="does not belong"):
        custody.append_event(
            cast(Session, FakeSession()),
            actor=_actor(),
            case_id=uuid4(),
            evidence=evidence,
            event_type=CustodyEventType.INGESTED,
            purpose="acquisition",
        )


def test_verify_chain_detects_a_broken_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    actor = _actor()
    case_id = uuid4()
    event = SimpleNamespace(
        id=uuid4(),
        case_id=case_id,
        evidence_id=uuid4(),
        sequence=1,
        event_type=CustodyEventType.INGESTED,
        actor_id=actor.id,
        system_actor=None,
        acted_at="2026-11-18T00:00:00+00:00",
        sha256_at_event="a" * 64,
        purpose="acquisition",
        ip=None,
        user_agent=None,
        request_id=None,
        recipient_id=None,
        detail={},
        prev_hash="0" * 64,
        record_hash="f" * 64,
    )
    monkeypatch.setattr(custody, "authorize_case_access", lambda *args, **kwargs: None)
    monkeypatch.setattr(custody, "list_events", lambda *args, **kwargs: [event])
    valid, broken = custody.verify_chain(
        cast(Session, FakeSession()), actor=actor, case_id=case_id
    )
    assert not valid
    assert broken == event.id


def test_verify_chain_accepts_a_valid_record(monkeypatch: pytest.MonkeyPatch) -> None:
    actor = _actor()
    case_id = uuid4()
    event = SimpleNamespace(
        id=uuid4(),
        case_id=case_id,
        evidence_id=uuid4(),
        sequence=1,
        event_type=CustodyEventType.INGESTED,
        actor_id=actor.id,
        system_actor=None,
        acted_at="2026-11-18T00:00:00+00:00",
        sha256_at_event="a" * 64,
        purpose="acquisition",
        ip=None,
        user_agent=None,
        request_id=None,
        recipient_id=None,
        detail={},
        prev_hash="0" * 64,
        record_hash="",
    )
    event.record_hash = custody.record_digest(cast(CustodyEvent, event))
    monkeypatch.setattr(custody, "authorize_case_access", lambda *args, **kwargs: None)
    monkeypatch.setattr(custody, "list_events", lambda *args, **kwargs: [event])
    valid, broken = custody.verify_chain(
        FakeSession(), actor=actor, case_id=case_id
    )
    assert valid
    assert broken is None


# fmt: on
