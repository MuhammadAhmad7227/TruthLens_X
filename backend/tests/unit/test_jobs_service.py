from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ValidationError
from app.models.enums import JobStatus
from app.services import jobs


class FakeSession:
    def __init__(self, existing: Any = None) -> None:
        self.existing = existing
        self.added: list[Any] = []
        self.committed = False

    def scalar(self, *args: Any, **kwargs: Any) -> Any:
        return self.existing

    def add(self, value: Any) -> None:
        self.added.append(value)

    def flush(self) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        return None


def _actor() -> Any:
    return SimpleNamespace(id=uuid4())


def test_create_job_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    existing = SimpleNamespace(
        params_hash=jobs._params_hash({"a": 1}),
        pipeline="maintenance.noop",
    )
    session = FakeSession(existing)
    monkeypatch.setattr(jobs, "authorize_case_access", lambda *args, **kwargs: None)

    found = jobs.create_job(
        cast(Session, session),
        actor=_actor(),
        case_id=uuid4(),
        pipeline="maintenance.noop",
        pipeline_version="1.0.0",
        params={"a": 1},
        queue="maintenance",
        idempotency_key=uuid4(),
    )

    assert found is cast(Any, existing)
    assert session.added == []


def test_idempotency_reuse_with_different_pipeline_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = SimpleNamespace(params_hash=jobs._params_hash({}), pipeline="maintenance.noop")
    session = FakeSession(existing)
    monkeypatch.setattr(jobs, "authorize_case_access", lambda *args, **kwargs: None)

    with pytest.raises(ConflictError):
        jobs.create_job(
            cast(Session, session),
            actor=_actor(),
            case_id=uuid4(),
            pipeline="maintenance.other",
            pipeline_version="1.0.0",
            params={},
            queue="maintenance",
            idempotency_key=uuid4(),
        )


def test_create_job_rejects_unknown_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession()
    monkeypatch.setattr(jobs, "authorize_case_access", lambda *args, **kwargs: None)

    with pytest.raises(ValidationError, match="Unsupported queue"):
        jobs.create_job(
            session,
            actor=_actor(),
            case_id=uuid4(),
            pipeline="maintenance.noop",
            pipeline_version="1.0.0",
            params={},
            queue="unknown",
        )


def test_cancel_job_changes_state(monkeypatch: pytest.MonkeyPatch) -> None:
    job = SimpleNamespace(
        status=JobStatus.QUEUED,
        finished_at=None,
        progress_message="Queued",
    )
    monkeypatch.setattr(jobs, "get_job", lambda *args, **kwargs: job)
    session = FakeSession()

    result = jobs.cancel_job(cast(Session, session), actor=_actor(), case_id=uuid4(), job_id=uuid4())

    assert result.status is JobStatus.CANCELLED
    assert session.committed
