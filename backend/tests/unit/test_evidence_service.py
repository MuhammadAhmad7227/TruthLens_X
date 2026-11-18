# fmt: off
from __future__ import annotations

import io
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.errors import ValidationError
from app.models.enums import EvidenceStatus, EvidenceType, IntegrityStatus
from app.services import evidence


class FakeSession:
    def __init__(self) -> None:
        self.added = []

    def execute(self, *args, **kwargs):
        return None

    def add(self, value) -> None:
        self.added.append(value)

    def flush(self) -> None:
        return None

    def commit(self) -> None:
        return None

    def refresh(self, value) -> None:
        return None


def _case(case_id, quota=None):
    return SimpleNamespace(
        id=case_id,
        status=SimpleNamespace(value="draft"),
        legal_hold=True,
        storage_quota_bytes=quota,
        storage_used_bytes=0,
    )


def test_ingest_creates_case_scoped_evidence(monkeypatch, dev_settings) -> None:
    session = FakeSession()
    case_id = uuid4()
    actor = SimpleNamespace(id=uuid4(), global_role=SimpleNamespace(value="investigator"))
    case = _case(case_id)
    access = SimpleNamespace(case=case)
    monkeypatch.setattr(evidence, "_case_access", lambda *args, **kwargs: access)
    monkeypatch.setattr(evidence, "get_physical_object_by_sha256", lambda *args, **kwargs: None)
    monkeypatch.setattr(evidence, "next_evidence_number", lambda *args, **kwargs: "EXH-0001")
    monkeypatch.setattr(evidence, "append_audit", lambda *args, **kwargs: None)

    item = evidence.ingest(
        session,
        settings=dev_settings,
        actor=actor,
        case_id=case_id,
        source=io.BytesIO(b"%PDF-1.7\nhello"),
        filename="../../report.pdf",
        declared_mime="application/pdf",
        item_type=EvidenceType.DOCUMENT.value,
        tags=["a", "a", "b"],
    )

    assert item.evidence_number == "EXH-0001"
    assert item.sanitized_filename == "report.pdf"
    assert item.status is EvidenceStatus.STORED
    assert item.integrity_status is IntegrityStatus.VERIFIED
    assert item.tags == ["a", "b"]
    assert case.storage_used_bytes > 0
    assert len(session.added) == 2


def test_ingest_rejects_incompatible_magic_bytes(monkeypatch, dev_settings) -> None:
    session = FakeSession()
    case_id = uuid4()
    actor = SimpleNamespace(id=uuid4(), global_role=SimpleNamespace(value="investigator"))
    monkeypatch.setattr(evidence, "_case_access", lambda *args, **kwargs: SimpleNamespace(case=_case(case_id)))

    with pytest.raises(ValidationError, match="incompatible"):
        evidence.ingest(
            session,
            settings=dev_settings,
            actor=actor,
            case_id=case_id,
            source=io.BytesIO(b"%PDF-1.7"),
            filename="image.jpg",
            declared_mime="image/jpeg",
            item_type=EvidenceType.IMAGE.value,
        )


def test_ingest_enforces_case_quota(monkeypatch, dev_settings) -> None:
    session = FakeSession()
    case_id = uuid4()
    actor = SimpleNamespace(id=uuid4(), global_role=SimpleNamespace(value="investigator"))
    monkeypatch.setattr(
        evidence,
        "_case_access",
        lambda *args, **kwargs: SimpleNamespace(case=_case(case_id, quota=1)),
    )

    with pytest.raises(ValidationError, match="storage quota"):
        evidence.ingest(
            session,
            settings=dev_settings,
            actor=actor,
            case_id=case_id,
            source=io.BytesIO(b"%PDF-1.7\nlarge"),
            filename="x.pdf",
            declared_mime="application/pdf",
            item_type=EvidenceType.DOCUMENT.value,
        )


def test_validate_type_rejects_wrong_category() -> None:
    with pytest.raises(ValidationError, match="incompatible"):
        evidence._validate_type(EvidenceType.AUDIO.value, "image/png")


def test_validate_type_allows_other() -> None:
    evidence._validate_type(EvidenceType.OTHER.value, "application/octet-stream")


def test_prepare_download_audits_and_returns_stream(monkeypatch, dev_settings) -> None:
    session = FakeSession()
    item = SimpleNamespace(
        id=uuid4(),
        case_id=uuid4(),
        physical_object=SimpleNamespace(
            storage_path="aa/bb/digest",
            detected_mime="application/pdf",
        ),
    )
    actor = SimpleNamespace(id=uuid4(), global_role=SimpleNamespace(value="investigator"))
    monkeypatch.setattr(evidence, "get_one", lambda *args, **kwargs: item)
    monkeypatch.setattr(evidence, "append_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(evidence, "iter_object", lambda **kwargs: iter([b"data"]))

    found, stream = evidence.prepare_download(
        session,
        settings=dev_settings,
        actor=actor,
        evidence_id=item.id,
        purpose="case review",
    )

    assert found is item
    assert list(stream) == [b"data"]


# fmt: on
