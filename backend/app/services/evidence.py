# fmt: off
"""M5 evidence ingest, integrity and private-storage service."""
from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import IntegrityError as EvidenceIntegrityError, NotFoundError, ValidationError
from app.core.storage import (
    StoredUpload,
    iter_object,
    sanitise_filename,
    stream_to_quarantine,
)
from app.models.cases import Case
from app.models.enums import EvidenceStatus, EvidenceType, IntegrityStatus, SourceType
from app.models.evidence import EvidenceItem, IntegrityCheck, PhysicalObject
from app.models.identity import User
from app.repositories.audit import append_audit
from app.repositories.evidence import (
    get_evidence,
    get_physical_object_by_sha256,
    list_evidence,
    next_evidence_number,
)
from app.services.authorization import authorize_case_access


def _case_access(session: Session, actor: User, case_id: UUID):
    return authorize_case_access(session, user=actor, case_id=case_id, capability="edit_case")


def _validate_type(item_type: str, mime: str) -> None:
    allowed = {
        "image": mime.startswith("image/"),
        "video": mime.startswith("video/"),
        "audio": mime.startswith("audio/"),
        "document": mime in {"application/pdf", "text/plain"},
        "archive": mime in {"application/zip"},
        "text": mime == "text/plain",
        "other": True,
    }
    if not allowed.get(item_type, False):
        raise ValidationError(
            f"Detected MIME {mime!r} is incompatible with evidence type {item_type!r}"
        )


def _item_response(item: EvidenceItem) -> dict[str, object]:
    obj = item.physical_object
    return {
        "id": item.id,
        "case_id": item.case_id,
        "physical_object_id": item.physical_object_id,
        "evidence_number": item.evidence_number,
        "original_filename": item.original_filename,
        "sanitized_filename": item.sanitized_filename,
        "item_type": item.item_type,
        "subcategory": item.subcategory,
        "status": item.status,
        "integrity_status": item.integrity_status,
        "source_type": item.source_type,
        "size_bytes": obj.size_bytes,
        "sha256": obj.sha256,
        "detected_mime": obj.detected_mime,
        "declared_mime": obj.declared_mime,
        "submitted_by": item.submitted_by,
        "acquired_at": item.acquired_at,
        "acquisition_method": item.acquisition_method,
        "acquisition_device": item.acquisition_device,
        "collection_location": item.collection_location,
        "notes": item.notes,
        "tags": item.tags,
        "sensitivity_override": item.sensitivity_override,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def ingest(
    session: Session,
    *,
    settings: Settings,
    actor: User,
    case_id: UUID,
    source,
    filename: str | None,
    declared_mime: str | None,
    item_type: str,
    acquisition_method: str | None = None,
    acquisition_device: str | None = None,
    collection_location: str | None = None,
    notes: str | None = None,
    tags: list[str] | None = None,
    sensitivity_override=None,
    acquired_at: datetime | None = None,
) -> EvidenceItem:
    access = _case_access(session, actor, case_id)
    case: Case = access.case
    if case.status.value in {"closed", "archived"}:
        raise ValidationError("Closed or archived cases cannot receive new evidence")
    stored: StoredUpload
    try:
        stored = stream_to_quarantine(
            source, settings=settings, declared_mime=declared_mime
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    try:
        evidence_type = EvidenceType(item_type)
    except ValueError as exc:
        raise ValidationError(f"Unsupported evidence type: {item_type!r}") from exc
    _validate_type(evidence_type.value, stored.detected_mime)
    if case.storage_quota_bytes is not None and case.storage_used_bytes + stored.size_bytes > case.storage_quota_bytes:
        _cleanup_unreferenced(settings, stored)
        raise ValidationError("Case storage quota would be exceeded")

    physical = get_physical_object_by_sha256(session, stored.sha256)
    created_physical = physical is None
    if physical is None:
        physical = PhysicalObject(
            id=uuid4(),
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            storage_backend=settings.storage_backend,
            storage_path=stored.storage_path,
            detected_mime=stored.detected_mime,
            declared_mime=stored.declared_mime,
            encryption="none",
            written_at=datetime.now(UTC),
            first_ingested_by=actor.id,
            reference_count=0,
        )
        session.add(physical)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            physical = get_physical_object_by_sha256(session, stored.sha256)
            if physical is None:
                raise
            created_physical = False

    if physical.detected_mime != stored.detected_mime:
        raise EvidenceIntegrityError("Content hash maps to an inconsistent MIME record")

    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"truthlens.evidence.number:{case_id}"},
    )
    number = next_evidence_number(session, case_id)
    item = EvidenceItem(
        case_id=case_id,
        physical_object_id=physical.id,
        evidence_number=number,
        original_filename=filename or "evidence",
        sanitized_filename=sanitise_filename(filename),
        item_type=evidence_type,
        subcategory=stored.detected_mime.split("/", 1)[-1],
        status=EvidenceStatus.STORED,
        integrity_status=IntegrityStatus.VERIFIED,
        source_type=SourceType.UPLOAD,
        submitted_by=actor.id,
        acquired_at=acquired_at,
        acquisition_method=acquisition_method,
        acquisition_device=acquisition_device,
        collection_location=collection_location,
        custody_holder_id=actor.id,
        notes=notes,
        tags=sorted(set(tags or [])),
        sensitivity_override=sensitivity_override,
    )
    physical.reference_count += 1
    case.storage_used_bytes += stored.size_bytes
    session.add(item)
    append_audit(
        session,
        action="evidence.ingested",
        result="success",
        actor_id=actor.id,
        actor_role=actor.global_role.value,
        resource_type="evidence_item",
        resource_id=item.id,
        case_id=case_id,
        metadata={"sha256": stored.sha256, "size_bytes": stored.size_bytes},
    )
    session.commit()
    session.refresh(item)
    if not created_physical:
        _cleanup_duplicate_upload(settings, stored)
    return item


def _cleanup_duplicate_upload(settings: Settings, stored: StoredUpload) -> None:
    # The content-addressed destination is already the canonical object. A duplicate upload was
    # removed by stream_to_quarantine before this function is reached.
    return None


def _cleanup_unreferenced(settings: Settings, stored: StoredUpload) -> None:
    path = settings.evidence_root / stored.storage_path
    with suppress(FileNotFoundError):
        path.unlink()


def prepare_download(
    session: Session, *, settings: Settings, actor: User, evidence_id: UUID, purpose: str
) -> tuple[EvidenceItem, object]:
    item = get_one(session, actor=actor, evidence_id=evidence_id)
    append_audit(
        session,
        action="evidence.downloaded",
        result="success",
        actor_id=actor.id,
        actor_role=actor.global_role.value,
        resource_type="evidence_item",
        resource_id=item.id,
        case_id=item.case_id,
        reason=purpose,
    )
    session.commit()
    return item, iter_object(settings=settings, storage_path=item.physical_object.storage_path)


def verify_integrity(
    session: Session, *, settings: Settings, actor: User, evidence_id: UUID
) -> IntegrityCheck:
    item = get_evidence(session, evidence_id)
    if item is None:
        raise NotFoundError()
    _case_access(session, actor, item.case_id)
    expected = item.physical_object.sha256
    digest = hashlib.sha256()
    readable = True
    try:
        for chunk in iter_object(settings=settings, storage_path=item.physical_object.storage_path):
            digest.update(chunk)
        actual = digest.hexdigest()
        result = IntegrityStatus.VERIFIED if actual == expected else IntegrityStatus.MISMATCH
    except (FileNotFoundError, OSError):
        readable = False
        actual = None
        result = IntegrityStatus.MISSING

    checked_at = datetime.now(UTC)
    check = IntegrityCheck(
        physical_object_id=item.physical_object_id,
        checked_at=checked_at,
        expected_sha256=expected,
        actual_sha256=actual,
        result=result,
    )
    session.add(check)
    item.integrity_status = result
    item.integrity_last_checked_at = checked_at
    if result is not IntegrityStatus.VERIFIED:
        item.status = EvidenceStatus.INTEGRITY_FAILED
        append_audit(
            session,
            action="evidence.integrity_failed",
            result="denied",
            actor_id=actor.id,
            actor_role=actor.global_role.value,
            reason="INTEGRITY_MISMATCH",
            resource_type="evidence_item",
            resource_id=item.id,
            case_id=item.case_id,
            metadata={"expected_sha256": expected, "actual_sha256": actual},
        )
    else:
        append_audit(
            session,
            action="evidence.integrity_verified",
            result="success",
            actor_id=actor.id,
            actor_role=actor.global_role.value,
            resource_type="evidence_item",
            resource_id=item.id,
            case_id=item.case_id,
        )
    session.commit()
    session.refresh(check)
    if not readable or result is not IntegrityStatus.VERIFIED:
        raise EvidenceIntegrityError(
            "Stored evidence failed integrity verification",
            context={"evidence_id": str(evidence_id), "expected_sha256": expected, "actual_sha256": actual},
        )
    return check


def get_one(session: Session, *, actor: User, evidence_id: UUID) -> EvidenceItem:
    item = get_evidence(session, evidence_id)
    if item is None:
        raise NotFoundError()
    _case_access(session, actor, item.case_id)
    return item


def list_for_case(
    session: Session, *, actor: User, case_id: UUID, limit: int = 100, offset: int = 0
):
    authorize_case_access(session, user=actor, case_id=case_id, capability="view_case")
    return list_evidence(session, case_id=case_id, limit=limit, offset=offset)

# fmt: on
