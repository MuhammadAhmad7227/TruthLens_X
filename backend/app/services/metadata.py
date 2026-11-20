"""M8 metadata extraction orchestration and persistence."""
from __future__ import annotations

from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import NotFoundError, ValidationError
from app.core.storage import resolve_within_root
from app.forensics.metadata import MetadataExtractor
from app.models.analysis import AnalysisJob
from app.models.evidence import EvidenceItem
from app.models.identity import User
from app.models.location import Location
from app.models.metadata import MetadataRecord
from app.services.authorization import authorize_case_access


def _evidence(session: Session, evidence_id: UUID) -> EvidenceItem:
    item = session.scalar(select(EvidenceItem).where(EvidenceItem.id == evidence_id))
    if item is None:
        raise NotFoundError()
    return item


def _source_path(settings: Settings, item: EvidenceItem) -> Path:
    return resolve_within_root(settings.evidence_root, item.physical_object.storage_path)


def extract_for_job(
    session: Session,
    *,
    settings: Settings,
    job: AnalysisJob,
) -> MetadataRecord:
    if job.evidence_id is None:
        raise ValidationError("Metadata extraction requires an evidence_id")
    item = _evidence(session, job.evidence_id)
    if item.case_id != job.case_id:
        raise ValidationError("Evidence does not belong to the job case")

    source = _source_path(settings, item)
    result = MetadataExtractor(settings).extract(source, item.physical_object.detected_mime)

    existing = session.scalar(
        select(MetadataRecord)
        .where(
            MetadataRecord.evidence_id == item.id,
            MetadataRecord.extractor == result.extractor,
            MetadataRecord.extractor_version == result.extractor_version,
        )
        .order_by(MetadataRecord.extracted_at.desc())
    )
    if existing is not None:
        existing.raw_tags = result.raw_tags
        existing.normalised = result.normalised
        existing.invocation_args = result.invocation_args
        existing.stripping_signals = result.stripping_signals
        existing.source_sha256 = item.physical_object.sha256
        existing.extraction_job_id = job.id
        session.commit()
        session.refresh(existing)
        return existing

    record = MetadataRecord(
        evidence_id=item.id,
        extractor=result.extractor,
        extractor_version=result.extractor_version,
        invocation_args=result.invocation_args,
        raw_tags=result.raw_tags,
        normalised=result.normalised,
        extraction_job_id=job.id,
        stripping_signals=result.stripping_signals,
        source_sha256=item.physical_object.sha256,
    )
    session.add(record)

    location = result.normalised.get("location")
    if isinstance(location, dict):
        latitude = location.get("latitude")
        longitude = location.get("longitude")
        if isinstance(latitude, (int, float)) and isinstance(longitude, (int, float)):
            session.add(
                Location(
                    evidence_id=item.id,
                    latitude=latitude,
                    longitude=longitude,
                    altitude_m=location.get("altitude_m"),
                    uncertainty_m=location.get("uncertainty_radius_m"),
                    precision_digits=location.get("precision_digits"),
                    source=str(location.get("source") or "exif_gps"),
                )
            )

    session.commit()
    session.refresh(record)
    return record


def list_for_evidence(
    session: Session,
    *,
    actor: User,
    evidence_id: UUID,
) -> list[MetadataRecord]:
    item = _evidence(session, evidence_id)
    authorize_case_access(
        session, user=actor, case_id=item.case_id, capability="view_evidence"
    )
    return list(
        session.scalars(
            select(MetadataRecord)
            .where(MetadataRecord.evidence_id == evidence_id)
            .order_by(MetadataRecord.extracted_at.desc())
        )
    )


def get_latest(
    session: Session,
    *,
    actor: User,
    evidence_id: UUID,
) -> MetadataRecord:
    records = list_for_evidence(session, actor=actor, evidence_id=evidence_id)
    if not records:
        raise NotFoundError()
    return records[0]


def assert_case_access(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    evidence_id: UUID,
    capability: str = "view_evidence",
) -> EvidenceItem:
    item = _evidence(session, evidence_id)
    if item.case_id != case_id:
        raise NotFoundError()
    authorize_case_access(
        session, user=actor, case_id=case_id, capability=capability
    )
    return item
