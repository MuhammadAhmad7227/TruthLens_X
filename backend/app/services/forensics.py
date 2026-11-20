"""Application service for M9-M18 pipeline dispatch and truthful result envelopes."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationError
from app.forensics.pipelines.core import PipelineInput, run_pipeline
from app.models.analysis import AnalysisJob, AnalysisResult
from app.models.evidence import EvidenceItem


def run_forensic_job(session: Session, *, job: AnalysisJob, source: bytes) -> AnalysisResult | None:
    if job.evidence_id is None:
        raise ValidationError("Forensic pipelines require an evidence_id")
    evidence = session.scalar(
        select(EvidenceItem).where(
            EvidenceItem.id == job.evidence_id, EvidenceItem.case_id == job.case_id
        )
    )
    if evidence is None:
        raise NotFoundError()
    output = run_pipeline(
        PipelineInput(
            pipeline=job.pipeline,
            source_sha256=evidence.physical_object.sha256,
            data=source,
            parameters=dict(job.params),
        )
    )
    result = AnalysisResult(
        job_id=job.id,
        case_id=job.case_id,
        evidence_id=job.evidence_id,
        pipeline=output.result.pipeline,
        pipeline_version=output.result.pipeline_version,
        result_kind=output.result.pipeline,
        summary=output.result.summary,
        indicators=output.result.indicators,
        limitations_code=output.result.limitations_code,
        requires_human_verification=True,
        raw_output=output.result.model_dump(mode="json"),
        raw_output_schema_version=output.result.schema_version,
    )
    session.add(result)
    session.flush()
    return result


def compare_bytes(*, left: bytes, right: bytes) -> dict[str, Any]:
    import hashlib

    left_hash, right_hash = hashlib.sha256(left).hexdigest(), hashlib.sha256(right).hexdigest()
    return {
        "method": "exact_hash",
        "score": 0.0 if left_hash == right_hash else 1.0,
        "score_unit": "hamming_digest",
        "similarity_band": "identical" if left_hash == right_hash else "unrelated",
        "interpretation": "Identical SHA-256 values indicate identical bytes; different values indicate different bytes.",
        "left_sha256": left_hash,
        "right_sha256": right_hash,
    }
