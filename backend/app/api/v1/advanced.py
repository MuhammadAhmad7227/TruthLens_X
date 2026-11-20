"""M9-M21 advanced forensic, intelligence, reporting and assurance endpoints."""
from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.deps import SessionDep
from app.core.errors import ForbiddenRoleError
from app.forensics.pipelines.milestone_registry import (
    PIPELINE_CATALOGUE,
    all_pipelines,
)
from app.release.verification import evaluate_release
from app.security.assurance import container_hardening_config
from app.services.admin_monitoring import alert_conditions, validate_setting
from app.services.assistant import grounded_answer
from app.services.authorization import authorize_case_access
from app.services.comparison import cosine
from app.services.graph_timeline import stable_layout
from app.services.reports import build_report_text, manifest_hash

router = APIRouter(tags=["advanced-forensics"])


class CompareRequest(BaseModel):
    left_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    right_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class VectorRequest(BaseModel):
    left: list[float]
    right: list[float]


class AssistantRequest(BaseModel):
    question: str = Field(min_length=1, max_length=10000)
    retrieved: list[dict[str, Any]] = Field(default_factory=list)


class ReportRequest(BaseModel):
    title: str
    classification: str
    sections: list[dict[str, Any]]
    watermark: str = "DRAFT"


class ReleaseRequest(BaseModel):
    gates: dict[str, bool]


@router.get("/forensics/pipelines")
def pipelines() -> dict[str, Any]:
    return {"milestones": PIPELINE_CATALOGUE, "count": len(all_pipelines())}


@router.post("/cases/{case_id}/comparisons/exact")
def exact_compare(
    case_id: UUID,
    body: CompareRequest,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> dict[str, Any]:
    authorize_case_access(
        session,
        user=principal.user,
        case_id=case_id,
        capability="create_comparison",
    )
    same = body.left_sha256 == body.right_sha256
    return {
        "method": "exact_hash",
        "band": "identical" if same else "unrelated",
        "score": 0.0 if same else 1.0,
        "interpretation": (
            "Identical SHA-256 values indicate identical bytes; different values "
            "indicate different bytes."
        ),
        "human_verification_required": True,
    }


@router.post("/cases/{case_id}/comparisons/vector")
def vector_compare(
    case_id: UUID,
    body: VectorRequest,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> dict[str, Any]:
    authorize_case_access(
        session,
        user=principal.user,
        case_id=case_id,
        capability="create_comparison",
    )
    score = cosine(body.left, body.right)
    if score >= 0.98:
        band = "very_high"
    elif score >= 0.90:
        band = "high"
    elif score >= 0.75:
        band = "moderate"
    elif score >= 0.50:
        band = "low"
    else:
        band = "unrelated"
    return {
        "method": "embedding_cosine",
        "score": score,
        "band": band,
        "human_verification_required": True,
    }


@router.post("/cases/{case_id}/assistant/answer")
def assistant_answer(
    case_id: UUID,
    body: AssistantRequest,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> dict[str, Any]:
    authorize_case_access(
        session,
        user=principal.user,
        case_id=case_id,
        capability="use_assistant",
    )
    answer = grounded_answer(
        body.question,
        [x for x in body.retrieved if x.get("case_id") == str(case_id)],
    )
    return {
        "content": answer.content,
        "citations": [c.__dict__ for c in answer.citations],
        "unsupported": answer.unsupported,
        "guardrail_version": answer.guardrail_version,
    }


@router.post("/cases/{case_id}/graph/layout")
def graph_layout(
    case_id: UUID,
    node_ids: list[UUID],
    principal: CurrentPrincipal,
    session: SessionDep,
) -> dict[str, Any]:
    authorize_case_access(
        session,
        user=principal.user,
        case_id=case_id,
        capability="view_case",
    )
    return {"seed": 0, "layout": stable_layout(node_ids, seed=0)}


@router.post("/cases/{case_id}/reports/preview")
def report_preview(
    case_id: UUID,
    body: ReportRequest,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> dict[str, Any]:
    authorize_case_access(
        session,
        user=principal.user,
        case_id=case_id,
        capability="generate_report",
    )
    manifest = {
        "case_id": str(case_id),
        "title": body.title,
        "sections": body.sections,
        "watermark": body.watermark,
    }
    return {
        "manifest": manifest,
        "manifest_hash": manifest_hash(manifest),
        "text": build_report_text(
            body.title,
            body.classification,
            body.sections,
            body.watermark,
        ),
        "human_approval_required": True,
    }


def _require_admin(principal: CurrentPrincipal) -> None:
    if principal.user.global_role.value != "admin":
        raise ForbiddenRoleError("Admin role required")


@router.post("/admin/settings/validate")
def validate_admin_setting(
    key: str,
    value: Any,
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    _require_admin(principal)
    return {"key": key, "value": validate_setting(key, value)}


@router.get("/admin/alerts")
def admin_alerts(
    failed_jobs: int = 0,
    auth_denials: int = 0,
    integrity_failures: int = 0,
    principal: CurrentPrincipal = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    if principal is None:
        raise ForbiddenRoleError("Admin role required")
    _require_admin(principal)
    return {
        "alerts": alert_conditions(
            failed_jobs=failed_jobs,
            auth_denials=auth_denials,
            integrity_failures=integrity_failures,
        )
    }


@router.get("/admin/hardening")
def hardening(principal: CurrentPrincipal) -> dict[str, Any]:
    _require_admin(principal)
    return container_hardening_config()


@router.post("/admin/release/evaluate")
def release(
    body: ReleaseRequest,
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    _require_admin(principal)
    gates = evaluate_release(body.gates)
    return {
        "ready": all(g.passed for g in gates),
        "gates": [g.__dict__ for g in gates],
    }
