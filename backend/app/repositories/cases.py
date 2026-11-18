"""Case-management persistence. Queries are always explicitly case-scoped where applicable."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.models.analysis import AnalysisJob, AnalysisResult
from app.models.cases import Case, CaseMember
from app.models.enums import VerificationStatus
from app.models.evidence import EvidenceItem, IntegrityCheck
from app.models.identity import User


def next_case_number(session: Session, year: int) -> str:
    sequence = int(session.scalar(text("SELECT nextval('case_number_seq')")) or 0)
    return f"TLX-{year:04d}-{sequence:06d}"


def get_case(session: Session, case_id: UUID) -> Case | None:
    return session.scalar(
        select(Case).where(Case.id == case_id, Case.deleted_at.is_(None))
    )


def get_case_by_number(session: Session, case_number: str) -> Case | None:
    return session.scalar(
        select(Case).where(
            Case.case_number == case_number,
            Case.deleted_at.is_(None),
        )
    )


def get_case_member_for_user(
    session: Session, *, case_id: UUID, user_id: UUID
) -> CaseMember | None:
    return get_membership(session, case_id=case_id, user_id=user_id, active_only=True)


def list_accessible_cases(
    session: Session,
    *,
    user_id: UUID,
    status: str | None = None,
    lead_id: UUID | None = None,
    sensitivity: str | None = None,
    tag: str | None = None,
    query: str | None = None,
) -> list[Case]:
    now = datetime.now(UTC)
    stmt = (
        select(Case)
        .join(CaseMember, CaseMember.case_id == Case.id)
        .where(
            Case.deleted_at.is_(None),
            CaseMember.user_id == user_id,
            CaseMember.revoked_at.is_(None),
            (CaseMember.valid_from.is_(None) | (CaseMember.valid_from <= now)),
            (CaseMember.valid_until.is_(None) | (CaseMember.valid_until > now)),
        )
        .order_by(Case.created_at.desc())
    )
    if status:
        stmt = stmt.where(Case.status == status)
    if lead_id:
        stmt = stmt.where(Case.lead_investigator_id == lead_id)
    if sensitivity:
        stmt = stmt.where(Case.sensitivity == sensitivity)
    if tag:
        stmt = stmt.where(Case.tags.any(tag))
    if query:
        stmt = stmt.where(Case.search_vector.op("@@")(func.plainto_tsquery("english", query)))
    return list(session.scalars(stmt).unique())


def get_membership(
    session: Session,
    *,
    case_id: UUID,
    user_id: UUID,
    active_only: bool = False,
) -> CaseMember | None:
    member = session.scalar(
        select(CaseMember).where(
            CaseMember.case_id == case_id,
            CaseMember.user_id == user_id,
        )
    )
    if member is None or not active_only:
        return member
    now = datetime.now(UTC)
    if (
        member.revoked_at is not None
        or (member.valid_from is not None and member.valid_from > now)
        or (member.valid_until is not None and member.valid_until <= now)
    ):
        return None
    return member


def list_members(session: Session, *, case_id: UUID) -> list[CaseMember]:
    return list(
        session.scalars(
            select(CaseMember)
            .where(CaseMember.case_id == case_id)
            .order_by(CaseMember.created_at.asc())
        )
    )


def get_user(session: Session, user_id: UUID) -> User | None:
    return session.get(User, user_id)


def case_counts(session: Session, case_id: UUID) -> dict[str, int]:
    # Evidence/analysis tables are introduced in the M2 schema; the counters are deliberately
    # computed from their case_id columns so dashboard reads cannot cross a case boundary.
    evidence = int(
        session.scalar(
            select(func.count()).select_from(EvidenceItem).where(EvidenceItem.case_id == case_id)
        )
        or 0
    )
    jobs = int(
        session.scalar(
            select(func.count()).select_from(AnalysisJob).where(AnalysisJob.case_id == case_id)
        )
        or 0
    )
    findings = int(
        session.scalar(
            select(func.count()).select_from(AnalysisResult).where(AnalysisResult.case_id == case_id)
        )
        or 0
    )
    integrity = int(
        session.scalar(
            select(func.count())
            .select_from(IntegrityCheck)
            .where(
                IntegrityCheck.case_id == case_id,
                IntegrityCheck.status.in_(("mismatch", "missing")),
            )
        )
        or 0
    )
    verification_backlog = int(
        session.scalar(
            select(func.count())
            .select_from(AnalysisResult)
            .where(
                AnalysisResult.case_id == case_id,
                AnalysisResult.requires_human_verification.is_(True),
                AnalysisResult.verification_status == VerificationStatus.UNVERIFIED,
                AnalysisResult.is_current.is_(True),
            )
        )
        or 0
    )
    return {
        "evidence_count": evidence,
        "analysis_job_count": jobs,
        "finding_count": findings,
        "integrity_exception_count": integrity,
        "verification_backlog": verification_backlog,
    }
