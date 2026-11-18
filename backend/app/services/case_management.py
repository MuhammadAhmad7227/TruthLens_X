# ruff: isort: skip_file
"""M4 case-management business rules."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.errors import (
    AuthorisationError,
    CaseClosedError,
    InvalidStateTransitionError,
    NotFoundError,
    ValidationError,
)
from app.models.cases import Case, CaseMember
from app.models.enums import CaseRole, CaseStatus, GlobalRole, Sensitivity, UserStatus
from app.models.identity import User
from app.repositories.cases import (
    case_counts,
    get_case,
    get_case_by_number,
    get_membership,
    get_user,
    list_accessible_cases,
    list_members,
    next_case_number,
)
from app.repositories.audit import append_audit
from app.services.authorization import authorize_case_access


_CASE_CREATORS = {
    GlobalRole.ADMIN,
    GlobalRole.LEAD_INVESTIGATOR,
    GlobalRole.INVESTIGATOR,
}

_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.DRAFT: {CaseStatus.ACTIVE},
    CaseStatus.ACTIVE: {CaseStatus.UNDER_REVIEW},
    CaseStatus.UNDER_REVIEW: {CaseStatus.CLOSED},
    CaseStatus.CLOSED: {CaseStatus.ACTIVE, CaseStatus.ARCHIVED},
    CaseStatus.ARCHIVED: set(),
}


def _require_owner_or_lead(member: CaseMember) -> None:
    if member.case_role not in {CaseRole.OWNER, CaseRole.LEAD}:
        raise AuthorisationError("Case owner or lead membership required")


def _ensure_writable(case: Case, *, actor: User, member: CaseMember) -> None:
    if case.status in {CaseStatus.CLOSED, CaseStatus.ARCHIVED}:
        if actor.global_role is not GlobalRole.ADMIN:
            raise CaseClosedError()
        return
    if member.case_role not in {CaseRole.OWNER, CaseRole.LEAD}:
        raise AuthorisationError("Case owner or lead membership required")


def _audit(
    session: Session,
    *,
    actor: User,
    action: str,
    case: Case,
    metadata: dict[str, object] | None = None,
) -> None:
    append_audit(
        session,
        action=action,
        result="allowed",
        actor_id=actor.id,
        actor_role=actor.global_role.value,
        resource_type="case",
        resource_id=case.id,
        metadata=metadata,
    )


def create_case(
    session: Session,
    *,
    actor: User,
    title: str,
    description: str | None,
    sensitivity: str | Sensitivity,
    case_type: str | None,
    jurisdiction: str | None,
    lead_investigator_id: UUID | None,
    statutory_deadline: datetime | None,
    tags: list[str],
) -> Case:
    sensitivity = Sensitivity(sensitivity)
    if actor.global_role not in _CASE_CREATORS or actor.status is not UserStatus.ACTIVE:
        raise AuthorisationError("Your role cannot create cases")
    if not title.strip():
        raise ValidationError("Case title is required")
    if lead_investigator_id is not None:
        lead = get_user(session, lead_investigator_id)
        if lead is None or lead.status is not UserStatus.ACTIVE:
            raise ValidationError("Lead investigator must be an active user")
    case = Case(
        case_number=next_case_number(session, datetime.now(UTC).year),
        title=title.strip(),
        description=description,
        sensitivity=sensitivity,
        case_type=case_type,
        jurisdiction=jurisdiction,
        lead_investigator_id=lead_investigator_id,
        statutory_deadline=statutory_deadline,
        tags=sorted(set(tags)),
        created_by=actor.id,
    )
    session.add(case)
    session.flush()
    session.add(
        CaseMember(
            case_id=case.id,
            user_id=actor.id,
            case_role=CaseRole.OWNER,
            granted_by=actor.id,
            can_view_original_content=True,
        )
    )
    if lead_investigator_id is not None and lead_investigator_id != actor.id:
        session.add(
            CaseMember(
                case_id=case.id,
                user_id=lead_investigator_id,
                case_role=CaseRole.LEAD,
                granted_by=actor.id,
                can_view_original_content=True,
            )
        )
    _audit(session, actor=actor, action="case.created", case=case, metadata={"case_number": case.case_number})
    session.commit()
    session.refresh(case)
    return case


def get_case_by_number_for_user(session: Session, *, actor: User, case_number: str) -> Case:
    case = get_case_by_number(session, case_number)
    if case is None:
        raise NotFoundError()
    authorize_case_access(session, user=actor, case_id=case.id, capability="view_case")
    return case


def list_cases(
    session: Session,
    *,
    actor: User,
    status: str | None = None,
    lead_id: UUID | None = None,
    sensitivity: str | None = None,
    tag: str | None = None,
    query: str | None = None,
) -> list[Case]:
    return list_accessible_cases(
        session,
        user_id=actor.id,
        status=status,
        lead_id=lead_id,
        sensitivity=sensitivity,
        tag=tag,
        query=query,
    )


def get_case_detail(session: Session, *, actor: User, case_id: UUID, capability: str = "view_case") -> Case:

    authorize_case_access(session, user=actor, case_id=case_id, capability=capability)
    case = get_case(session, case_id)
    if case is None:
        raise NotFoundError()
    return case


def _normalise_case_changes(session: Session, *, case_id: UUID, changes: dict[str, object]) -> dict[str, object]:
    allowed = {
        "title",
        "description",
        "sensitivity",
        "case_type",
        "jurisdiction",
        "lead_investigator_id",
        "statutory_deadline",
        "tags",
    }
    unknown = set(changes) - allowed
    if unknown:
        raise ValidationError(f"Unsupported case fields: {', '.join(sorted(unknown))}")
    if "title" in changes and changes["title"] is None:
        raise ValidationError("Case title cannot be cleared")
    if "sensitivity" in changes and changes["sensitivity"] is None:
        raise ValidationError("Case sensitivity cannot be cleared")
    if "tags" in changes:
        tags = changes["tags"]
        if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
            raise ValidationError("Case tags must be a list of strings")
        changes["tags"] = sorted(set(tags))
    if "sensitivity" in changes and changes["sensitivity"] is not None:
        changes["sensitivity"] = Sensitivity(str(changes["sensitivity"]))
    if "lead_investigator_id" in changes and changes["lead_investigator_id"] is not None:
        lead_id = changes["lead_investigator_id"]
        if not isinstance(lead_id, UUID):
            raise ValidationError("Lead investigator id must be a UUID")
        lead = get_user(session, lead_id)
        if lead is None or lead.status is not UserStatus.ACTIVE:
            raise ValidationError("Lead investigator must be an active user")
        lead_member = get_membership(session, case_id=case_id, user_id=lead.id)
        if lead_member is None or lead_member.revoked_at is not None:
            raise ValidationError("Lead investigator must be an active case member")
        lead_member.case_role = CaseRole.LEAD
    return changes


def update_case(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    changes: dict[str, object],
) -> Case:
    access = authorize_case_access(session, user=actor, case_id=case_id, capability="edit_case")
    case = access.case
    _ensure_writable(case, actor=actor, member=access.member)
    immutable = {"case_number", "id", "created_by", "created_at", "organisation_id"}
    if immutable.intersection(changes):
        raise ValidationError("Case number and ownership fields are immutable")

    changes = _normalise_case_changes(session, case_id=case_id, changes=changes)
    for key, value in changes.items():
        setattr(case, key, value)
    if "lead_investigator_id" in changes:
        case.lead_investigator_id = changes["lead_investigator_id"]  # type: ignore[assignment]
    _audit(
        session,
        actor=actor,
        action="case.updated",
        case=case,
        metadata={"fields": sorted(changes)},
    )
    session.commit()
    session.refresh(case)
    return case


def transition_case(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    target: str | CaseStatus,
    reason: str | None,
) -> Case:

    target = CaseStatus(target)
    capability = "reopen_case" if actor.global_role is GlobalRole.ADMIN and target is CaseStatus.ACTIVE else "close_case"
    access = authorize_case_access(session, user=actor, case_id=case_id, capability=capability)
    case = access.case
    current = case.status
    if target not in _TRANSITIONS[current]:
        raise InvalidStateTransitionError(f"{current.value} cannot transition to {target.value}")
    if current is CaseStatus.CLOSED and target is CaseStatus.ACTIVE:
        if actor.global_role is not GlobalRole.ADMIN:
            raise AuthorisationError("Only an administrator may reopen a closed case")
        if not reason or not reason.strip():
            raise ValidationError("A justification is required to reopen a closed case")
    else:
        _require_owner_or_lead(access.member)
        if current is CaseStatus.CLOSED and actor.global_role is not GlobalRole.ADMIN:
            raise CaseClosedError()
        if case.status in {CaseStatus.CLOSED, CaseStatus.ARCHIVED}:
            raise CaseClosedError()
        if not reason or not reason.strip():
            raise ValidationError("A transition reason is required")
    case.status = target
    now = datetime.now(UTC)
    if target is CaseStatus.ACTIVE and case.opened_at is None:
        case.opened_at = now
    if target in {CaseStatus.CLOSED, CaseStatus.ARCHIVED}:
        case.closed_at = now if case.closed_at is None else case.closed_at
    if target is CaseStatus.ACTIVE and current is CaseStatus.CLOSED:
        case.closed_at = None
    _audit(
        session,
        actor=actor,
        action="case.transitioned",
        case=case,
        metadata={"from": current.value, "to": target.value, "reason": reason},
    )
    session.commit()
    session.refresh(case)
    return case


def list_case_members(session: Session, *, actor: User, case_id: UUID) -> list[CaseMember]:

    authorize_case_access(session, user=actor, case_id=case_id, capability="view_case")
    return list_members(session, case_id=case_id)


def add_member(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    user_id: UUID,
    case_role: str | CaseRole,
    valid_from: datetime | None,
    valid_until: datetime | None,
    capability_overrides: list[str],
    can_view_original_content: bool,
    can_verify_findings: bool,
) -> CaseMember:

    case_role = CaseRole(case_role)
    access = authorize_case_access(session, user=actor, case_id=case_id, capability="manage_members")
    case = access.case
    _require_owner_or_lead(access.member)
    if case.status in {CaseStatus.CLOSED, CaseStatus.ARCHIVED} and actor.global_role is not GlobalRole.ADMIN:
        raise CaseClosedError()
    target = get_user(session, user_id)
    if target is None or target.status is not UserStatus.ACTIVE:
        raise NotFoundError()
    if case_role is CaseRole.OWNER:
        raise ValidationError("Only the case creator may hold the owner role")
    if case_role is CaseRole.LEAD and target.global_role not in {
        GlobalRole.ADMIN,
        GlobalRole.LEAD_INVESTIGATOR,
        GlobalRole.INVESTIGATOR,
    }:
        raise ValidationError("Lead membership requires an investigator-capable global role")
    if get_membership(session, case_id=case_id, user_id=user_id) is not None:
        raise ValidationError("User is already a member of this case")
    member = CaseMember(
        case_id=case_id,
        user_id=user_id,
        case_role=case_role,
        granted_by=actor.id,
        valid_from=valid_from,
        valid_until=valid_until,
        capability_overrides=capability_overrides,
        can_view_original_content=can_view_original_content,
        can_verify_findings=can_verify_findings,
    )
    session.add(member)
    if case_role is CaseRole.LEAD:
        for existing in list_members(session, case_id=case_id):
            if existing.user_id != user_id and existing.case_role is CaseRole.LEAD and existing.revoked_at is None:
                existing.case_role = CaseRole.MEMBER
        case.lead_investigator_id = user_id
    _audit(session, actor=actor, action="case.member.added", case=case, metadata={"user_id": str(user_id), "case_role": case_role.value})
    session.commit()
    session.refresh(member)
    return member


def update_member(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    user_id: UUID,
    changes: dict[str, object],
) -> CaseMember:

    access = authorize_case_access(session, user=actor, case_id=case_id, capability="manage_members")
    case = access.case
    _require_owner_or_lead(access.member)
    member = get_membership(session, case_id=case_id, user_id=user_id)
    if member is None:
        raise NotFoundError()
    if "case_role" in changes and changes["case_role"] is not None:
        changes["case_role"] = CaseRole(str(changes["case_role"]))
    if "case_role" in changes and changes["case_role"] is CaseRole.OWNER:
        raise ValidationError("Only the case creator may hold the owner role")
    if "case_role" in changes and changes["case_role"] is CaseRole.LEAD:
        target = get_user(session, user_id)
        if target is None or target.global_role not in {
            GlobalRole.ADMIN,
            GlobalRole.LEAD_INVESTIGATOR,
            GlobalRole.INVESTIGATOR,
        }:
            raise ValidationError("Lead membership requires an investigator-capable global role")
    allowed = {
        "case_role",
        "valid_from",
        "valid_until",
        "capability_overrides",
        "can_view_original_content",
        "can_verify_findings",
    }
    unknown = set(changes) - allowed
    if unknown:
        raise ValidationError(f"Unsupported membership fields: {', '.join(sorted(unknown))}")
    for key, value in changes.items():
        setattr(member, key, value)
    if member.case_role is CaseRole.LEAD:
        for existing in list_members(session, case_id=case_id):
            if existing.user_id != user_id and existing.case_role is CaseRole.LEAD and existing.revoked_at is None:
                existing.case_role = CaseRole.MEMBER
        case.lead_investigator_id = member.user_id
    elif case.lead_investigator_id == member.user_id:
        case.lead_investigator_id = None
    _audit(session, actor=actor, action="case.member.updated", case=case, metadata={"user_id": str(user_id), "fields": sorted(changes)})
    session.commit()
    session.refresh(member)
    return member


def revoke_member(
    session: Session,
    *,
    actor: User,
    case_id: UUID,
    user_id: UUID,
) -> None:

    access = authorize_case_access(session, user=actor, case_id=case_id, capability="manage_members")
    case = access.case
    _require_owner_or_lead(access.member)
    if user_id == case.created_by:
        raise ValidationError("The case owner cannot be revoked")
    member = get_membership(session, case_id=case_id, user_id=user_id)
    if member is None or member.revoked_at is not None:
        raise NotFoundError()
    member.revoked_at = datetime.now(UTC)
    member.revoked_by = actor.id
    if case.lead_investigator_id == user_id:
        case.lead_investigator_id = None
    _audit(session, actor=actor, action="case.member.revoked", case=case, metadata={"user_id": str(user_id)})
    session.commit()


def dashboard(session: Session, *, actor: User, case_id: UUID) -> dict[str, object]:

    access = authorize_case_access(session, user=actor, case_id=case_id, capability="view_case")
    counts = case_counts(session, case_id)
    return {
        "case_id": case_id,
        "status": access.case.status.value,
        "evidence_count": counts["evidence_count"],
        "analysis_job_count": counts["analysis_job_count"],
        "finding_count": counts["finding_count"],
        "verification_backlog": counts["verification_backlog"],
        "integrity_exception_count": counts["integrity_exception_count"],
        "storage_used_bytes": access.case.storage_used_bytes,
    }
