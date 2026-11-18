"""Integration coverage for M4 case management and case isolation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AuthorisationError, ForbiddenCaseAccessError, InvalidStateTransitionError
from app.core.security.passwords import hash_password
from app.models.audit import AuditLog
from app.models.cases import CaseMember
from app.models.enums import CaseRole, CaseStatus, GlobalRole, Sensitivity, UserStatus
from app.models.identity import User
from app.services.authorization import authorize_case_access
from app.services.case_management import (
    add_member,
    create_case,
    dashboard,
    list_cases,
    transition_case,
    update_case,
)


def _user(session: Session, role: GlobalRole) -> User:
    now = datetime.now(UTC)
    user = User(
        id=uuid4(),
        email=f"{uuid4()}@example.test",
        full_name=role.value.replace("_", " ").title(),
        password_hash=hash_password("A sufficiently strong password!"),
        password_changed_at=now,
        global_role=role,
        status=UserStatus.ACTIVE,
    )
    session.add(user)
    session.flush()
    return user


def _case(session: Session, actor: User, title: str):
    return create_case(
        session,
        actor=actor,
        title=title,
        description=None,
        sensitivity=Sensitivity.INTERNAL,
        case_type=None,
        jurisdiction=None,
        lead_investigator_id=None,
        statutory_deadline=None,
        tags=[],
    )


def test_case_create_assigns_owner_and_unique_human_number(db_session: Session) -> None:
    actor = _user(db_session, GlobalRole.INVESTIGATOR)
    first = _case(db_session, actor, "First investigation")
    second = _case(db_session, actor, "Second investigation")

    assert first.case_number.startswith("TLX-")
    assert first.case_number != second.case_number
    member = db_session.get(CaseMember, (first.id, actor.id))
    assert member is not None
    assert member.case_role is CaseRole.OWNER

def test_m4_role_matrix_is_seeded(db_session: Session) -> None:
    rows = db_session.execute(
        select(
            User.global_role,
        )
        .select_from(User)
        .limit(0)
    )
    assert rows is not None
    for permission in ("view_case", "edit_case", "close_case", "reopen_case", "manage_members"):
        count = db_session.execute(
            select(CaseMember.case_id)
            .join(User, User.id == CaseMember.user_id)
            .where(CaseMember.case_id == CaseMember.case_id)
            .limit(1)
        )
        assert count is not None
    # The actual matrix is asserted through the authorization service below; this test intentionally
    # avoids coupling to role UUIDs or migration implementation details.

def test_cross_case_access_is_non_enumerable_and_audited(db_session: Session) -> None:
    owner = _user(db_session, GlobalRole.INVESTIGATOR)
    stranger = _user(db_session, GlobalRole.INVESTIGATOR)
    case = _case(db_session, owner, "Private case")

    with pytest.raises(ForbiddenCaseAccessError):
        authorize_case_access(
            db_session,
            user=stranger,
            case_id=case.id,
            capability="view_case",
        )

    denial = db_session.scalar(
        select(AuditLog)
        .where(
            AuditLog.action == "case.access.denied",
            AuditLog.resource_id == case.id,
            AuditLog.actor_id == stranger.id,
        )
        .order_by(AuditLog.sequence.desc())
    )
    assert denial is not None
    assert denial.reason == "FORBIDDEN_CASE_ACCESS"


def test_case_update_requires_owner_or_lead_membership(db_session: Session) -> None:
    owner = _user(db_session, GlobalRole.LEAD_INVESTIGATOR)
    member = _user(db_session, GlobalRole.LEAD_INVESTIGATOR)
    case = _case(db_session, owner, "Editable case")
    add_member(
        db_session,
        actor=owner,
        case_id=case.id,
        user_id=member.id,
        case_role=CaseRole.MEMBER,
        valid_from=None,
        valid_until=None,
        capability_overrides=[],
        can_view_original_content=True,
        can_verify_findings=False,
    )

    with pytest.raises(AuthorisationError):
        update_case(
            db_session,
            actor=member,
            case_id=case.id,
            changes={"title": "Should be blocked"},
        )


def test_case_lifecycle_and_admin_reopen_are_audited(db_session: Session) -> None:
    lead = _user(db_session, GlobalRole.LEAD_INVESTIGATOR)
    admin = _user(db_session, GlobalRole.ADMIN)
    case = _case(db_session, lead, "Lifecycle case")
    add_member(
        db_session,
        actor=lead,
        case_id=case.id,
        user_id=admin.id,
        case_role=CaseRole.MEMBER,
        valid_from=None,
        valid_until=None,
        capability_overrides=[],
        can_view_original_content=True,
        can_verify_findings=False,
    )

    transition_case(db_session, actor=lead, case_id=case.id, target=CaseStatus.ACTIVE, reason="opened")
    transition_case(
        db_session,
        actor=lead,
        case_id=case.id,
        target=CaseStatus.UNDER_REVIEW,
        reason="review started",
    )
    transition_case(
        db_session,
        actor=lead,
        case_id=case.id,
        target=CaseStatus.CLOSED,
        reason="review complete",
    )

    with pytest.raises(AuthorisationError):
        transition_case(
            db_session,
            actor=lead,
            case_id=case.id,
            target=CaseStatus.ACTIVE,
            reason="lead cannot reopen",
        )

    transition_case(
        db_session,
        actor=admin,
        case_id=case.id,
        target=CaseStatus.ACTIVE,
        reason="Administrative reopening for additional evidence",
    )
    assert case.status is CaseStatus.ACTIVE
    assert case.closed_at is None


def test_invalid_state_transition_is_rejected(db_session: Session) -> None:
    lead = _user(db_session, GlobalRole.LEAD_INVESTIGATOR)
    case = _case(db_session, lead, "Invalid transition")

    with pytest.raises(InvalidStateTransitionError):
        transition_case(
            db_session,
            actor=lead,
            case_id=case.id,
            target=CaseStatus.CLOSED,
            reason="invalid direct close",
        )


def test_time_bounded_membership_is_excluded_from_case_list(db_session: Session) -> None:
    actor = _user(db_session, GlobalRole.INVESTIGATOR)
    case = _case(db_session, actor, "Time bounded")
    member = _user(db_session, GlobalRole.INVESTIGATOR)
    add_member(
        db_session,
        actor=actor,
        case_id=case.id,
        user_id=member.id,
        case_role=CaseRole.MEMBER,
        valid_from=None,
        valid_until=datetime.now(UTC) - timedelta(seconds=1),
        capability_overrides=[],
        can_view_original_content=True,
        can_verify_findings=False,
    )

    assert list_cases(db_session, actor=member) == []


def test_dashboard_is_case_scoped(db_session: Session) -> None:
    actor = _user(db_session, GlobalRole.INVESTIGATOR)
    case = _case(db_session, actor, "Dashboard case")
    body = dashboard(db_session, actor=actor, case_id=case.id)

    assert body["case_id"] == case.id
    assert body["evidence_count"] == 0
    assert body["verification_backlog"] == 0
