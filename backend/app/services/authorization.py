"""Case authorization choke point for M4."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenCaseAccessError, ForbiddenRoleError, NotFoundError
from app.models.cases import Case, CaseMember
from app.models.identity import Permission, Role, RolePermission, User
from app.repositories.audit import append_audit
from app.repositories.cases import get_case, get_membership


@dataclass(frozen=True)
class CaseAccess:
    case: Case
    member: CaseMember


def _global_capability_allowed(session: Session, user: User, capability: str) -> bool:
    stmt = (
        select(RolePermission.permission_id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(Role.code == user.global_role, Permission.code == capability)
        .limit(1)
    )
    return session.scalar(stmt) is not None


def _active_membership(member: CaseMember, now: datetime) -> bool:
    return (
        member.revoked_at is None
        and (member.valid_from is None or member.valid_from <= now)
        and (member.valid_until is None or member.valid_until > now)
    )


def authorize_case_access(
    session: Session,
    *,
    user: User,
    case_id: UUID,
    capability: str,
) -> CaseAccess:
    case = get_case(session, case_id)
    if case is None:
        raise NotFoundError()

    member = get_membership(session, case_id=case_id, user_id=user.id)
    if member is None or not _active_membership(member, datetime.now(UTC)):
        append_audit(
            session,
            action="case.access.denied",
            result="denied",
            actor_id=user.id,
            actor_role=user.global_role.value,
            reason="FORBIDDEN_CASE_ACCESS",
            resource_type="case",
            resource_id=case_id,
            metadata={"capability": capability},
        )
        session.commit()
        raise ForbiddenCaseAccessError()

    if not _global_capability_allowed(session, user, capability):
        append_audit(
            session,
            action="case.access.denied",
            result="denied",
            actor_id=user.id,
            actor_role=user.global_role.value,
            reason="FORBIDDEN_ROLE",
            resource_type="case",
            resource_id=case_id,
            metadata={"capability": capability},
        )
        session.commit()
        raise ForbiddenRoleError()

    return CaseAccess(case=case, member=member)
