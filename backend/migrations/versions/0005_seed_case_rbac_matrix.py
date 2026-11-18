"""Seed the M4 case-management authorization matrix.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CASE_MATRIX: dict[str, tuple[str, ...]] = {
    "view_case": (
        "admin",
        "lead_investigator",
        "investigator",
        "analyst",
        "reviewer",
        "auditor",
    ),
    "edit_case": ("admin", "lead_investigator"),
    "close_case": ("admin", "lead_investigator"),
    "reopen_case": ("admin",),
    "manage_members": ("admin", "lead_investigator"),
}


def upgrade() -> None:
    bind = op.get_bind()
    for permission_code, role_codes in CASE_MATRIX.items():
        for role_code in role_codes:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO role_permissions (role_id, permission_id)
                    SELECT r.id, p.id
                    FROM roles AS r
                    CROSS JOIN permissions AS p
                    WHERE r.code = CAST(:role_code AS global_role)
                      AND p.code = :permission_code
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"role_code": role_code, "permission_code": permission_code},
            )


def downgrade() -> None:
    bind = op.get_bind()
    for permission_code, role_codes in CASE_MATRIX.items():
        for role_code in role_codes:
            bind.execute(
                sa.text(
                    """
                    DELETE FROM role_permissions
                    WHERE role_id = (
                        SELECT id FROM roles WHERE code = CAST(:role_code AS global_role)
                    )
                    AND permission_id = (
                        SELECT id FROM permissions WHERE code = :permission_code
                    )
                    """
                ),
                {"role_code": role_code, "permission_code": permission_code},
            )
