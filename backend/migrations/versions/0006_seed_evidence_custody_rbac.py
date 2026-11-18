"""Seed evidence-access and custody authorization cells for M5/M6.

Revision ID: 0006
Revises: 0005
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EVIDENCE_CUSTODY_MATRIX: dict[str, tuple[str, ...]] = {
    "upload_evidence": ("lead_investigator", "investigator", "analyst"),
    "view_evidence": (
        "admin",
        "lead_investigator",
        "investigator",
        "analyst",
        "reviewer",
        "auditor",
    ),
    "view_evidence_content": (
        "lead_investigator",
        "investigator",
        "analyst",
        "reviewer",
    ),
    "edit_evidence_metadata": ("lead_investigator", "investigator", "analyst"),
    "delete_evidence": ("lead_investigator",),
    "read_audit": ("admin", "lead_investigator", "auditor"),
    "verify_audit_chain": ("admin", "auditor"),
}


def upgrade() -> None:
    bind = op.get_bind()
    for permission_code, role_codes in EVIDENCE_CUSTODY_MATRIX.items():
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
    for permission_code, role_codes in EVIDENCE_CUSTODY_MATRIX.items():
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
