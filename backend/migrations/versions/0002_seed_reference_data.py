"""Seed the reference data the schema depends on: the default organisation, roles, capabilities.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-15

``DATABASE_DESIGN.md`` §11 requires seed data to arrive as a **versioned data migration**, never as
an ad-hoc script: a database built by ``alembic upgrade head`` must be complete without anybody
remembering to run something else afterwards.

What is seeded here, and what deliberately is not
-------------------------------------------------
**Seeded.** The single inert ``organisations`` row that ``cases.organisation_id`` defaults to (§3.2b,
ADR-0004/ADR-0010); the six global roles of §3.1, materialised as rows so that permissions and
assignments can reference them by primary key; and the thirty canonical capability codes of
``SECURITY_ARCHITECTURE.md`` §4.2, which ``case_members.capability_overrides`` and M3's
authorization service both name.

**Not seeded: ``role_permissions`` rows.** §4.2 says the matrix is data seeded by migration, and it
will be — but populating it *is* the authorization decision, deciding which role may verify a
finding, who may hard-delete evidence, who may export. That is M3's work and this milestone is
explicitly forbidden from implementing RBAC. Seeding the vocabulary now and the matrix in M3 means
the privilege decision arrives as its own reviewed migration, which is what §4.2 asks for ("changing
a cell requires a migration + review, which makes privilege changes auditable"). An empty matrix is
also the fail-closed state: with no grants, the authorization service M3 writes denies everything
until somebody decides otherwise.

Every statement is idempotent (``ON CONFLICT DO NOTHING``), so re-running the revision — or running
it against a database where an operator already inserted the rows by hand — converges instead of
failing.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
import sqlalchemy as sa

from app.models.cases import DEFAULT_ORGANISATION_ID

#: One revision id, referenced by name so a rename cannot silently detach it from its file.
revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: §3.1's six global roles. ``code`` is the ``global_role`` enum value; ``name`` is the label a
#: report header prints.
ROLES: tuple[tuple[str, str, str], ...] = (
    (
        "admin",
        "Administrator",
        "Platform administration. Content access is NOT implicit: an administrator reaches a case's "
        "originals only as an explicit member or through break-glass (SECURITY_ARCHITECTURE §4.2 "
        "note 1), and cannot set verification status (note 3).",
    ),
    (
        "lead_investigator",
        "Lead investigator",
        "Owns cases: membership, status transitions, evidence deletion, and approving a report as "
        "FINAL. The only role that can set a verification verdict alongside reviewer.",
    ),
    (
        "investigator",
        "Investigator",
        "Works cases: uploads and analyses evidence, creates comparisons, graph edges and timeline "
        "events. Cannot manage membership or approve reports.",
    ),
    (
        "analyst",
        "Analyst",
        "Analyses evidence and generates reports. Cannot close a case, manage members, or approve a "
        "report as FINAL.",
    ),
    (
        "reviewer",
        "Reviewer",
        "Reviews work and may set verification verdicts. Metadata-only access to originals unless a "
        "case membership grants view_evidence_content (§4.2 note 2).",
    ),
    (
        "auditor",
        "Auditor",
        "Reads the audit trail and verifies the hash chain. Metadata-only by default and cannot set "
        "verification verdicts: auditing a conclusion is not the same as making one.",
    ),
)

#: The canonical capability vocabulary of SECURITY_ARCHITECTURE §4.2, transcribed verbatim. The
#: ``resource`` column groups them for an administration UI; it is a label, not an authorization
#: rule — nothing reads it to decide anything.
PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("view_case", "View case", "case"),
    ("edit_case", "Edit case metadata", "case"),
    ("close_case", "Close case", "case"),
    ("reopen_case", "Reopen case", "case"),
    ("manage_members", "Manage case membership", "case"),
    ("upload_evidence", "Upload evidence", "evidence"),
    ("view_evidence", "View evidence metadata", "evidence"),
    ("view_evidence_content", "View original evidence content", "evidence"),
    ("edit_evidence_metadata", "Edit evidence metadata", "evidence"),
    ("delete_evidence", "Soft-delete evidence", "evidence"),
    ("hard_delete_evidence", "Hard-delete evidence (second approver required)", "evidence"),
    ("analyze_evidence", "Launch analysis", "analysis"),
    ("view_finding", "View findings", "finding"),
    ("verify_finding", "Set verification verdict on a finding", "finding"),
    ("create_comparison", "Create comparison", "comparison"),
    ("create_graph_edge", "Create graph edge", "graph"),
    ("verify_graph_edge", "Verify graph edge", "graph"),
    ("create_timeline_event", "Create timeline event", "timeline"),
    ("use_assistant", "Use the AI assistant", "assistant"),
    ("export_reports", "Export reports", "report"),
    ("generate_report", "Generate report", "report"),
    ("approve_report", "Approve report as FINAL", "report"),
    ("read_audit", "Read audit log", "audit"),
    ("verify_audit_chain", "Verify the audit hash chain", "audit"),
    ("manage_users", "Manage users", "admin"),
    ("manage_models", "Manage the model registry", "admin"),
    ("manage_settings", "Manage system settings", "admin"),
    ("manage_queues", "Administrate analysis queues", "admin"),
    ("break_glass", "Break-glass access to a case (justified, time-bounded, audited)", "admin"),
    ("enable_external_ai", "Enable external AI egress", "ai"),
)


def upgrade() -> None:
    """Insert the reference rows. Idempotent."""
    bind = op.get_bind()

    # The default organisation must carry the exact identifier that cases.organisation_id defaults
    # to, so the value is imported rather than retyped: a second copy of a UUID literal is a second
    # place to get it wrong, and the failure would be every case insert in the platform.
    bind.execute(
        sa.text(
            "INSERT INTO organisations (id, name, slug, status) "
            "VALUES (CAST(:id AS uuid), :name, :slug, :status) "
            "ON CONFLICT (slug) DO NOTHING"
        ),
        {
            "id": DEFAULT_ORGANISATION_ID,
            "name": "Default organisation",
            "slug": "org_default",
            "status": "active",
        },
    )

    for code, name, description in ROLES:
        bind.execute(
            sa.text(
                "INSERT INTO roles (code, name, description, is_system) "
                "VALUES (CAST(:code AS global_role), :name, :description, true) "
                "ON CONFLICT (code) DO NOTHING"
            ),
            {"code": code, "name": name, "description": description},
        )

    for code, name, resource in PERMISSIONS:
        # `description` is left NULL rather than duplicating `name`: the label is already human
        # readable, and a column full of copies of another column is noise an administrator has to
        # read past. Longer explanations are added by the milestone that builds the admin UI.
        bind.execute(
            sa.text(
                "INSERT INTO permissions (code, name, resource, is_system) "
                "VALUES (:code, :name, :resource, true) "
                "ON CONFLICT (code) DO NOTHING"
            ),
            {"code": code, "name": name, "resource": resource},
        )


def _data_loss_permitted() -> bool:
    """The same ``-x allow_data_loss=true`` flag revision ``0001`` consults.

    Duplicated rather than imported: a revision is a snapshot of what was true when it was written,
    and importing a helper from a later revision would make this one's behaviour depend on code that
    did not exist when it ran.
    """
    value = context.get_x_argument(as_dictionary=True).get("allow_data_loss", "")
    return value.strip().lower() == "true"


def downgrade() -> None:
    """Remove the seeded reference rows — but only if nothing depends on them.

    Assignments in ``user_roles``, grants in ``role_permissions`` and cases in ``cases`` all
    reference these rows. Deleting a role a live account holds, or the organisation a case belongs
    to, either fails mid-statement with a raw foreign-key error or silently strips somebody's access,
    so the revision checks first and explains what has to happen instead. That is the difference
    between a downgrade and a surprise.

    When the operator has passed ``-x allow_data_loss=true`` — a deliberate teardown, normally on the
    way to ``base`` — the rows are left alone instead: revision ``0001`` drops the tables that hold
    them, so a full teardown removes them anyway, and no seed revision should be deleting case data
    to make its own bookkeeping tidy.
    """
    bind = op.get_bind()

    # Checked before anything is deleted, so the revision fails with an explanation instead of
    # failing halfway through with a raw foreign-key error.
    dependents = {
        "user_roles": "role assignments to live accounts",
        "role_permissions": "role-to-capability grants",
        "cases": "cases belonging to the default organisation",
    }
    blocking: list[str] = []
    for table, description in dependents.items():
        rows = bind.execute(sa.text(f"SELECT EXISTS (SELECT 1 FROM {table})")).scalar()
        if bool(rows):
            blocking.append(f"{table} ({description})")

    if blocking and _data_loss_permitted():
        # A deliberate teardown: revision 0001 drops these tables next, so the rows go with them.
        return

    if blocking:
        raise RuntimeError(
            "refusing to downgrade revision 0002: the seeded reference rows are still referenced by "
            + ", ".join(blocking)
            + ". Remove those rows first — they record who was granted what and which cases exist, "
            "which is the history an audit trail is made of. For a deliberate, backed-up teardown "
            "run: alembic -x allow_data_loss=true downgrade base"
        )

    permission_codes = ", ".join(f"'{code}'" for code, _, _ in PERMISSIONS)
    role_codes = ", ".join(f"CAST('{code}' AS global_role)" for code, _, _ in ROLES)
    op.execute(sa.text(f"DELETE FROM permissions WHERE code IN ({permission_codes})"))
    op.execute(sa.text(f"DELETE FROM roles WHERE code IN ({role_codes})"))
    op.execute(sa.text("DELETE FROM organisations WHERE slug = 'org_default'"))
