"""Identity and authorization: ``users``, ``roles``, ``permissions``, ``user_roles``.

This module is the substrate M3 builds authentication and RBAC **on**. It deliberately contains no
authorization logic: no capability resolution, no membership check, no password hashing. What it
fixes now is the shape of the tables, so that M3 adds queries and services rather than migrations
that rewrite a live database.

The two-layer model of ``SECURITY_ARCHITECTURE.md`` §4.1 is represented structurally:

* **Layer 1 — global role.** ``users.global_role`` is the effective primary role, kept as a native
  enum column because §3.1 indexes and filters on it directly. ``roles`` materialises the same six
  values as rows, ``permissions`` holds the canonical capability vocabulary of §4.2, and
  ``role_permissions`` is the matrix §4.2 describes as *data, seeded by migration*. ``user_roles``
  records which global roles are assigned to whom, with the same time-bounding and revocation
  columns ``case_members`` uses, so a grant can expire without anyone remembering to remove it.
* **Layer 2 — case membership.** Lives in :mod:`app.models.cases` (``case_members``), because it is
  meaningless without a case.

Why both ``users.global_role`` and ``user_roles`` exist, and the invariant that ties them
---------------------------------------------------------------------------------------
§3.1 requires the enum column: it is the single value an index, an audit row and a report header
all read. ``user_roles`` is required for anything that has to be *auditable and revocable* — who
granted the role, from when, until when, and when it was taken away. So the enum column is the
denormalised answer to "what is this user's role right now" and ``user_roles`` is the history and
the source of truth for assignment.

The invariant is: **a user's active primary ``user_roles`` row has the same ``code`` as
``users.global_role``.** The schema enforces the part it can enforce alone — a partial unique index
guarantees at most one active primary role per user — and leaves the agreement between the two to
the single service that writes both, in M3. Enforcing it here would need a trigger, and a trigger
that keeps two representations in step is a place for authorization logic to hide where no test and
no code review will look for it.

Passwords
---------
``users.password_hash`` stores an argon2id **encoded string** (algorithm, parameters, salt and
digest in one self-describing token) and ``password_alg`` records which hasher produced it, so a
legacy ``bcrypt`` row can be upgraded on the next successful login. There is no column anywhere in
this schema that could hold a plaintext password, and no column that holds a reversible secret:
``mfa_secret_encrypted`` is ``bytea`` ciphertext under the application KEK, and
``ai_provider_settings.api_key_encrypted`` follows the same rule. Both are asserted by
``tests/db/test_models.py`` rather than left to review.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Integer, Text, text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin, UTCDateTime
from app.db.uuid7 import uuid7
from app.models.enums import GlobalRole, PasswordAlgorithm, UserStatus, native_enum
from app.models.types import HEX_SHA256_PATTERN, SHA256

if TYPE_CHECKING:
    # Relationship targets that live in sibling domain modules. Imported for the type checker only:
    # a runtime import here would be a cycle, because those modules import Base and the enums from
    # this same package. SQLAlchemy resolves the string annotations against its class registry at
    # mapper-configuration time, which is after ``app.models`` has imported every module.
    from app.models.cases import Case, CaseMember, Notification

__all__ = [
    "Organisation",
    "Permission",
    "Role",
    "RolePermission",
    "User",
    "UserRole",
    "UserSession",
]


class User(Base, TimestampMixin, SoftDeleteMixin):
    """A person (or service identity) that can act on the platform.

    Never hard-deleted (§3.1): ``deleted_at`` marks deactivation, because every custody event and
    audit row references the actor and a platform that cannot answer "who did this" has lost the
    property it exists to provide.
    """

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )

    #: Unique case-insensitively. §3.1 specifies ``citext``; the schema uses a functional unique
    #: index on ``lower(email)`` instead, which gives the identical guarantee with no extension
    #: dependency. ``citext`` would also make the comparison implicit — and an implicit
    #: case-folding rule on a column that appears in a WHERE clause is how an index stops being
    #: used. ``lower(email)`` is explicit, and the index below is the one it can use.
    email: Mapped[str] = mapped_column(Text, nullable=False)

    #: Optional alternate login, also case-insensitively unique when present.
    username: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    full_name: Mapped[str] = mapped_column(Text, nullable=False)

    #: argon2id encoded string. NEVER a plaintext password, and never a bare digest: the encoded
    #: form carries the parameters, so a future cost increase does not invalidate existing rows.
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    password_alg: Mapped[PasswordAlgorithm] = mapped_column(
        # Named `password_alg` to match the type §9 declares, not `password_algorithm`.
        native_enum(PasswordAlgorithm, name="password_alg"),
        nullable=False,
        server_default=text("'argon2id'"),
    )
    password_changed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    global_role: Mapped[GlobalRole] = mapped_column(
        native_enum(GlobalRole), nullable=False, server_default=text("'investigator'")
    )
    status: Mapped[UserStatus] = mapped_column(
        native_enum(UserStatus), nullable=False, server_default=text("'pending_activation'")
    )

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    #: TOTP secret, encrypted under the application KEK. NULL when MFA has not been enrolled.
    mfa_secret_encrypted: Mapped[bytes | None] = mapped_column(nullable=True, default=None)
    mfa_required_by_policy: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )

    #: Lockout state. ``failed_login_count`` and ``locked_until`` are columns, not Redis keys, so a
    #: restart cannot reset an attacker's progress (Redis remains the rate-limit fast path in M3).
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    #: ``inet``, not ``text``: PostgreSQL validates the literal and can answer subnet queries,
    #: which is what an investigation into a compromised account actually asks.
    last_login_ip: Mapped[str | None] = mapped_column(INET, nullable=True, default=None)

    role_assignments: Mapped[list[UserRole]] = relationship(
        back_populates="user",
        foreign_keys="[UserRole.user_id]",
        cascade="all, delete-orphan",
    )
    case_memberships: Mapped[list[CaseMember]] = relationship(
        back_populates="user", foreign_keys="[CaseMember.user_id]"
    )
    notifications: Mapped[list[Notification]] = relationship(
        back_populates="user", foreign_keys="[Notification.user_id]"
    )
    #: Login sessions. No cascade: ``user_sessions.user_id`` is ``ON DELETE RESTRICT`` (§3.2), so an
    #: ORM-level cascade would contradict the database and fail at flush time instead of at delete
    #: time. Users are soft-deleted anyway — see the class docstring.
    sessions: Mapped[list[UserSession]] = relationship(back_populates="user")

    __table_args__ = (
        Index("uq_users_email_lower", text("lower(email)"), unique=True),
        Index(
            "uq_users_username_lower",
            text("lower(username)"),
            unique=True,
            postgresql_where=text("username IS NOT NULL"),
        ),
        Index("ix_users_global_role", "global_role"),
        Index("ix_users_status", "status"),
        # §3.1's partial index: the active population, which is what administration queries.
        Index(
            "ix_users_active_email",
            text("lower(email)"),
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    # No CHECK ties `mfa_secret_encrypted` to `mfa_enabled`. TOTP enrolment stores the encrypted
    # secret *before* the user confirms it, so "a secret implies enabled" would forbid the very
    # flow §3.1 describes. That ordering is M3 service logic, and a constraint contradicting the
    # flow it guards is worse than no constraint.


class Organisation(Base, TimestampMixin):
    """Tenancy placeholder — exactly one seeded row in v1 (ADR-0004, §3.2b).

    Inert: no authorization logic reads it and it carries no ``tenant_id`` semantics (ADR-0010).
    It exists so that multi-tenancy is an *additive* change later — populate real organisations,
    backfill ``cases.organisation_id``, add one predicate inside the single authorization choke
    point — rather than a rewrite of every case-scoped query. Removing it now would make that
    future change a schema migration against a database holding live evidence.
    """

    __tablename__ = "organisations"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    #: ``text``, not an enum: the vocabulary is one value today (``active``) and belongs to a
    #: feature that does not exist yet, so fixing it as an enum would be a guess (§9).
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'active'"))

    cases: Mapped[list[Case]] = relationship(back_populates="organisation")


class Role(Base, TimestampMixin):
    """A global role as a row, so permissions and assignments can reference it by primary key.

    ``code`` is the same native enum as ``users.global_role``, which is what keeps the two
    representations from drifting: a ``roles`` row cannot be created for a role the platform does
    not recognise, and a role cannot be removed from the enum without a migration that also deals
    with the row.
    """

    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    code: Mapped[GlobalRole] = mapped_column(native_enum(GlobalRole), nullable=False, unique=True)
    #: Human label, distinct from ``code``: ``lead_investigator`` is an identifier, "Lead
    #: investigator" is what a report header prints.
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: System roles are seeded and cannot be deleted by an administrator. The six global roles are
    #: referenced by ``users.global_role`` values that already exist, so deleting one would orphan
    #: live accounts.
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    permissions: Mapped[list[Permission]] = relationship(
        secondary="role_permissions", back_populates="roles"
    )
    assignments: Mapped[list[UserRole]] = relationship(
        back_populates="role", cascade="all, delete-orphan"
    )


class Permission(Base, TimestampMixin):
    """A named capability — the vocabulary of ``SECURITY_ARCHITECTURE.md`` §4.2.

    ``DATABASE_DESIGN.md`` §13 calls this table ``capabilities``; it is named ``permissions`` here
    to match the milestone's entity list, and the two are the same thing (recorded in §14).

    ``code`` is ``text``, not an enum, on purpose: capabilities grow as features are added, and §9
    is explicit that a growing vocabulary must not be a native enum, because PostgreSQL cannot drop
    an enum value. Thirty codes are seeded by migration ``0002`` from the canonical list in §4.2.
    """

    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    code: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    #: ``case``, ``evidence``, ``report``, ``admin``, ``platform`` — the resource family a
    #: capability acts on. Queryable, so an administrator UI can group the list without parsing
    #: dotted codes.
    resource: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    roles: Mapped[list[Role]] = relationship(
        secondary="role_permissions", back_populates="permissions"
    )


class RolePermission(Base, TimestampMixin):
    """The RBAC matrix (§4.2: "the matrix is **data**, seeded by migration").

    A row here is a privilege decision, which is why it carries ``created_at`` and is materialised
    as an association object rather than a bare secondary table: changing a cell must be auditable,
    and a bare ``secondary=`` gives you nothing to audit.
    """

    __tablename__ = "role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )

    #: `overlaps` names the many-to-many relationships that traverse this same association table.
    #: Both views of the join are wanted — `Role.permissions` reads the matrix, and these two
    #: reach the association row that carries its own `created_at` — so the overlap is declared
    #: rather than silenced.
    role: Mapped[Role] = relationship(overlaps="permissions,roles")
    permission: Mapped[Permission] = relationship(overlaps="permissions,roles")


class UserRole(Base, TimestampMixin):
    """Assignment of a global role to a user, with grant and revocation provenance.

    ``is_primary`` plus the partial unique index below give a user at most one active primary role,
    which is the row ``users.global_role`` must agree with. Additional non-primary rows are how a
    second, narrower role is delegated — for example an ``investigator`` who is also ``auditor`` —
    without inventing a seventh combined role.
    """

    __tablename__ = "user_roles"

    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
    )
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    granted_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )
    #: Time-bounded grants, mirroring ``case_members`` (CASE-03). An expired grant stops applying
    #: without anyone having to remember to revoke it.
    valid_from: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    revoked_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, default=None
    )

    user: Mapped[User] = relationship(back_populates="role_assignments", foreign_keys=[user_id])
    role: Mapped[Role] = relationship(back_populates="assignments")
    granted_by_user: Mapped[User | None] = relationship(foreign_keys=[granted_by])
    revoked_by_user: Mapped[User | None] = relationship(foreign_keys=[revoked_by])

    __table_args__ = (
        Index("uq_user_roles_user_role", "user_id", "role_id", unique=True),
        # At most one active primary role per user. Partial rather than plain: revoked rows must
        # not consume the slot, or re-granting a role would fail against history.
        Index(
            "uq_user_roles_primary_active",
            "user_id",
            unique=True,
            postgresql_where=text("is_primary AND revoked_at IS NULL"),
        ),
        Index(
            "ix_user_roles_user_active",
            "user_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
        CheckConstraint(
            "valid_from IS NULL OR valid_until IS NULL OR valid_until > valid_from",
            name="validity_window_is_ordered",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_by IS NOT NULL",
            name="revocation_names_an_actor",
        ),
    )


class UserSession(Base):
    """One issued refresh token, and the family it belongs to (§3.2).

    This is the durable half of authentication state. ``SECURITY_ARCHITECTURE`` keeps the *fast*
    half in Redis — an access-token ``jti`` denylist with a matching TTL — and §3.2 says so
    explicitly: Redis answers "is this token revoked right now" on every request, Postgres is the
    record that survives a Redis restart and the one an investigation reads.

    Nothing here can produce a usable credential. ``refresh_token_hash`` holds a SHA-256 digest of
    the token, so a database read — a stolen backup, an over-broad SELECT in a report, a
    ``tlx_auditor`` session — yields no token to replay. The token itself exists only in the
    response that issued it and in the client that received it.

    Token families
    --------------
    ``family_id`` is what makes rotation detect reuse (M3 task 3.4). Each refresh issues a new token
    in the same family and revokes the old one; presenting an *already-rotated* token means somebody
    is replaying a credential the legitimate client handed back, so the whole family is revoked —
    the attacker's copy and the user's current session together. That is a deliberate denial of
    service against the real user, and it is the correct trade: a stolen refresh token that keeps
    working silently is worse than a forced re-login.

    The revocation therefore has no human actor, which is why there is no ``revoked_by`` column and
    no ``revocation_names_an_actor`` CHECK here — unlike ``user_roles`` and ``case_members``, where a
    revocation is always somebody's decision. Who detected the reuse is an ``audit_logs`` row.

    Timestamps
    ----------
    No ``TimestampMixin``: ``issued_at`` *is* this row's creation time, and a second insert-time
    column would invite code to use the wrong one — the same reasoning ``custody_events`` gives for
    omitting ``created_at``. There is no ``updated_at`` either, because the only update this row ever
    receives is revocation, and ``revoked_at`` records it more precisely than a generic timestamp
    would.
    """

    __tablename__ = "user_sessions"

    #: UUIDv7 rather than ``gen_random_uuid()``. This is a high-volume table — one row per login per
    #: device, never reused — so time-ordered keys keep its primary index appending at the right-hand
    #: edge instead of scattering (§1.1). ADR-0009's disclosure concern does not apply: the id is
    #: never handed to a client. The credential is the token, and what the database stores of it is a
    #: digest.
    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid7, server_default=text("uuid_generate_v7()")
    )
    #: ``RESTRICT``, per §3.2 — not ``CASCADE``. Deleting a user must not erase the record that they
    #: authenticated, from where, with what client: that history is exactly what an investigation
    #: into a compromised account asks for, and §12 keeps user PII deactivated rather than erased
    #: while cases reference the user.
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    #: Digest, never the token. ``char(64)`` + the lowercase-hex CHECK rather than §3.2's literal
    #: ``text``, for the reason ``app.models.types`` gives: a variable-length digest column lets a
    #: truncated value pass a length check nobody wrote, and this one is a security anchor.
    refresh_token_hash: Mapped[str] = mapped_column(SHA256, nullable=False, unique=True)
    #: Groups every rotation descended from one login. Indexed non-partially on purpose: reuse
    #: detection has to find the *revoked* token that was replayed, not just the live ones.
    family_id: Mapped[UUID] = mapped_column(nullable=False, default=uuid4)
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, default=None)
    #: ``inet``, not ``text`` — the same choice ``users.last_login_ip`` makes: PostgreSQL validates
    #: the literal, and "every session from this subnet" is a query an incident response actually
    #: runs.
    ip: Mapped[str | None] = mapped_column(INET, nullable=True, default=None)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    user: Mapped[User] = relationship(back_populates="sessions")

    __table_args__ = (
        # "This user's sessions, newest first" — the account-security page and the revoke-all action.
        Index(
            "ix_user_sessions_user_active", "user_id", postgresql_where=text("revoked_at IS NULL")
        ),
        Index("ix_user_sessions_family", "family_id"),
        CheckConstraint(
            "expires_at > issued_at",
            name="expiry_after_issue",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= issued_at",
            name="revocation_after_issue",
        ),
        CheckConstraint(
            f"refresh_token_hash ~ '{HEX_SHA256_PATTERN}'",
            name="refresh_token_hash_is_lowercase_hex",
        ),
        # There is deliberately no upper bound tying revoked_at to expires_at. Revoking a session
        # that has already expired is a legitimate housekeeping act — a sweep that marks dead rows
        # revoked so the active-session query stops considering them — and a constraint forbidding
        # it would turn that sweep into a stream of failures. "Is this session usable?" is answered
        # by revoked_at IS NULL AND expires_at > now(), which is one predicate, not an ambiguity.
    )
