"""SQLAlchemy ORM models — one module per domain (``SYSTEM_ARCHITECTURE.md`` §4).

Importing this package imports every model module, and that import is what registers the tables on
``Base.metadata``. Two things depend on it being complete:

* **Alembic.** ``migrations/env.py`` sets ``target_metadata`` from here. A model module that is
  never imported is invisible to ``alembic revision --autogenerate``, and the migration it produces
  will ``DROP`` that module's tables — autogenerate treats "not in the metadata" as "should not
  exist". This is the single easiest way to lose a table, and it produces no error anywhere.
* **The schema tests.** ``tests/db`` asserts primary keys, foreign keys, unique constraints and
  relationship directions against ``Base.metadata``. Same failure mode: an unimported model is
  silently untested.

So: add a model module, add its import here. There is no lazy-loading cleverness worth the risk.
"""

from __future__ import annotations

from app.db.base import Base
from app.models.analysis import AnalysisJob, AnalysisResult, LimitationStatement
from app.models.assistant import AIConversation, AIMessage
from app.models.audit import AuditLog
from app.models.cases import DEFAULT_ORGANISATION_ID, Case, CaseMember, CaseNote, Notification
from app.models.enums import (
    AIMessageStatus,
    ArtifactStatus,
    AuditResult,
    CaseRole,
    CaseStatus,
    ChatRole,
    CustodyEventType,
    DerivativeKind,
    EncState,
    EvidenceStatus,
    EvidenceType,
    GlobalRole,
    IntegrityStatus,
    JobStatus,
    ModelStatus,
    PasswordAlgorithm,
    ReportStatus,
    Sensitivity,
    SourceType,
    UserStatus,
    VerificationStatus,
)
from app.models.evidence import (
    GENESIS_PREV_HASH,
    CustodyEvent,
    Derivative,
    EvidenceItem,
    IntegrityCheck,
    PhysicalObject,
)
from app.models.metadata import MetadataRecord
from app.models.identity import (
    Organisation,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
    UserSession,
)
from app.models.platform import (
    RETENTION_ACTIONS,
    RETENTION_SCOPES,
    FeatureFlag,
    RetentionPolicy,
    SystemSetting,
)
from app.models.registry import AIModel, AIProviderSettings
from app.models.reporting import Report, ReportVersion
from app.models.types import HEX_SHA256_PATTERN

#: The metadata every table is registered on. Re-exported because Alembic, the health probe and
#: the schema tests all need the *same* object, and "which metadata?" should never be a question
#: with two answers.
metadata = Base.metadata

__all__ = [
    "DEFAULT_ORGANISATION_ID",
    "GENESIS_PREV_HASH",
    "HEX_SHA256_PATTERN",
    "RETENTION_ACTIONS",
    "RETENTION_SCOPES",
    "AIConversation",
    "AIMessage",
    "AIMessageStatus",
    "AIModel",
    "AIProviderSettings",
    "AnalysisJob",
    "AnalysisResult",
    "ArtifactStatus",
    "AuditLog",
    "AuditResult",
    "Base",
    "Case",
    "CaseMember",
    "CaseNote",
    "CaseRole",
    "CaseStatus",
    "ChatRole",
    "CustodyEvent",
    "CustodyEventType",
    "Derivative",
    "DerivativeKind",
    "EncState",
    "EvidenceItem",
    "EvidenceStatus",
    "EvidenceType",
    "FeatureFlag",
    "GlobalRole",
    "IntegrityCheck",
    "IntegrityStatus",
    "JobStatus",
    "LimitationStatement",
    "MetadataRecord",
    "ModelStatus",
    "Notification",
    "Organisation",
    "PasswordAlgorithm",
    "Permission",
    "PhysicalObject",
    "Report",
    "ReportStatus",
    "ReportVersion",
    "RetentionPolicy",
    "Role",
    "RolePermission",
    "Sensitivity",
    "SourceType",
    "SystemSetting",
    "User",
    "UserRole",
    "UserSession",
    "UserStatus",
    "VerificationStatus",
    "metadata",
]
