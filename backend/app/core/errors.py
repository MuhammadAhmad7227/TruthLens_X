"""Exception hierarchy and the RFC 9457 ``application/problem+json`` error model.

Rules implemented here (``docs/API_SPECIFICATION.md`` §1.4, ``docs/SECURITY_ARCHITECTURE.md`` §6.3):

* A stable machine-readable ``error_code`` is always present. Clients must never parse ``title``.
* Stack traces and internal detail never reach the client; they are logged server-side under the
  same ``request_id`` that is returned to the caller.
* Every error carries a ``request_id`` so support can correlate a user-visible failure to logs.

``audit_reason`` exists because of a conflict found during ratification (ADR-0004, conflict #4):
``API_SPECIFICATION.md`` listed ``FORBIDDEN_CASE_ACCESS`` as a **403** code, which contradicted the
non-enumerability requirement in ``SECURITY_ARCHITECTURE.md`` §5.5 *and* the insider-threat alerting
requirement in §9. Both are satisfied by separating the two audiences — the client sees ``404`` /
``NOT_FOUND``, while the audit log records ``FORBIDDEN_CASE_ACCESS``.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

PROBLEM_CONTENT_TYPE = "application/problem+json"
ERROR_TYPE_BASE = "https://errors.truthlens.local"

#: The stable machine-readable codes defined in API_SPECIFICATION §1.4.
#: These are what a **client** sees. Server-side audit reasons are a separate vocabulary —
#: see ``AuditReason`` below and the note on ``ForbiddenCaseAccessError``.
ErrorCode = Literal[
    "VALIDATION_ERROR",
    "UNSUPPORTED_EVIDENCE_TYPE",
    "UNAUTHENTICATED",
    "TOKEN_EXPIRED",
    "MFA_REQUIRED",
    "FORBIDDEN_ROLE",
    "FORBIDDEN_CAPABILITY",
    "CASE_CLOSED",
    "LEGAL_HOLD",
    "NOT_FOUND",
    "CONFLICT",
    "IDEMPOTENCY_KEY_REUSED",
    "INVALID_STATE_TRANSITION",
    "EVIDENCE_INTEGRITY_MISMATCH",
    "PAYLOAD_TOO_LARGE",
    "UNSUPPORTED_MEDIA_TYPE",
    "ENGINE_UNAVAILABLE",
    "MODEL_NOT_LOADED",
    "RATE_LIMITED",
    "INTERNAL_ERROR",
    "DEPENDENCY_UNAVAILABLE",
    "CONFIGURATION_ERROR",
    "EXTERNAL_AI_DISABLED",
    "EGRESS_CONFIRMATION_REQUIRED",
    "EGRESS_CATEGORY_NOT_ALLOWED",
    "EGRESS_GRANT_EXPIRED",
    "ASSISTANT_UNAVAILABLE",
    "CAPABILITY_DISABLED",
    "RETENTION_NOT_CONFIGURED",
]

#: Reasons recorded in the audit log. Deliberately a **superset** of ``ErrorCode``: some denials
#: must be detectable by monitoring (SECURITY_ARCHITECTURE §9) without being visible to the caller.
AuditReason = Literal[
    "FORBIDDEN_CASE_ACCESS",
    "FORBIDDEN_CAPABILITY",
    "FORBIDDEN_ROLE",
    "BREAK_GLASS_DENIED",
    "EGRESS_BLOCKED",
    "INTEGRITY_MISMATCH",
    "CROSS_CASE_ACCESS_ATTEMPT",
]


class FieldError(BaseModel):
    """A single field-level validation failure."""

    field: str = Field(description="Dotted path to the offending field, e.g. 'body.case_id'.")
    message: str = Field(description="Human-readable explanation.")
    code: str = Field(default="invalid", description="Stable per-field code.")


class ProblemDetail(BaseModel):
    """RFC 9457 problem document, extended with TruthLens-specific members.

    ``audit_reason`` is deliberately **absent**: this model is the client-facing payload, and a
    denial reason that distinguishes "forbidden" from "absent" is exactly what must not leak.
    """

    type: str = Field(description="URI identifying the problem type.")
    title: str = Field(description="Short human-readable summary.")
    status: int = Field(ge=400, le=599)
    detail: str | None = Field(
        default=None, description="Human-readable explanation for this occurrence."
    )
    instance: str | None = Field(default=None, description="Request path this problem occurred on.")
    request_id: str | None = Field(
        default=None, description="Correlation id; quote this when reporting."
    )
    error_code: ErrorCode = Field(
        description="Stable machine-readable code. Parse this, never 'title'."
    )
    remediation: str | None = Field(default=None, description="What the caller can do about it.")
    field_errors: list[FieldError] = Field(default_factory=list)


class TruthLensError(Exception):
    """Base class for every application-raised error that maps to an HTTP response.

    Subclasses set ``status`` and ``error_code``. ``detail`` is written for a human operator and
    must never contain a secret, a stack trace, or raw evidence content.
    """

    status: int = 500
    error_code: ErrorCode = "INTERNAL_ERROR"
    title: str = "Internal server error"
    #: Whether the occurrence is logged at ERROR with a stack trace. Client errors are not.
    log_with_traceback: bool = False
    #: Server-side audit vocabulary. Defaults to ``None`` (not audited as a denial). Overridden
    #: where monitoring needs to see something the client must not.
    audit_reason: AuditReason | None = None

    def __init__(
        self,
        detail: str | None = None,
        *,
        remediation: str | None = None,
        field_errors: list[FieldError] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail or self.title)
        self.detail = detail
        self.remediation = remediation
        self.field_errors = field_errors or []
        #: Structured context for the *server-side log record only*. Never serialised to the client.
        self.context: dict[str, Any] = context or {}

    @property
    def type_uri(self) -> str:
        return f"{ERROR_TYPE_BASE}/{self.error_code.lower().replace('_', '-')}"

    def to_problem(
        self, *, instance: str | None = None, request_id: str | None = None
    ) -> ProblemDetail:
        """Build the client-facing problem document.

        ``audit_reason`` and ``context`` are excluded by construction — ``ProblemDetail`` has no
        field for either, so leaking them would require changing the model, not a careless call.
        """
        return ProblemDetail(
            type=self.type_uri,
            title=self.title,
            status=self.status,
            detail=self.detail,
            instance=instance,
            request_id=request_id,
            error_code=self.error_code,
            remediation=self.remediation,
            field_errors=self.field_errors,
        )


# ── 4xx ──────────────────────────────────────────────────────────────────────
class DomainError(TruthLensError):
    """A rule of the domain was violated. Base for most 4xx errors."""

    status: int = 409
    error_code: ErrorCode = "CONFLICT"
    title = "Request conflicts with the current state"


class ValidationError(TruthLensError):
    status: int = 400
    error_code: ErrorCode = "VALIDATION_ERROR"
    title = "Request validation failed"


class NotFoundError(DomainError):
    status: int = 404
    error_code: ErrorCode = "NOT_FOUND"
    title = "Resource not found"


class AuthorisationError(TruthLensError):
    """Base for every denial. Subclasses distinguish *which* layer denied the request."""

    status: int = 403
    error_code: ErrorCode = "FORBIDDEN_CAPABILITY"
    title = "Access denied"
    audit_reason: AuditReason | None = "FORBIDDEN_CAPABILITY"


class UnauthenticatedError(AuthorisationError):
    status: int = 401
    error_code: ErrorCode = "UNAUTHENTICATED"
    title = "Authentication required"
    audit_reason: AuditReason | None = None


class ForbiddenRoleError(AuthorisationError):
    error_code: ErrorCode = "FORBIDDEN_ROLE"
    title = "Your role does not permit this action"
    audit_reason: AuditReason | None = "FORBIDDEN_ROLE"


class ForbiddenCaseAccessError(NotFoundError):
    """Deliberately a **404 with ``error_code=NOT_FOUND``**, not a 403.

    ``SECURITY_ARCHITECTURE.md`` §5.5: returning 403 would confirm that the case exists, letting a
    caller enumerate cases across an authorisation boundary. Denials for case-scoped resources are
    therefore indistinguishable from a missing resource.

    §9 requires that these denials remain **detectable for insider-threat alerting** — cross-case
    access attempts are the highest-signal insider indicator. That requirement is met by
    ``audit_reason``, which is written to the audit log and never to the response body.

    This resolves ratification conflict #4; see ADR-0004 and DECISIONS.md.
    """

    status: int = 404
    error_code: ErrorCode = "NOT_FOUND"
    title = "Resource not found"
    #: Audit-only. Never reaches ``ProblemDetail`` — that model has no field for it.
    audit_reason: AuditReason | None = "FORBIDDEN_CASE_ACCESS"


class CaseClosedError(AuthorisationError):
    error_code: ErrorCode = "CASE_CLOSED"
    title = "This case is closed and read-only"
    audit_reason: AuditReason | None = None


class LegalHoldError(AuthorisationError):
    status = 423  # WebDAV "Locked" — unambiguous, unlike a 409 that could mean anything
    error_code: ErrorCode = "LEGAL_HOLD"
    title = "Blocked by legal hold"
    audit_reason: AuditReason | None = None


class IntegrityError(TruthLensError):
    """Evidence integrity could not be established. **Fail closed** — never proceed with analysis.

    A hash mismatch is not a warning to be logged and continued past: analysis on unverified
    evidence produces conclusions that cannot be attributed to the item actually acquired.
    """

    status: int = 409
    error_code: ErrorCode = "EVIDENCE_INTEGRITY_MISMATCH"
    title = "Evidence integrity verification failed"
    audit_reason: AuditReason | None = "INTEGRITY_MISMATCH"
    log_with_traceback = True


class InvalidStateTransitionError(DomainError):
    error_code: ErrorCode = "INVALID_STATE_TRANSITION"
    title = "That state transition is not permitted"


class CapabilityDisabledError(TruthLensError):
    """A gated capability is not enabled in this deployment.

    Used instead of a fabricated empty result: a disabled feature must say it is disabled
    (ADR-0002 PDF rasterisation, ADR-0014 AV scanning, ADR-0015 gazetteer). Silently returning
    "nothing found" would be a false negative presented as a finding.
    """

    status: int = 422
    error_code: ErrorCode = "CAPABILITY_DISABLED"
    title = "This capability is not enabled in this deployment"


class RetentionNotConfiguredError(TruthLensError):
    """ADR-0020: retention has no statutory period configured, so nothing may be deleted."""

    status: int = 409
    error_code: ErrorCode = "RETENTION_NOT_CONFIGURED"
    title = "Retention period is not configured"


class ExternalAIDisabledError(AuthorisationError):
    error_code: ErrorCode = "EXTERNAL_AI_DISABLED"
    title = "External AI providers are disabled"
    audit_reason: AuditReason | None = "EGRESS_BLOCKED"


class EgressConfirmationRequiredError(AuthorisationError):
    """ADR-0021: a bound, expiring confirmation token is required before anything leaves the host."""

    error_code: ErrorCode = "EGRESS_CONFIRMATION_REQUIRED"
    title = "External data transmission requires confirmation"
    audit_reason: AuditReason | None = "EGRESS_BLOCKED"


class EgressCategoryNotAllowedError(AuthorisationError):
    """ADR-0021: the category allowlist is empty by default, so enabling AI authorises nothing."""

    error_code: ErrorCode = "EGRESS_CATEGORY_NOT_ALLOWED"
    title = "This data category may not be transmitted"
    audit_reason: AuditReason | None = "EGRESS_BLOCKED"


class EgressGrantExpiredError(AuthorisationError):
    error_code: ErrorCode = "EGRESS_GRANT_EXPIRED"
    title = "The external AI grant has expired"
    audit_reason: AuditReason | None = "EGRESS_BLOCKED"


class AssistantUnavailableError(TruthLensError):
    """ADR-0007 / ADR-0021: local inference failed.

    There is **no cloud fallback** — the provider is fixed at startup, so a failure is a failure the
    user sees, never an answer silently sourced from somewhere else. ``fallback_attempted`` is
    always false because no code path could set it true.
    """

    status: int = 422
    error_code: ErrorCode = "ASSISTANT_UNAVAILABLE"
    title = "The investigation assistant is unavailable"


# ── 5xx ──────────────────────────────────────────────────────────────────────
class EngineError(TruthLensError):
    """A forensic engine could not produce a result.

    MASTER_PRD AR-7: an engine failure is *visible*. It must never be reported as "no issues
    found" — a silent failure in a forensic tool is an fabricated negative result.
    """

    status: int = 422
    error_code: ErrorCode = "ENGINE_UNAVAILABLE"
    title = "Analysis engine unavailable"
    log_with_traceback = True


class DependencyUnavailableError(TruthLensError):
    status: int = 503
    error_code: ErrorCode = "DEPENDENCY_UNAVAILABLE"
    title = "A required service is unavailable"
    log_with_traceback = True


class InternalError(TruthLensError):
    status: int = 500
    error_code: ErrorCode = "INTERNAL_ERROR"
    title = "Internal server error"
    log_with_traceback = True


__all__ = [
    "ERROR_TYPE_BASE",
    "PROBLEM_CONTENT_TYPE",
    "AssistantUnavailableError",
    "AuditReason",
    "AuthorisationError",
    "CapabilityDisabledError",
    "CaseClosedError",
    "DependencyUnavailableError",
    "DomainError",
    "EgressCategoryNotAllowedError",
    "EgressConfirmationRequiredError",
    "EgressGrantExpiredError",
    "EngineError",
    "ErrorCode",
    "ExternalAIDisabledError",
    "FieldError",
    "ForbiddenCaseAccessError",
    "ForbiddenRoleError",
    "IntegrityError",
    "InternalError",
    "InvalidStateTransitionError",
    "LegalHoldError",
    "NotFoundError",
    "ProblemDetail",
    "RetentionNotConfiguredError",
    "TruthLensError",
    "UnauthenticatedError",
    "ValidationError",
]
