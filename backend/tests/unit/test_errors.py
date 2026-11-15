"""Error model tests: RFC 9457 shape, stable codes, and the status-code decisions.

The status codes encode ratified policy, not convenience:

* ``ForbiddenCaseAccessError`` returns **404** with ``error_code=NOT_FOUND``, not 403, so case
  existence is not enumerable — while ``audit_reason`` keeps the denial detectable server-side
  (ADR-0004, ratification conflict #4).
* ``LegalHoldError`` returns **423 Locked** rather than an ambiguous 409.
* ``AssistantUnavailableError`` returns **422**: a local inference failure is a visible failure,
  never a silently substituted answer (ADR-0007).
* ``CapabilityDisabledError`` returns **422** rather than an empty result, because a disabled feature
  that reports "nothing found" is a fabricated negative (ADR-0002, ADR-0014, ADR-0015).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.core.errors import (
    ERROR_TYPE_BASE,
    PROBLEM_CONTENT_TYPE,
    AssistantUnavailableError,
    AuthorisationError,
    CapabilityDisabledError,
    CaseClosedError,
    DependencyUnavailableError,
    DomainError,
    EgressCategoryNotAllowedError,
    EgressConfirmationRequiredError,
    EgressGrantExpiredError,
    EngineError,
    ExternalAIDisabledError,
    FieldError,
    ForbiddenCaseAccessError,
    ForbiddenRoleError,
    IntegrityError,
    InternalError,
    InvalidStateTransitionError,
    LegalHoldError,
    NotFoundError,
    ProblemDetail,
    RetentionNotConfiguredError,
    TruthLensError,
    UnauthenticatedError,
    ValidationError,
)


class TestProblemShape:
    def test_content_type_is_problem_json(self) -> None:
        assert PROBLEM_CONTENT_TYPE == "application/problem+json"

    def test_type_base_is_a_stable_uri(self) -> None:
        assert ERROR_TYPE_BASE == "https://errors.truthlens.local"

    def test_problem_omits_absent_fields_rather_than_nulling_them(self) -> None:
        problem = ProblemDetail(
            type=f"{ERROR_TYPE_BASE}/not-found",
            title="Resource not found",
            status=404,
            error_code="NOT_FOUND",
        )
        dumped = problem.model_dump(mode="json", exclude_none=True)
        assert dumped["type"].startswith("https://")
        assert dumped["status"] == 404
        assert "detail" not in dumped
        assert "request_id" not in dumped

    def test_request_id_is_carried_into_the_problem(self) -> None:
        problem = ProblemDetail(
            type=f"{ERROR_TYPE_BASE}/internal-error",
            title="Internal server error",
            status=500,
            error_code="INTERNAL_ERROR",
            request_id="req_abc123",
        )
        assert problem.model_dump(mode="json")["request_id"] == "req_abc123"

    def test_field_errors_round_trip(self) -> None:
        problem = ProblemDetail(
            type=f"{ERROR_TYPE_BASE}/validation-error",
            title="Request validation failed",
            status=400,
            error_code="VALIDATION_ERROR",
            field_errors=[FieldError(field="case_id", message="invalid uuid", code="uuid_parsing")],
        )
        dumped = problem.model_dump(mode="json", exclude_none=True)
        assert dumped["field_errors"][0]["field"] == "case_id"
        assert dumped["field_errors"][0]["code"] == "uuid_parsing"

    def test_status_outside_the_http_error_range_is_rejected(self) -> None:
        """`status` is bounded 400..599 so a problem document cannot claim success."""
        with pytest.raises(PydanticValidationError, match="greater than or equal to 400"):
            ProblemDetail(type="x", title="y", status=200, error_code="INTERNAL_ERROR")

    def test_problem_detail_has_no_audit_reason_field(self) -> None:
        """The client-facing model must make leaking an audit reason structurally impossible."""
        assert "audit_reason" not in ProblemDetail.model_fields
        assert "context" not in ProblemDetail.model_fields


class TestErrorToProblem:
    def test_to_problem_populates_instance_and_request_id(self) -> None:
        error = NotFoundError("The thing does not exist")
        problem = error.to_problem(instance="/api/v1/cases/1", request_id="req_1")
        assert problem.instance == "/api/v1/cases/1"
        assert problem.request_id == "req_1"
        assert problem.status == 404

    def test_to_problem_defaults_are_safe(self) -> None:
        problem = DomainError("x").to_problem()
        assert problem.instance is None
        assert problem.request_id is None

    def test_type_uri_is_derived_from_the_stable_code(self) -> None:
        error = LegalHoldError("locked")
        assert error.type_uri == f"{ERROR_TYPE_BASE}/legal-hold"
        assert error.to_problem().type == error.type_uri

    def test_underscored_codes_become_hyphenated_uris(self) -> None:
        assert AssistantUnavailableError().type_uri.endswith("/assistant-unavailable")

    def test_server_side_context_is_not_serialised_to_the_client(self) -> None:
        """`context` exists for logs only; leaking it would expose internals."""
        error = IntegrityError(
            "SHA-256 mismatch",
            context={
                "expected": "abc",
                "observed": "def",
                "internal_path": "/srv/truthlens/evidence/originals/ab/cd",
            },
        )
        problem = error.to_problem()
        dumped = problem.model_dump(mode="json")
        assert "context" not in dumped
        assert "/srv/truthlens/evidence" not in str(dumped)
        assert error.context["internal_path"].startswith("/srv/truthlens")

    def test_audit_reason_is_not_serialised_to_the_client(self) -> None:
        error = ForbiddenCaseAccessError("no membership")
        dumped = error.to_problem().model_dump(mode="json")
        assert "audit_reason" not in dumped
        assert "FORBIDDEN_CASE_ACCESS" not in str(dumped)
        # ...but it IS available server-side for the audit log.
        assert error.audit_reason == "FORBIDDEN_CASE_ACCESS"


class TestStatusCodes:
    @pytest.mark.parametrize(
        ("error", "expected_status", "expected_code"),
        [
            (DomainError("x"), 409, "CONFLICT"),
            (ValidationError("x"), 400, "VALIDATION_ERROR"),
            (NotFoundError("x"), 404, "NOT_FOUND"),
            (AuthorisationError("x"), 403, "FORBIDDEN_CAPABILITY"),
            (UnauthenticatedError(), 401, "UNAUTHENTICATED"),
            (ForbiddenRoleError("x"), 403, "FORBIDDEN_ROLE"),
            (ForbiddenCaseAccessError("x"), 404, "NOT_FOUND"),
            (CaseClosedError("x"), 403, "CASE_CLOSED"),
            (LegalHoldError("x"), 423, "LEGAL_HOLD"),
            (IntegrityError("x"), 409, "EVIDENCE_INTEGRITY_MISMATCH"),
            (InvalidStateTransitionError("x"), 409, "INVALID_STATE_TRANSITION"),
            (CapabilityDisabledError("x"), 422, "CAPABILITY_DISABLED"),
            (RetentionNotConfiguredError("x"), 409, "RETENTION_NOT_CONFIGURED"),
            (ExternalAIDisabledError(), 403, "EXTERNAL_AI_DISABLED"),
            (EgressConfirmationRequiredError(), 403, "EGRESS_CONFIRMATION_REQUIRED"),
            (EgressCategoryNotAllowedError(), 403, "EGRESS_CATEGORY_NOT_ALLOWED"),
            (EgressGrantExpiredError(), 403, "EGRESS_GRANT_EXPIRED"),
            (AssistantUnavailableError(), 422, "ASSISTANT_UNAVAILABLE"),
            (EngineError("x"), 422, "ENGINE_UNAVAILABLE"),
            (DependencyUnavailableError("x"), 503, "DEPENDENCY_UNAVAILABLE"),
            (InternalError("x"), 500, "INTERNAL_ERROR"),
        ],
    )
    def test_status_and_code(
        self, error: TruthLensError, expected_status: int, expected_code: str
    ) -> None:
        assert error.status == expected_status
        assert error.error_code == expected_code

    def test_case_access_denial_is_indistinguishable_from_absence(self) -> None:
        """ADR-0004 conflict #4: a caller must not learn whether a case they cannot see exists."""
        denied = ForbiddenCaseAccessError("no membership").to_problem()
        absent = NotFoundError("not found").to_problem()
        assert denied.status == absent.status == 404
        assert denied.error_code == absent.error_code == "NOT_FOUND"
        assert denied.title == absent.title
        # The full client payloads are identical apart from `detail`, which the caller controls.
        assert denied.type == absent.type

    def test_egress_errors_are_distinguishable_from_each_other(self) -> None:
        """A client must be able to tell 'not allowed at all' from 'allowed after a step'."""
        codes = {
            ExternalAIDisabledError().error_code,
            EgressConfirmationRequiredError().error_code,
            EgressCategoryNotAllowedError().error_code,
            EgressGrantExpiredError().error_code,
        }
        assert len(codes) == 4

    def test_every_error_has_a_distinct_stable_code(self) -> None:
        """Clients switch on `error_code`, so codes must not collide across meanings."""
        errors = [
            ValidationError("x"),
            NotFoundError("x"),
            AuthorisationError("x"),
            UnauthenticatedError(),
            ForbiddenRoleError("x"),
            ForbiddenCaseAccessError("x"),
            CaseClosedError("x"),
            LegalHoldError("x"),
            IntegrityError("x"),
            InvalidStateTransitionError("x"),
            CapabilityDisabledError("x"),
            RetentionNotConfiguredError("x"),
            ExternalAIDisabledError(),
            EgressConfirmationRequiredError(),
            EgressCategoryNotAllowedError(),
            EgressGrantExpiredError(),
            AssistantUnavailableError(),
            EngineError("x"),
            DependencyUnavailableError("x"),
            InternalError("x"),
        ]
        codes = [e.error_code for e in errors]
        # ForbiddenCaseAccessError deliberately shares NOT_FOUND with NotFoundError (ADR-0004),
        # so exactly one duplicate is expected and it is the intentional one.
        assert len(codes) - len(set(codes)) == 1
        assert codes.count("NOT_FOUND") == 2

    def test_server_errors_are_logged_with_traceback(self) -> None:
        assert InternalError("boom").log_with_traceback is True
        assert DependencyUnavailableError("down").log_with_traceback is True
        assert EngineError("failed").log_with_traceback is True
        # Integrity failures are 409 but are genuinely exceptional and must be diagnosable.
        assert IntegrityError("mismatch").log_with_traceback is True

    def test_client_errors_do_not_demand_a_traceback(self) -> None:
        assert ValidationError("bad").log_with_traceback is False
        assert NotFoundError("gone").log_with_traceback is False
        assert ForbiddenCaseAccessError("denied").log_with_traceback is False


class TestAuditReasons:
    def test_denials_carry_an_audit_reason(self) -> None:
        assert AuthorisationError("x").audit_reason == "FORBIDDEN_CAPABILITY"
        assert ForbiddenRoleError("x").audit_reason == "FORBIDDEN_ROLE"
        assert ForbiddenCaseAccessError("x").audit_reason == "FORBIDDEN_CASE_ACCESS"

    def test_egress_blocks_are_audited(self) -> None:
        """SECURITY_ARCHITECTURE §9: blocked egress attempts are a monitored signal."""
        for error in (
            ExternalAIDisabledError(),
            EgressConfirmationRequiredError(),
            EgressCategoryNotAllowedError(),
            EgressGrantExpiredError(),
        ):
            assert error.audit_reason == "EGRESS_BLOCKED"

    def test_integrity_mismatch_is_audited(self) -> None:
        assert IntegrityError("x").audit_reason == "INTEGRITY_MISMATCH"

    def test_ordinary_client_errors_are_not_audited_as_denials(self) -> None:
        """A validation error is not a security event; flooding the audit log hides real ones."""
        assert ValidationError("x").audit_reason is None
        assert NotFoundError("x").audit_reason is None
        assert UnauthenticatedError().audit_reason is None
        assert CaseClosedError("x").audit_reason is None


class TestErrorConstruction:
    def test_context_defaults_to_empty_dict(self) -> None:
        assert DomainError("x").context == {}

    def test_detail_is_the_constructor_message(self) -> None:
        error = DomainError("A longer operator-facing explanation.")
        assert error.detail == "A longer operator-facing explanation."
        assert error.to_problem().detail == "A longer operator-facing explanation."
        assert str(error) == "A longer operator-facing explanation."

    def test_absent_detail_falls_back_to_the_title(self) -> None:
        error = DomainError()
        assert str(error) == error.title
        assert error.detail is None

    def test_remediation_is_passed_through(self) -> None:
        error = IntegrityError("mismatch", remediation="Re-acquire the file and compare digests.")
        assert error.to_problem().remediation == "Re-acquire the file and compare digests."

    def test_field_errors_are_passed_through(self) -> None:
        error = ValidationError(
            "invalid", field_errors=[FieldError(field="body.name", message="required")]
        )
        problem = error.to_problem()
        assert problem.field_errors[0].field == "body.name"

    def test_errors_are_catchable_as_the_base_class(self) -> None:
        """A single handler catches every application error — see exception_handlers."""
        with pytest.raises(TruthLensError):
            raise ForbiddenCaseAccessError("denied")
        assert issubclass(ForbiddenCaseAccessError, NotFoundError)
        assert issubclass(UnauthenticatedError, AuthorisationError)
