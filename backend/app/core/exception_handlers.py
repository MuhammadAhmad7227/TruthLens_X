"""Exception handlers producing RFC 9457 ``application/problem+json``.

Rules (``docs/API_SPECIFICATION.md`` §1.4, ``docs/SECURITY_ARCHITECTURE.md`` §6.3):

* Every response carries the stable ``error_code`` and the ``request_id``.
* Nothing internal reaches the client: no stack traces, no third-party exception messages, no
  configuration values, no evidence content.
* Server-side logging keeps the detail, correlated by the same ``request_id``.
* Framework-raised errors are mapped onto the same shape, so a client sees exactly **one** error
  format no matter which layer produced the failure.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ExceptionHandler

from app.core.errors import (
    PROBLEM_CONTENT_TYPE,
    ErrorCode,
    FieldError,
    ProblemDetail,
    TruthLensError,
)

logger = structlog.get_logger(__name__)

#: A response at or above this status is a server-side failure and is logged at ERROR with a
#: traceback. Below it, the caller made the mistake and the event is a warning.
_SERVER_ERROR_STATUS = 500

#: Map a bare HTTP status to our stable error codes, for errors raised by Starlette/FastAPI itself
#: (routing, method not allowed, payload too large) rather than by application code.
_STATUS_TO_CODE: dict[int, ErrorCode] = {
    400: "VALIDATION_ERROR",
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN_CAPABILITY",
    404: "NOT_FOUND",
    405: "NOT_FOUND",
    408: "DEPENDENCY_UNAVAILABLE",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "VALIDATION_ERROR",
    423: "LEGAL_HOLD",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    503: "DEPENDENCY_UNAVAILABLE",
}

_STATUS_TO_TITLE: dict[int, str] = {
    400: "Bad request",
    401: "Authentication required",
    403: "Access denied",
    404: "Resource not found",
    405: "Method not allowed",
    408: "Request timed out",
    413: "Request payload too large",
    415: "Unsupported media type",
    422: "Request validation failed",
    423: "Blocked by legal hold",
    429: "Rate limit exceeded",
    500: "Internal server error",
    503: "A required service is unavailable",
}


def _request_id(request: Request) -> str | None:
    """The correlation id bound by ``RequestContextMiddleware``, if it ran."""
    return getattr(request.state, "request_id", None)


def _problem_response(problem: ProblemDetail) -> JSONResponse:
    return JSONResponse(
        status_code=problem.status,
        content=problem.model_dump(mode="json", exclude_none=True),
        media_type=PROBLEM_CONTENT_TYPE,
    )


def _type_uri(code: ErrorCode) -> str:
    return f"https://errors.truthlens.local/{code.lower().replace('_', '-')}"


async def handle_truthlens_error(request: Request, exc: TruthLensError) -> JSONResponse:
    """Handle every application-raised error.

    ``exc.audit_reason`` is logged server-side but is **not** part of the response. For
    ``ForbiddenCaseAccessError`` that separation is the whole point: the caller sees ``404`` /
    ``NOT_FOUND`` while monitoring sees ``FORBIDDEN_CASE_ACCESS`` (ADR-0004, conflict #4).
    """
    request_id = _request_id(request)
    problem = exc.to_problem(instance=request.url.path, request_id=request_id)

    is_server_error = problem.status >= _SERVER_ERROR_STATUS
    log = logger.error if (exc.log_with_traceback or is_server_error) else logger.warning
    log(
        "http.error",
        error_code=exc.error_code,
        # Server-side only; never returned to the client.
        audit_reason=exc.audit_reason,
        status=problem.status,
        path=request.url.path,
        method=request.method,
        # `context` is server-side only. The redaction processor runs on it before output.
        context=exc.context,
        exc_info=exc if exc.log_with_traceback else None,
    )
    return _problem_response(problem)


async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Map pydantic/FastAPI validation failures onto our problem shape with field-level detail."""
    request_id = _request_id(request)
    raw_errors = exc.errors()
    field_errors = [_field_error_from(raw) for raw in raw_errors]
    problem = ProblemDetail(
        type=_type_uri("VALIDATION_ERROR"),
        title="Request validation failed",
        status=status.HTTP_400_BAD_REQUEST,
        detail=(
            "The request did not satisfy the schema. Unknown or malformed fields are rejected "
            "rather than ignored, so mass-assignment is not possible."
        ),
        instance=request.url.path,
        request_id=request_id,
        error_code="VALIDATION_ERROR",
        remediation="Correct the fields listed in field_errors and retry.",
        field_errors=field_errors,
    )
    # Log field *locations* and error types, never the submitted values — they may contain personal
    # data, and a validation error is exactly where a caller's input would otherwise be echoed back.
    logger.info(
        "http.validation_error",
        status=400,
        path=request.url.path,
        fields=[fe.field for fe in field_errors],
        error_types=[raw.get("type") for raw in raw_errors],
    )
    return _problem_response(problem)


def _field_error_from(raw: dict[str, Any]) -> FieldError:
    location = raw.get("loc", ())
    field = ".".join(str(part) for part in location) or "body"
    return FieldError(
        field=field,
        message=str(raw.get("msg", "invalid value")),
        code=str(raw.get("type", "invalid")),
    )


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Give framework-raised HTTP errors the same problem+json shape."""
    request_id = _request_id(request)
    status_code = exc.status_code
    code = _STATUS_TO_CODE.get(status_code, "INTERNAL_ERROR")
    detail = exc.detail if isinstance(exc.detail, str) else None
    problem = ProblemDetail(
        type=_type_uri(code),
        title=_STATUS_TO_TITLE.get(status_code, detail or "Error"),
        status=status_code,
        detail=detail,
        instance=request.url.path,
        request_id=request_id,
        error_code=code,
    )
    log = logger.error if status_code >= _SERVER_ERROR_STATUS else logger.info
    log("http.exception", status=status_code, path=request.url.path, error_code=code)
    return _problem_response(problem)


async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler. The client receives a correlation id and nothing else."""
    request_id = _request_id(request)
    logger.error(
        "http.unhandled_exception",
        path=request.url.path,
        method=request.method,
        error_class=type(exc).__name__,
        exc_info=exc,
    )
    problem = ProblemDetail(
        type=_type_uri("INTERNAL_ERROR"),
        title="Internal server error",
        status=500,
        detail=(
            "An unexpected error occurred. It has been logged with the request_id in this response; "
            "quote that id when reporting the problem."
        ),
        instance=request.url.path,
        request_id=request_id,
        error_code="INTERNAL_ERROR",
        remediation="Retry, or report the request_id to an administrator.",
    )
    return _problem_response(problem)


_ExcT = TypeVar("_ExcT", bound=Exception)


def _register(
    app: FastAPI,
    exc_class: type[_ExcT],
    handler: Callable[[Request, _ExcT], Awaitable[JSONResponse]],
) -> None:
    """Attach one handler, narrowing the exc_type→handler relationship to a single `cast`.

    ``starlette.types.ExceptionHandler`` types the second parameter invariantly as ``Exception``,
    while each of our handlers legitimately accepts only the class it is registered for. Starlette
    dispatches by exception class, so the narrowing is guaranteed by the framework — the cast states
    that guarantee once, here, rather than four times as ``# type: ignore`` comments that would also
    suppress unrelated future errors.
    """
    app.add_exception_handler(exc_class, cast("ExceptionHandler", handler))


def register_exception_handlers(app: FastAPI) -> None:
    """Attach all handlers. Registration order matters: most specific first."""
    _register(app, TruthLensError, handle_truthlens_error)
    _register(app, RequestValidationError, handle_validation_error)
    _register(app, StarletteHTTPException, handle_http_exception)
    # The catch-all must be registered last so it does not shadow the specific handlers.
    _register(app, Exception, handle_unexpected_error)


__all__ = [
    "handle_http_exception",
    "handle_truthlens_error",
    "handle_unexpected_error",
    "handle_validation_error",
    "register_exception_handlers",
]
