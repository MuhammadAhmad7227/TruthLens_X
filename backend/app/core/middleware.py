"""Request-context and security-header middleware.

Two pieces:

``RequestContextMiddleware`` gives every request a correlation id and emits exactly one access-log
line. The id is echoed back in a response header so a user reporting a failure can quote it and
support can find the exact log records — including the server-side detail that was deliberately
withheld from the response body.

``SecurityHeadersMiddleware`` sets a conservative, uniform header set. It is deliberately static:
there is no per-route variation, so no endpoint can accidentally ship without it.
"""

from __future__ import annotations

import re
import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.config import Settings

logger = structlog.get_logger(__name__)

#: Inbound ids are validated before use. Accepting an arbitrary client-supplied string into a log
#: line is a log-injection vector: a value containing a newline or an ANSI escape can forge records
#: or corrupt a log aggregator's parsing. Anything that fails validation is replaced, not sanitised —
#: sanitising would produce an id that does not match what the client sent, which is worse than
#: issuing a fresh one.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._\-]{8,128}$")

#: A response at or above this status is always logged, even on an otherwise quiet path.
_LOG_ALWAYS_STATUS = 400

#: Paths excluded from access logging when the response is successful. Probes fire every few
#: seconds; logging them buries real traffic. Failures are ALWAYS logged, because a failing probe
#: is an incident.
_QUIET_PATHS = frozenset({"/healthz", "/readyz"})


def new_request_id() -> str:
    """Generate a correlation id. ``uuid4`` is backed by the OS CSPRNG."""
    return f"req_{uuid.uuid4().hex}"


def normalise_request_id(raw: str | None) -> str:
    """Return a safe request id, honouring a well-formed inbound value."""
    if raw and _VALID_REQUEST_ID.match(raw):
        return raw
    return new_request_id()


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Bind a request id into structlog contextvars and emit one access-log line per request."""

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings
        self._header = settings.request_id_header

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = normalise_request_id(request.headers.get(self._header))
        started = time.perf_counter()

        # Bind into contextvars so every log line emitted while handling this request carries the
        # id without any call site having to pass it explicitly.
        token = structlog.contextvars.bind_contextvars(request_id=request_id)
        # Also on request.state, for exception handlers that need it without touching contextvars.
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            # Log the failure before re-raising: the exception handlers build the response, but a
            # crash below them must still be attributable to this request id.
            logger.error(
                "http.request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            raise
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
            del token  # the bind token is not reusable after unbind; release it explicitly

        # The header is set in a `finally`-equivalent position so it is present on success AND on
        # handled-error responses. Without it a user cannot quote the id they were given.
        response.headers[self._header] = request_id
        self._log_access(request, response, started)
        return response

    def _log_access(self, request: Request, response: Response, started: float) -> None:
        status_code = response.status_code
        quiet = request.url.path in _QUIET_PATHS and status_code < _LOG_ALWAYS_STATUS
        if quiet:
            return
        # `_safe_query` keeps a credential accidentally passed as a query parameter out of the log.
        logger.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            query=_safe_query(request),
            status=status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            client=request.client.host if request.client else None,
        )


def _safe_query(request: Request) -> str | None:
    """Return the query string with keys that look credential-bearing redacted.

    The value-level redaction processor would catch a secret *shaped* value, but a short password in
    a query string may not match any pattern. Reducing the key set is the reliable control.
    """
    if not request.url.query:
        return None
    # Local import: logging imports nothing from middleware, but keeping this lazy avoids an import
    # cycle as the package grows, and this helper runs per-request on the hot path.
    from app.core.logging import REDACTED, SENSITIVE_KEY_PATTERN  # noqa: PLC0415

    parts = []
    for key, value in request.query_params.multi_items():
        parts.append(f"{key}={REDACTED if SENSITIVE_KEY_PATTERN.search(key) else value}")
    return "&".join(parts)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """A static, conservative security-header set applied to every response.

    Static on purpose: a per-route header policy is a policy that will eventually be missing on some
    route. Cache handling is the one place a path distinction is made, because caching an
    ``/api/`` response would persist case data in a shared or browser cache.
    """

    #: Evidence and case data must never be cached, even briefly, in any intermediary.
    _NO_STORE_PREFIXES = ("/api/", "/docs", "/redoc", "/openapi.json")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        headers: dict[str, str] = {
            # No MIME sniffing: a mislabelled derivative could otherwise be executed as script.
            "X-Content-Type-Options": "nosniff",
            # Never leak the referring URL, which may contain a case id or a signed token.
            "Referrer-Policy": "no-referrer",
            # This is an internal investigative tool; it is never a legitimate framing target.
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": (
                "default-src 'self'; img-src 'self' data: blob:; "
                "media-src 'self' blob:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            ),
            # Cross-origin isolation: stop this origin's data being readable by another.
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Permissions-Policy": (
                "geolocation=(), camera=(), microphone=(), usb=(), interest-cohort=()"
            ),
        }
        path = request.url.path
        if any(path.startswith(prefix) for prefix in self._NO_STORE_PREFIXES):
            headers["Cache-Control"] = "no-store, max-age=0"
            headers["Pragma"] = "no-cache"
        else:
            headers["Cache-Control"] = "no-cache"

        for name, value in headers.items():
            # setdefault would let a downstream handler override a security header; assignment
            # makes this middleware authoritative.
            response.headers[name] = value
        return response


__all__ = [
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
    "new_request_id",
    "normalise_request_id",
]
