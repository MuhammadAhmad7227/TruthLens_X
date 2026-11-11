"""Structured logging with **unconditional** secret and evidence-content redaction.

Logging is the most likely place for a secret or evidence content to escape a forensic platform: it
is written continuously, by many call sites, often from exception handlers that were not designed
with disclosure in mind, and it usually ends up aggregated somewhere with weaker access control than
the database.

``SECURITY_ARCHITECTURE.md`` §5.4 therefore requires that redaction is **not opt-in per call site**.
It is a structlog processor applied to every event, running **last** so it also sees the text that
``format_exc_info`` produced from an exception — a traceback containing a connection string is the
classic leak, and a redactor that runs before exception formatting misses it entirely.

Two deliberate design points:

* **SHA-256 evidence digests are preserved.** They are operationally essential (an examiner greps
  logs for a digest) and are not secrets — knowing a hash does not reveal the file. A blanket
  "redact anything that looks like a long hex string" rule would destroy the audit value of the logs,
  so the digest pattern is matched and protected *before* the generic long-hex rule is applied.
* **Bytes are never rendered.** Any ``bytes`` value becomes ``<N bytes omitted>``, because the only
  bytes this platform handles in bulk are evidence content.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping
from typing import Any

import structlog

REDACTED = "[REDACTED]"

#: Keys whose *values* are always redacted, matched case-insensitively on the key name.
#: Deliberately broad: a false positive costs a log field, a false negative costs a secret.
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)("
    r"password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|jwt|credential|authorization|cookie|session[_-]?id|"
    r"totp|mfa[_-]?secret|dek|kek|database_url|redis_url|dsn|connection[_-]?string|"
    r"hmac|salt|passphrase|key[_-]?material"
    # Plus ANY field whose name is or ends with a `key` component: `encryption_key`,
    # `signing_key`, `master_key`, `api_key`. Anchored on separators so `monkey` and `keyboard`
    # are not caught. The leading (?i) already applies to the whole pattern, so no inline flag
    # appears here. A false positive costs one log field; a false negative costs a secret.
    r"|(^|[_-])key([_-]|$)"
    r")"
)

#: Keys that must never carry a value at all, whatever it looks like.
FORBIDDEN_KEYS = frozenset({"stack_trace_of_user_data", "evidence_bytes", "file_content"})

#: Values that look like credentials regardless of the key they arrived under. A key-based rule
#: alone is insufficient: secrets get logged under innocent names like ``detail`` or ``error``.
SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PEM private-key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # Connection strings with embedded credentials
    # Two subtleties, both of which caused a real leak:
    #   * the username is OPTIONAL — `redis://:password@host` is the standard form for a Redis
    #     URL with no username, and requiring one would leave the broker URL unredacted;
    #   * the scheme may carry a **driver suffix** — `postgresql+psycopg://`, `mysql+pymysql://`.
    #     That is the form this project's own DATABASE_URL uses, so omitting it leaked the DSN.
    re.compile(
        r"(?i)\b(postgresql|postgres|mysql|mariadb|redis|rediss|amqp|amqps|mongodb|https?)"
        r"(\+[A-Za-z0-9_]+)?://[^\s@]*:[^\s@/]+@[^\s/]+"
    ),
    # Bearer tokens
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"),
    # Long hex that is NOT a 64-char digest (see SHA256_PATTERN) — session ids, API secrets
    re.compile(r"\b[A-Fa-f0-9]{32,63}\b"),
    # Long base64 blobs (JWT segments, encoded keys)
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    # Provider API keys
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    # Common cloud/SCM token shapes
    re.compile(r"\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"),
)

#: Hex strings of **exactly** 64 characters are evidence SHA-256 values and ARE meaningful in logs.
SHA256_PATTERN = re.compile(r"\b[A-Fa-f0-9]{64}\b")

_configured = False


def redact_value(value: Any) -> Any:
    """Redact secrets from an arbitrary value, recursing into mappings and sequences.

    **Key-name checks apply at every depth**, not only at the top level. A nested
    ``{"user": {"password": "..."}}`` must be redacted exactly like a top-level ``password``;
    checking keys only once would leak the common case where a secret sits inside a payload object.

    SHA-256 evidence digests (exactly 64 hex characters) are preserved because they are
    operationally essential and are not secrets.
    """
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and (
                key in FORBIDDEN_KEYS or SENSITIVE_KEY_PATTERN.search(key)
            ):
                result[key] = REDACTED
            else:
                result[key] = redact_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        # Never render byte payloads: the only large byte values here are evidence content.
        return f"<{len(value)} bytes omitted>"
    return value


#: Control characters that are legitimate in log text.
_ALLOWED_CONTROL = frozenset("\n\r\t")

#: Below this length a string is too short to classify reliably, so it is treated as text.
_MIN_BINARY_PROBE_LENGTH = 16
#: Above this ratio of non-printable characters a string is decoded binary, not text.
_BINARY_CHAR_RATIO = 0.1


def _looks_binary(value: str) -> bool:
    """Whether a string is really decoded binary content rather than text.

    ``UnicodeDecoder`` and any ``bytes.decode()`` in application code can turn evidence content into
    a ``str``. Redacting by type alone would then pass it straight through, so the shape of the
    value is checked as well. This is defence in depth behind the type check in ``redact_value``.
    """
    if "\x00" in value:
        return True
    if len(value) < _MIN_BINARY_PROBE_LENGTH:
        return False
    non_text = sum(1 for char in value if not char.isprintable() and char not in _ALLOWED_CONTROL)
    return non_text / len(value) > _BINARY_CHAR_RATIO


def _redact_string(value: str) -> str:
    if not value:
        return value
    if _looks_binary(value):
        return f"<{len(value)} chars of binary data omitted>"
    # 1. Protect evidence digests BEFORE the generic long-hex rule can match part of them.
    #    A placeholder containing NUL bytes cannot occur in real log text.
    preserved: dict[str, str] = {}
    working = value
    for index, match in enumerate(SHA256_PATTERN.finditer(value)):
        token = f"\x00sha{index}\x00"
        preserved[token] = match.group(0)
        working = working.replace(match.group(0), token, 1)

    # 2. Apply every secret pattern.
    for pattern in SECRET_VALUE_PATTERNS:
        working = pattern.sub(REDACTED, working)

    # 3. Restore the digests.
    for token, original in preserved.items():
        working = working.replace(token, original)
    return working


def redact_processor(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor enforcing redaction on every event.

    Sensitive *keys* have their values replaced wholesale; all other values are scanned for
    secret-shaped substrings. Runs last in the chain — see the module docstring for why.
    """
    for key in list(event_dict):
        if key in FORBIDDEN_KEYS:
            event_dict[key] = REDACTED
            continue
        if isinstance(key, str) and SENSITIVE_KEY_PATTERN.search(key):
            event_dict[key] = REDACTED
            continue
        event_dict[key] = redact_value(event_dict[key])
    return event_dict


def add_service_context(
    _logger: Any, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Attach stable service identity to every event."""
    # Local import: config imports nothing from logging, but keeping this lazy avoids any chance of
    # an import cycle as the package grows. Logging must also be importable when configuration is
    # invalid, which is exactly when this function is most needed.
    from app.core.config import get_settings  # noqa: PLC0415

    try:
        settings = get_settings()
        event_dict.setdefault("service", settings.service_name)
        event_dict.setdefault("env", str(settings.tlx_env.value))
    except Exception:
        # Configuration may be invalid; that failure is reported by create_app, not by the logger.
        event_dict.setdefault("service", "truthlens")
        event_dict.setdefault("env", "unconfigured")
    return event_dict


def configure_logging(
    *,
    level: str = "INFO",
    json_format: bool = True,
    stream: Any = None,
) -> None:
    """Configure structlog and the standard library so both emit through one pipeline.

    Routing stdlib logging through structlog matters: uvicorn, sqlalchemy and any third-party
    library log via ``logging``, and a redactor that only covers structlog events would leave those
    unredacted.

    Idempotent: repeated calls reconfigure rather than stacking processors.

    Args:
        level: minimum level name (``DEBUG``/``INFO``/``WARNING``/``ERROR``/``CRITICAL``).
        json_format: ``True`` for machine-parseable JSON to stdout; ``False`` for a readable
            console renderer (development only — refused in production by ``Settings``).
        stream: destination file object. Defaults to ``sys.stdout``. Tests pass a ``StringIO`` so
            redaction can be asserted on the bytes that would actually be written.
    """
    global _configured  # noqa: PLW0603

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,  # request_id bound by RequestContextMiddleware
        structlog.stdlib.add_log_level,
        # add_logger_name reads `logger.name`, which only a stdlib logger has — hence
        # LoggerFactory below rather than PrintLoggerFactory.
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(
            fmt="iso", utc=True
        ),  # TZ must stay UTC — timestamps are evidence
        structlog.processors.StackInfoRenderer(),
        # UnicodeDecoder runs AFTER redaction on purpose. It converts `bytes` to `str`, and if it
        # ran first the redactor would see evidence content as an ordinary string and pass it
        # through. Redaction must observe the real type.
        add_service_context,
        structlog.processors.format_exc_info,
        # Redaction runs LAST among the transforming processors so it sees the fully assembled
        # event, including any exception text that format_exc_info produced. This ordering is the
        # whole point of the design.
        redact_processor,
        # Decoding is presentation, not transformation of meaning, so it is safe after redaction.
        structlog.processors.UnicodeDecoder(),
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer(sort_keys=True)
        if json_format
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    destination = stream if stream is not None else sys.stdout

    structlog.configure(
        processors=[*shared_processors, renderer],
        # A stdlib logger factory (not PrintLoggerFactory) so that:
        #   * add_logger_name works — PrintLogger has no `.name` attribute;
        #   * third-party libraries logging via `logging` share ONE pipeline and one handler, so
        #     nothing can write to stdout unredacted beside our own events.
        # Level filtering is done by the stdlib logger configured below.
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        # Caching would bind the first handler forever and break reconfiguration in tests.
        cache_logger_on_first_use=False,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=destination,
        level=_level_number(level),
        # Replace any handler installed by a library or a previous call, so output is not doubled.
        force=True,
    )
    # Silence noisy loggers whose output carries no forensic value and risks leaking connection detail.
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "sqlalchemy.pool"):
        logging.getLogger(noisy).setLevel(max(_level_number(level), logging.WARNING))

    _configured = True


def _level_number(level: str) -> int:
    return int(getattr(logging, level.upper(), logging.INFO))


def is_configured() -> bool:
    """Whether :func:`configure_logging` has run. Used by the startup assertion and by tests."""
    return _configured


def get_logger(name: str | None = None) -> Any:
    """Return a bound logger. Callers should pass ``__name__``."""
    return structlog.get_logger(name) if name else structlog.get_logger()


__all__ = [
    "FORBIDDEN_KEYS",
    "REDACTED",
    "SECRET_VALUE_PATTERNS",
    "SENSITIVE_KEY_PATTERN",
    "SHA256_PATTERN",
    "add_service_context",
    "configure_logging",
    "get_logger",
    "is_configured",
    "redact_processor",
    "redact_value",
]
