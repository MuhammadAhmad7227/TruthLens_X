"""M19 operational controls and allowlisted settings."""

from __future__ import annotations

from typing import Any

FAILED_JOB_ALERT_THRESHOLD = 10
AUTH_DENIAL_ALERT_THRESHOLD = 20

ALLOWED_SETTINGS = {
    "max_upload_bytes",
    "default_job_timeout",
    "external_ai_enabled",
    "retention_days",
    "log_level",
}


def validate_setting(key: str, value: Any) -> Any:
    if key not in ALLOWED_SETTINGS:
        raise ValueError("Setting is not allowlisted")
    if key == "max_upload_bytes" and (not isinstance(value, int) or value <= 0):
        raise ValueError("Invalid upload quota")
    if key == "retention_days" and (not isinstance(value, int) or value < 0):
        raise ValueError("Invalid retention period")
    if key == "external_ai_enabled" and not isinstance(value, bool):
        raise ValueError("Invalid external AI flag")
    return value


def alert_conditions(*, failed_jobs: int, auth_denials: int, integrity_failures: int) -> list[str]:
    alerts = []
    if failed_jobs >= FAILED_JOB_ALERT_THRESHOLD:
        alerts.append("job_failure_burst")
    if auth_denials >= AUTH_DENIAL_ALERT_THRESHOLD:
        alerts.append("auth_burst")
    if integrity_failures > 0:
        alerts.append("integrity_mismatch")
    return alerts
