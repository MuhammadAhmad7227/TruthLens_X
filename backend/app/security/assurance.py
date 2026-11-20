"""M20 negative-control and release-assurance helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityCheck:
    code: str
    passed: bool
    detail: str


def forbidden_action_check(*, allowed: bool, expected_code: str, actual_code: str) -> SecurityCheck:
    return SecurityCheck(
        "NEGATIVE_ACCESS",
        (not allowed) and actual_code == expected_code,
        f"expected={expected_code};actual={actual_code}",
    )


def container_hardening_config() -> dict[str, object]:
    return {
        "non_root": True,
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "original_evidence_mount_read_only": True,
    }
