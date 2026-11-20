"""M21 release verification helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReleaseGate:
    name: str
    passed: bool
    evidence: str


def evaluate_release(gates: dict[str, bool]) -> list[ReleaseGate]:
    return [ReleaseGate(k, v, "passed" if v else "blocked") for k, v in sorted(gates.items())]


def release_ready(gates: dict[str, bool]) -> bool:
    return all(gates.values())
