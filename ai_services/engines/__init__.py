"""Forensic engine contract and registry.

Import surface for both sides of the boundary:

* an engine implementation subclasses :class:`engines.base.Engine` and returns
  :class:`engines.base.EngineResult`;
* an orchestrator builds an :class:`engines.registry.EngineRegistry`, discovers or registers
  engines, and calls :meth:`engines.base.Engine.execute`.

This package must not import ``backend.app`` (SYSTEM_ARCHITECTURE §4.1 rule 5). The contract here is
the only coupling between the two, which is what keeps an engine testable without a database, a queue
or the FastAPI app.
"""

from __future__ import annotations

from .base import (
    CONTRACT_VERSION,
    MAX_LIMITATION_CHARS,
    Engine,
    EngineContext,
    EngineInput,
    EngineResult,
    EngineStatus,
)
from .registry import (
    ENTRY_POINT_GROUP,
    DiscoveryReport,
    DuplicateEngineError,
    EngineRegistry,
    PinViolation,
    RegistryError,
    UnknownEngineError,
)

__all__ = [
    "CONTRACT_VERSION",
    "ENTRY_POINT_GROUP",
    "MAX_LIMITATION_CHARS",
    "DiscoveryReport",
    "DuplicateEngineError",
    "Engine",
    "EngineContext",
    "EngineInput",
    "EngineRegistry",
    "EngineResult",
    "EngineStatus",
    "PinViolation",
    "RegistryError",
    "UnknownEngineError",
]
