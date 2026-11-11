"""TruthLens X backend application package.

Milestone **M1 — repository foundation.** This package currently contains configuration, logging,
the error model, request middleware, health checks and the system API namespace. It contains **no
forensic capability**: authentication arrives in M3, evidence handling in M5, custody in M6 and the
analysis engines from M8 onward. See ``docs/IMPLEMENTATION_ROADMAP.md``.

The repository is deliberately unlicensed — see ``docs/adr/ADR-0008``.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
