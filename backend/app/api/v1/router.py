"""v1 API router.

Routers are aggregated here so ``app.main`` has exactly one include point. Milestone M1 contains the
``system`` namespace only; each later milestone adds its own module under ``app/api/v1/``.

Per ``docs/SYSTEM_ARCHITECTURE.md`` §4.1, routers stay thin: validate → call a service → map to a
schema. No business logic and no direct repository access live in this package.

Note that ``system.router`` declares both the unprefixed probes (``/healthz``, ``/readyz``) and the
explicitly prefixed ``/api/v1/status``, so it is included **without** an additional prefix. Domain
routers added from M3 onward will be included with ``prefix="/api/v1"``.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import system

api_router = APIRouter()
api_router.include_router(system.router)

__all__ = ["api_router"]
