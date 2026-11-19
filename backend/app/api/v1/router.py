"""v1 API router."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import admin_auth, auth, cases, custody, evidence, job_monitor, jobs, system

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(auth.router, prefix="/api/v1")
api_router.include_router(admin_auth.router, prefix="/api/v1")
api_router.include_router(cases.router, prefix="/api/v1")
api_router.include_router(evidence.router, prefix="/api/v1")
api_router.include_router(custody.router, prefix="/api/v1")
api_router.include_router(jobs.router, prefix="/api/v1")
api_router.include_router(job_monitor.router, prefix="/api/v1")

__all__ = ["api_router"]
