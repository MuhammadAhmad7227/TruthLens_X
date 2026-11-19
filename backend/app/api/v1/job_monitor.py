"""Administrative worker and queue monitoring for M7."""
from __future__ import annotations

from typing import Any

from celery import Celery
from fastapi import APIRouter

from app.api.v1.auth_deps import CurrentPrincipal
from app.core.config import get_settings
from app.core.errors import ForbiddenRoleError

router = APIRouter(prefix="/admin/jobs", tags=["jobs"])


def _require_admin(principal: CurrentPrincipal) -> None:
    if principal.user.global_role.value != "admin":
        raise ForbiddenRoleError("Administrator role required")


def _queue_lengths(broker_url: str) -> dict[str, int]:
    import redis

    client = redis.Redis.from_url(broker_url, decode_responses=True)
    try:
        return {
            queue: int(client.llen(queue))
            for queue in ("ingest", "analysis.cpu", "analysis.gpu", "reports", "maintenance")
        }
    finally:
        client.close()


@router.get("/monitor")
def monitor(principal: CurrentPrincipal) -> dict[str, Any]:
    _require_admin(principal)
    settings = get_settings()
    celery = Celery("truthlens-monitor", broker=settings.celery_broker_url)
    inspect = celery.control.inspect(timeout=1.0)
    active = inspect.active() or {}
    reserved = inspect.reserved() or {}
    stats = inspect.stats() or {}
    try:
        queues = _queue_lengths(settings.celery_broker_url)
    except Exception:
        queues = {}
    return {
        "workers": {
            name: {
                "active": len(active.get(name, [])),
                "reserved": len(reserved.get(name, [])),
                "stats": stats.get(name),
            }
            for name in sorted(set(active) | set(reserved) | set(stats))
        },
        "queues": queues,
    }
