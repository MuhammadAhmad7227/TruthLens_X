# fmt: off
"""Small deterministic in-process fixed-window rate limiter for M3.

Redis-backed rate limiting is deferred with the same infrastructure constraint as AUTH-06. The
limiter is a replaceable process-local implementation for development/test; it must not be presented
as a distributed production limiter.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from time import monotonic


@dataclass
class _Window:
    started_at: float
    hits: int


class InProcessRateLimiter:
    def __init__(self) -> None:
        self._windows: dict[str, _Window] = {}
        self._lock = RLock()

    def allow(self, key: str, *, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = monotonic()
        with self._lock:
            current = self._windows.get(key)
            if current is None or now - current.started_at >= window_seconds:
                current = _Window(now, 0)
                self._windows[key] = current
            current.hits += 1
            remaining = max(0, limit - current.hits)
            return current.hits <= limit, remaining

    def purge_expired(self, *, window_seconds: int) -> int:
        now = monotonic()
        with self._lock:
            expired = [
                key for key, value in self._windows.items()
                if now - value.started_at >= window_seconds
            ]
            for key in expired:
                self._windows.pop(key, None)
            return len(expired)

# fmt: on
