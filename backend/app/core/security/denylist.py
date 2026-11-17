"""AUTH-06 denylist port and deterministic in-process implementation.

Redis is the production target specified by AUTH-06, but Redis infrastructure is intentionally
deferred in M3. The authentication service depends on this port so the implementation can later be
swapped for Redis without changing authentication business logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from time import monotonic
from typing import Protocol


class JtiDenylist(Protocol):
    def deny(self, jti: str, ttl_seconds: int) -> None: ...
    def is_denied(self, jti: str) -> bool: ...
    def purge_expired(self) -> int: ...


@dataclass(frozen=True)
class _Entry:
    expires_at: float


class InProcessJtiDenylist(JtiDenylist):
    """Thread-safe TTL denylist for development/test execution."""

    def __init__(self) -> None:
        self._entries: dict[str, _Entry] = {}
        self._lock = RLock()

    def deny(self, jti: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        with self._lock:
            self._entries[jti] = _Entry(monotonic() + ttl_seconds)

    def is_denied(self, jti: str) -> bool:
        now = monotonic()
        with self._lock:
            entry = self._entries.get(jti)
            if entry is None:
                return False
            if entry.expires_at <= now:
                self._entries.pop(jti, None)
                return False
            return True

    def purge_expired(self) -> int:
        now = monotonic()
        with self._lock:
            expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
            for key in expired:
                self._entries.pop(key, None)
            return len(expired)
