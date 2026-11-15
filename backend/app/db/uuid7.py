"""UUIDv7 generation — RFC 9562 §5.7.

``docs/DATABASE_DESIGN.md`` §1.1 splits primary keys deliberately (ADR-0009):

* **UUIDv7** for high-volume, append-only tables — ``custody_events``, ``audit_logs``,
  ``analysis_jobs``, ``derivatives``. Time-ordered keys keep B-tree inserts at the right-hand
  edge of the index instead of scattering them, which is the difference between a table that
  grows to hundreds of millions of rows and one that fragments the index doing it.
* **UUIDv4** for externally visible, long-lived entities — ``users``, ``cases``,
  ``evidence_items``, ``physical_objects``, ``ai_models``, ``reports``. A v7 identifier leaks
  the creation time of anything a third party can see, which for evidence and case numbers is
  information nobody outside the platform is entitled to.

The database generates v7 server-side through the ``uuid_generate_v7()`` PL/pgSQL function that
migration ``0001`` installs, so rows inserted by any client — the ORM, ``psql``, a bulk
migration — get the same ordering property. This module exists for the Python side: tests,
services that need an identifier before insert, and anything comparing against the server
function's output.
"""

from __future__ import annotations

import secrets
import time
from uuid import UUID

__all__ = ["uuid7"]

#: 48 bits of millisecond timestamp, shifted into the most significant position.
_TIMESTAMP_SHIFT = 80
_TIMESTAMP_MASK = 0xFFFF_FFFF_FFFF

_VERSION_SHIFT = 76
_VERSION_7 = 0x7

_RANDOM_A_BITS = 12
_RANDOM_A_SHIFT = 64

_VARIANT_SHIFT = 62
_VARIANT_RFC4122 = 0b10

_RANDOM_B_BITS = 62


def uuid7(*, timestamp_ms: int | None = None) -> UUID:
    """Return a new UUIDv7.

    Args:
        timestamp_ms: Unix epoch milliseconds to embed. Defaults to the current time. Exposed
            so tests can build a deterministic identifier and assert the ordering property
            rather than merely trusting it.

    The 12 bits of ``rand_a`` and 62 bits of ``rand_b`` come from :mod:`secrets`, not
    :mod:`random`: identifiers are used as capability references in signed URLs, so
    predictability would be a security defect, not a style issue.
    """
    millis = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    value = (millis & _TIMESTAMP_MASK) << _TIMESTAMP_SHIFT
    value |= _VERSION_7 << _VERSION_SHIFT
    value |= secrets.randbits(_RANDOM_A_BITS) << _RANDOM_A_SHIFT
    value |= _VARIANT_RFC4122 << _VARIANT_SHIFT
    value |= secrets.randbits(_RANDOM_B_BITS)
    return UUID(int=value)
