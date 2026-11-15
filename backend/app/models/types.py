"""Column types shared across the schema, and the reasoning behind the two primary-key idioms.

PostgreSQL-native types are used deliberately (``TEXT``, ``CHAR(64)``, ``JSONB``, ``INET``,
``ARRAY``, ``TSVECTOR``). ``docs/DATABASE_DESIGN.md`` §1 and §11 name PostgreSQL 16 as the only
supported engine, and a dialect-neutral abstraction here would cost real guarantees: ``JSON``
instead of ``JSONB`` loses the GIN indexes §10 depends on, ``String`` instead of ``TEXT`` adds a
length limit nobody asked for, and a portable ``BINARY(16)`` UUID would give up the native
comparison operators that make UUIDv7 ordering useful in the first place.

Server defaults are written fresh at each column rather than exported as module-level singletons.
A ``TextClause`` used as a server default is bound to its column (``DefaultClause._set_parent``
records it), so one shared instance across twenty tables would leave every column but the last
bound to the wrong parent — the kind of aliasing bug that produces correct-looking DDL for one
table and quietly wrong DDL for the rest.

**Primary keys (ADR-0009, §1.1).** Two idioms, chosen per table:

* ``gen_random_uuid()`` — externally visible, long-lived entities (``users``, ``cases``,
  ``evidence_items``, ``physical_objects``, ``ai_models``, ``reports``). A time-ordered identifier
  on these would disclose when an item of evidence was ingested to anyone who can see the id,
  including a party on the other side of a case.
* ``uuid_generate_v7()`` — high-volume append-only tables (``custody_events``, ``audit_logs``,
  ``analysis_jobs``, ``derivatives``). Inserting in time order keeps B-tree pages appending at the
  right-hand edge instead of scattering across the index.

Both are also supplied as Python-side ``default`` values so an ORM object carries its identity
before flush, which is what makes it possible to assemble an object graph — a case, its members,
its first evidence item — and hand it to the session as one unit of work. The server default is
what non-ORM writers get: a bulk data migration or a ``psql`` session during an incident produces
the same kind of identifier. That matters for an append-only ledger, because §1 principle DB-3
requires the ledger to remain verifiable by tooling that is not this application.

Ordering caveat, stated plainly: ``uuid_generate_v7()`` embeds a millisecond timestamp and
cryptographically random low bits, so identifiers are ordered *across* milliseconds but not within
one. Nothing in the schema relies on v7 for correctness of order — ``custody_events.sequence`` and
``audit_logs.sequence`` are the authoritative ordering, allocated under an advisory lock. v7 buys
index locality, not sequence.
"""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy import CHAR, Numeric, Text
from sqlalchemy.dialects.postgresql import ARRAY

__all__ = [
    "HEX_SHA256_PATTERN",
    "MD5",
    "SHA1",
    "SHA256",
    "confidence_numeric",
    "score_numeric",
    "text_array",
]

#: ``char(64)`` — a hex-encoded SHA-256 digest. Fixed-width wherever it is the integrity anchor: a
#: variable-length column would let a truncated digest pass a length check nobody wrote.
SHA256 = CHAR(64)

#: Lowercase hex, exactly 64 characters — the alphabet check that goes with the width above.
#:
#: One copy, here, because four tables have a digest column and a pattern retyped at each of them is
#: a pattern that can differ at one of them. A digest that arrived uppercase would compare unequal to
#: the same digest computed again, and the failure would present as an integrity mismatch rather than
#: as a formatting bug.
HEX_SHA256_PATTERN = r"^[0-9a-f]{64}$"

#: ``char(40)`` — SHA-1, kept only for interoperability with external tooling that still emits it.
#: Never trusted for an integrity decision.
SHA1 = CHAR(40)

#: ``char(32)`` — MD5, legacy interop only.
MD5 = CHAR(32)


def text_array() -> ARRAY[Text]:
    """A fresh ``text[]`` type instance.

    A factory rather than a constant, for the same reason server defaults are not shared: array
    types carry per-column dimension state, and one instance reused across a schema is an
    invitation to an aliasing bug that only shows up in generated DDL.
    """
    # The `arg-type` ignore is a stub defect in sqlalchemy 2.1.8: ARRAY's item_type parameter is
    # declared as `_HasPythonType[_T]`, which `Text` (python type `str`) does not satisfy in either
    # its class or instance form. The call is the documented usage. mypy's `warn_unused_ignores`
    # (on, via strict) means this line fails again the moment a release fixes the stub.
    return ARRAY(Text())  # type: ignore[arg-type]


def score_numeric() -> Numeric[Decimal]:
    """``numeric(5,2)`` — advisory scores and their bounds, from 0.00 to 100.00.

    ``numeric``, never ``float``. A float round-trips 87.35 as 87.3499999999999943, and a number
    that appears in a court-facing report must be the number that was computed. §1.1 states the
    same principle for sizes (``bigint``, never floats); this is its application to scores.
    """
    return Numeric(5, 2)


def confidence_numeric() -> Numeric[Decimal]:
    """``numeric(5,4)`` — a calibrated confidence, from 0.0000 to 1.0000."""
    return Numeric(5, 4)
