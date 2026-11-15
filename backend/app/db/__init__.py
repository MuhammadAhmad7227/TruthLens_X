"""Database layer: engine, session, declarative base, transaction helpers.

``SYSTEM_ARCHITECTURE.md`` §4 describes this package as exactly that, and the module boundary rule
that governs it (``backend/tests/architecture/test_module_boundaries.py``, §4.1(7)) is that it
provides *sessions, not queries*: nothing here knows what a case or an item of evidence is. Models
import the declarative base from here; this package never imports them, which is what keeps the
dependency acyclic.

This ``__init__`` imports nothing on purpose. ``sqlalchemy`` and ``alembic`` ship in the optional
``db`` extra, and ``app/core/health.py`` must stay importable in environments where that extra is
absent — lint runs, docs builds, a frontend-only CI job — so that ``/readyz`` can report "the driver
is not installed" instead of failing at import. Re-exporting :class:`~app.db.base.Base` here would
make ``import app.db`` require the extra and quietly break that. Import from the submodule:

    from app.db.base import Base
    from app.db.session import get_session
    from app.db.transaction import atomic
"""

from __future__ import annotations
