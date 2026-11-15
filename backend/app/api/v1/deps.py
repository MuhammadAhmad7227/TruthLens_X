"""Request-scoped dependencies for the v1 API.

The dependency *implementations* live elsewhere — ``get_session`` in ``app/db/session.py`` — and this
module holds only the ``Annotated`` aliases routers declare. Two reasons, both structural:

``app.core`` may not import anything outside itself (and ``app.db``, for health probes). That is
§4.1's rule 6 and it is enforced by ``tests/architecture/test_module_boundaries.py``, so a
``app/core/deps.py`` full of FastAPI imports is not available as a home for these however convenient
it would be. The API layer is where a FastAPI dependency belongs, because a FastAPI dependency is an
API concern: it is the request scope.

And the alias, not the bare function, is what routers declare. ``session: SessionDep`` and
``session: Annotated[Session, Depends(get_session)]`` mean the same thing to FastAPI, but only the
first reads as a parameter and only the first can be changed once, here, for every router — which is
how the session boundary stays one decision rather than one per endpoint.

WHAT A ROUTER MAY DO WITH THIS
Receive it and hand it to a service. Rule 1 forbids ``app.api`` from importing ``app.models`` or
``app.repositories``, so a router cannot build an ORM query even holding a live session — and that is
the point of the rule: an authorisation decision or a transaction boundary written in a router cannot
be reused by a Celery worker, which is the other caller every service has. The session arrives here
because the *request* owns its lifetime (rollback on error, rollback-and-log on an uncommitted exit,
always closed — see ``get_session``), and it is passed down because the *service* owns the work.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.session import get_session

#: One ``Session`` per request, closed when the request ends and never committed by the dependency.
#:
#: Overridable in tests with ``app.dependency_overrides[get_session]`` — which works because the
#: override is keyed on the callable this alias wraps, not on the alias. That is also why there is no
#: second session dependency anywhere: two callables would mean two override keys and endpoints that
#: silently keep using the one a test forgot to replace.
SessionDep = Annotated[Session, Depends(get_session)]

__all__ = ["SessionDep"]
