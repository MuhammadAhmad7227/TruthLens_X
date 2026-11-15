"""The request-scoped session dependency, from the API side.

``tests/db/test_session.py`` covers what ``get_session`` *does* — rollback on error, rollback-and-log
on an uncommitted exit, always closed, never committed — against a real PostgreSQL server. Nothing
here repeats that, because there is only one implementation and it is already tested where it lives.

What is left, and what only an API-layer test can see, is the wiring: that the alias routers declare
wraps that exact function and not a copy of it, that FastAPI resolves it, and that one request gets
one session rather than one per declaration. Those are the properties that break silently. A second
session dependency, or an alias around a wrapper lambda, would leave ``dependency_overrides`` keyed
on a callable no endpoint uses — and every test would keep passing while exercising a different
session from the one the application creates.
"""

from __future__ import annotations

from typing import Annotated, Any, Final, cast, get_args

import pytest
from fastapi import Depends, FastAPI
from fastapi.params import Depends as DependsParam
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.deps import SessionDep
from app.db.session import get_session

#: What the override returns. Not a ``Session``: nothing here may reach a database, and a stand-in
#: that is obviously not one makes a test that accidentally used the real dependency fail loudly
#: instead of connecting.
SENTINEL: Final[str] = "the-session-this-request-was-given"


def _dependency_of(alias: Any) -> Any:
    """The callable an ``Annotated[..., Depends(f)]`` alias wraps."""
    args = get_args(alias)
    assert len(args) == 2, f"{alias} is not an Annotated dependency alias"
    depends = args[1]
    # ``fastapi.params.Depends``, the class, rather than ``fastapi.Depends`` — the public name is a
    # factory function, so it is what a route declares with but not what ``isinstance`` can narrow to.
    assert isinstance(depends, DependsParam), f"{alias} wraps {depends!r}, not a Depends"
    return depends.dependency


def nested_session(session: SessionDep) -> Any:
    """A sub-dependency that asks for the session, as a service-facing helper would.

    Module scope, and that is load-bearing rather than tidy: this file has
    ``from __future__ import annotations``, so every annotation is a *string* that FastAPI resolves
    with ``typing.get_type_hints`` against the defining module's globals. A dependency function
    defined inside another function is not in those globals, the lookup fails, and FastAPI quietly
    reclassifies the parameter as a query parameter — the endpoint then answers 422 "field required"
    instead of receiving a session. Defining it here is what makes the resolution succeed; the trap
    itself is asserted in ``TestAnnotationResolution`` below, because a router that defines a local
    sub-dependency hits it in production and not only in tests.
    """
    return session


@pytest.fixture
def probe_app() -> FastAPI:
    """An app whose route declares ``SessionDep`` twice: once directly, once through a sub-dependency.

    Two declarations in one request is the shape a real endpoint has — a router and the helper it
    calls both ask for a session — and it is the shape that exposes a broken request scope.
    """
    application = FastAPI()

    @application.get("/probe")
    def probe(
        session: SessionDep,
        from_nested: Annotated[Any, Depends(nested_session)],
    ) -> dict[str, bool]:
        # ``cast`` because the override supplies a string where the annotation promises a Session,
        # and mypy is right that comparing the two is meaningless — which is the point of a sentinel.
        injected = cast("Any", session)
        return {
            "resolved": injected == SENTINEL,
            "nested_resolved": from_nested == SENTINEL,
            "one_session_per_request": injected is from_nested,
        }

    application.dependency_overrides[get_session] = lambda: SENTINEL
    return application


class TestTheAliasWrapsTheImplementation:
    def test_it_depends_on_get_session_itself(self) -> None:
        """Identity, not equivalence.

        ``dependency_overrides`` is keyed on the callable object, so an alias around anything else —
        a wrapper, a re-export, a second generator that happens to behave the same — would make every
        override in every test silently miss. Asserting ``is`` is what keeps the API's session and the
        tested session the same object.
        """
        assert _dependency_of(SessionDep) is get_session

    def test_it_declares_a_session(self) -> None:
        """The annotation is what a router's signature promises, and what a service receives."""
        assert get_args(SessionDep)[0] is Session

    def test_the_dependency_is_not_wrapped_in_a_request_scope_that_disables_caching(self) -> None:
        """``Depends(get_session, use_cache=False)`` would be a new session per declaration.

        Two sessions in one request means two transactions, and the append-only guarantees §4.1 relies
        on become a matter of which one committed last.
        """
        depends = get_args(SessionDep)[1]
        assert isinstance(depends, DependsParam)
        assert depends.use_cache is True


class TestRequestScope:
    def test_a_route_receives_the_session_the_override_supplied(self, probe_app: FastAPI) -> None:
        with TestClient(probe_app) as client:
            body = client.get("/probe").json()
        assert body["resolved"] is True, f"the route did not get the injected session: {body}"

    def test_one_request_gets_one_session_however_many_times_it_is_declared(
        self, probe_app: FastAPI
    ) -> None:
        """The request scope, observed rather than assumed.

        A sub-dependency declaring ``SessionDep`` must be handed the *same* object the route got. This
        is the property that makes "the service and the router share one transaction" true, and it is
        invisible in the type: both signatures look identical whether caching is on or off.
        """
        with TestClient(probe_app) as client:
            body = client.get("/probe").json()
        assert body["nested_resolved"] is True, f"the sub-dependency got something else: {body}"
        assert body["one_session_per_request"] is True, (
            "two declarations in one request resolved to two different sessions"
        )


class TestAnnotationResolution:
    def test_a_locally_defined_dependency_is_not_resolvable_under_pep_563(self) -> None:
        """The trap ``nested_session``'s module scope exists to avoid, pinned so it cannot be
        "simplified" back into a closure.

        With ``from __future__ import annotations`` every annotation is a string, and FastAPI resolves
        it against the *defining module's* globals. A dependency defined inside a function or fixture
        is a local, the lookup raises ``NameError``, and FastAPI's fallback is not an error — it
        reclassifies the parameter as a query parameter. The endpoint then fails with 422 at request
        time, which reads like a client bug and points nowhere near the real cause.

        Asserted as behaviour rather than as a code-reading exercise: build the same route with a
        closure as the dependency and confirm the request is refused.
        """
        application = FastAPI()

        def closure_dependency(session: SessionDep) -> Any:
            return session

        @application.get("/closure")
        def closure_route(
            from_closure: Annotated[Any, Depends(closure_dependency)],
        ) -> dict[str, bool]:
            return {"resolved": from_closure == SENTINEL}

        application.dependency_overrides[get_session] = lambda: SENTINEL

        with TestClient(application, raise_server_exceptions=False) as client:
            response = client.get("/closure")

        assert response.status_code == 422, (
            f"expected the closure dependency to be misresolved as a query parameter, got "
            f"{response.status_code}: {response.text}"
        )
        assert response.json()["detail"][0]["loc"] == ["query", "from_closure"]

    def test_the_module_scope_version_of_the_same_route_resolves(self, probe_app: FastAPI) -> None:
        """The control for the test above: same shape, dependency at module scope, request succeeds.

        Without this the previous test would also pass if ``SessionDep`` simply never worked.
        """
        with TestClient(probe_app) as client:
            assert client.get("/probe").status_code == 200
