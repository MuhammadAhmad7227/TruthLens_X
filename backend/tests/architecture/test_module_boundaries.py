"""Enforce the module boundary rules of `docs/SYSTEM_ARCHITECTURE.md` §4.1.

§4.1 closes with the sentence that matters: *"Violations fail CI. This is what keeps the
'modular architecture' rule true over time rather than only at the start."* This module is
that enforcement. Without it the boundaries are documentation, and documentation loses to
deadlines.

Why this is hand-written AST analysis rather than `import-linter`
-----------------------------------------------------------------
§4.1 names `import-linter` as the intended tool, and it would do this job well. It is
deliberately **not** a dependency here, for a reason that is specific to this repository:
`import-linter` depends on `grimp`, so adopting it adds a third-party package to the graph
that `pip-audit` scans in CI and that the licence gate in `.github/workflows/security.yml`
reasons about (ADR-0001 — the default dependency set stays permissive). Spending a
dependency, an audit surface and a licence review on a check that the standard library can
perform is a bad trade while the rule count is six and the module count is in the dozens.

So the rules are expressed as data (``BOUNDARY_RULES``) and interpreted by a small
stdlib-only scanner. The table is intentionally shaped like an `import-linter` contract —
one entry per forbidden direction, each with its own reason — so that migrating later is a
mechanical translation of the table rather than a redesign of the check.

Two properties a boundary test must have, and how this one gets them
--------------------------------------------------------------------
*A boundary test that has never been seen to fail is not evidence of anything.* Most of the
packages these rules protect (``app.models``, ``app.services``, ``app.repositories``,
``app.forensics``) do not exist yet, so today the rules pass over empty sets — vacuously.
The synthetic-tree tests at the bottom build throwaway packages under ``tmp_path`` that
violate each rule and assert the scanner reports them, which proves the machinery works
before the code it will police arrives.

*A rule table that only covers today's packages rots silently.* Adding ``app/models`` with
no rule mentioning it would leave the new package unpoliced while the suite stayed green.
``test_every_existing_package_is_accounted_for`` fails in that case, forcing whoever adds a
package to say, in writing, which rule covers it.

Exemptions are declared, not discovered
---------------------------------------
``app`` and ``app.main`` are the composition root: wiring every layer together is their
entire job, so they are exempt from the rules that keep the layers apart. ``app.core`` may
import ``app.db`` because ``app/core/health.py`` probes the database to answer ``/readyz`` —
without that, readiness cannot report the thing operators most need to know. Both exemptions
are named in the table with a reason, so a reviewer can disagree with them explicitly
instead of finding them by accident in a stack trace.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

import pytest

# tests/architecture/test_module_boundaries.py -> architecture -> tests -> backend -> repo root
REPO_ROOT: Final = Path(__file__).resolve().parents[3]
BACKEND_ROOT: Final = REPO_ROOT / "backend"
AI_SERVICES_ROOT: Final = REPO_ROOT / "ai_services"

#: Modules exempt from every rule, with the reason. The composition root's job is to wire the
#: layers together, so the rules that keep them apart cannot apply to it.
EXEMPT: Final[dict[str, str]] = {
    "app": "package marker for the composition root",
    "app.main": "composition root: building the app from every layer is its only job",
}

#: Top-level packages that are not production code and therefore not subject to layering rules.
NOT_PRODUCTION_CODE: Final[frozenset[str]] = frozenset({"tests"})


@dataclass(frozen=True, slots=True)
class BoundaryRule:
    """One forbidden import direction from SYSTEM_ARCHITECTURE §4.1.

    ``module_prefix`` selects the modules the rule governs; ``forbidden`` lists the prefixes
    they must not import. ``allowed`` carves out a specific, reasoned exception — an entry
    there is a decision, and the reason is part of the rule so the decision is reviewable.
    """

    name: str
    rule_number: int
    module_prefix: str
    forbidden: tuple[str, ...]
    reason: str
    source: Path
    allowed: tuple[str, ...] = ()
    allowed_because: str = ""


def _rule(
    *,
    name: str,
    rule_number: int,
    module_prefix: str,
    forbidden: tuple[str, ...],
    reason: str,
    source: Path,
    allowed: tuple[str, ...] = (),
    allowed_because: str = "",
) -> BoundaryRule:
    """Build a rule, keeping the table below readable as prose."""
    return BoundaryRule(
        name=name,
        rule_number=rule_number,
        module_prefix=module_prefix,
        forbidden=forbidden,
        reason=reason,
        source=source,
        allowed=allowed,
        allowed_because=allowed_because,
    )


BOUNDARY_RULES: Final[tuple[BoundaryRule, ...]] = (
    _rule(
        name="api routers stay thin",
        rule_number=1,
        module_prefix="app.api",
        forbidden=("app.models", "app.repositories"),
        reason=(
            "§4.1(1): routers validate, call a service, and map to a schema. Importing models or "
            "repositories puts persistence and ORM objects in the request path, where a session "
            "boundary or an authorisation decision made in a router cannot be reused by a worker."
        ),
        source=BACKEND_ROOT,
    ),
    _rule(
        name="services own the rules",
        rule_number=2,
        module_prefix="app.services",
        forbidden=("app.api",),
        reason=(
            "§4.1(2): services own transactions and authorisation decisions. Importing the API "
            "inverts the dependency, so business rules could only be exercised through HTTP and "
            "a Celery task could never reuse them."
        ),
        source=BACKEND_ROOT,
    ),
    _rule(
        name="repositories only reach models",
        rule_number=3,
        module_prefix="app.repositories",
        forbidden=("app.api", "app.services", "app.tasks", "app.forensics", "app.reporting"),
        reason=(
            "§4.1(3): a repository is a persistence adapter. If it can call a service it can start "
            "a transaction inside someone else's transaction, and the custody ledger's "
            "append-only guarantees become a matter of luck rather than of structure."
        ),
        source=BACKEND_ROOT,
    ),
    _rule(
        name="forensics resolves engines through the registry",
        rule_number=4,
        module_prefix="app.forensics",
        forbidden=("engines", "ai_services"),
        reason=(
            "§4.1(4): forensics orchestrates; it does not import engine implementations. Engines "
            "are resolved through the registry, and the registry is imported by worker code, never "
            "by the API process. A direct import here would load model code — and its "
            "dependencies, and possibly its weights — into the API process that must stay able to "
            "serve and hash evidence without them."
        ),
        source=BACKEND_ROOT,
    ),
    _rule(
        name="core imports nothing from the application",
        rule_number=6,
        module_prefix="app.core",
        forbidden=(
            "app.api",
            "app.services",
            "app.repositories",
            "app.models",
            "app.forensics",
            "app.tasks",
            "app.reporting",
        ),
        reason=(
            "§4.1(6): core is configuration, logging, errors and health — the layer everything "
            "else depends on. An import back up from core creates a cycle that is invisible until "
            "the first import-order bug, and makes core untestable on its own."
        ),
        source=BACKEND_ROOT,
        allowed=("app.db",),
        allowed_because=(
            "app/core/health.py probes the database to answer /readyz. Readiness that cannot see "
            "the database would report healthy while evidence writes were failing, which is worse "
            "than not reporting at all. The dependency is a probe, not a query."
        ),
    ),
    _rule(
        name="db provides sessions, not queries",
        rule_number=7,
        module_prefix="app.db",
        forbidden=(
            "app.models",
            "app.repositories",
            "app.services",
            "app.api",
            "app.tasks",
            "app.forensics",
            "app.reporting",
        ),
        reason=(
            "§4.1(7): this layer hands out engines, sessions and transaction helpers. Models import "
            "the declarative base from here, so an import back is a cycle — and the cycle is not "
            "the worst part. Domain knowledge in the layer everything depends on means a worker "
            "cannot open a session without importing the schema, and the session helpers cannot be "
            "tested without a database that has the tables in them."
        ),
        source=BACKEND_ROOT,
    ),
    _rule(
        name="models declare the schema and nothing else",
        rule_number=8,
        module_prefix="app.models",
        forbidden=(
            "app.repositories",
            "app.services",
            "app.api",
            "app.tasks",
            "app.forensics",
            "app.reporting",
        ),
        reason=(
            "§4.1(8): a model has no session, so it cannot run a query, own a transaction or make an "
            "authorisation decision. Importing a service to do one of those would move the decision "
            "into a class declaration, where it runs at import time or not at all — and rule 3 says "
            "repositories import models, so the dependency would close a cycle through the "
            "persistence layer."
        ),
        source=BACKEND_ROOT,
        allowed=("app.db",),
        allowed_because=(
            "The declarative base, the timestamp and soft-delete mixins and the column types live in "
            "app.db. That import is the reason the models share one metadata object, one naming "
            "convention and one timestamptz type — which is what makes `alembic check` able to "
            "compare them against a migrated database at all."
        ),
    ),
    _rule(
        name="tasks never import the HTTP layer",
        rule_number=9,
        module_prefix="app.tasks",
        forbidden=("app.api",),
        reason=(
            "§4.1 async workers execute business services outside the HTTP process. A task importing "
            "routers would make queue execution depend on request wiring and create a second, unsafe "
            "authorization path."
        ),
        source=BACKEND_ROOT,
    ),
    _rule(
        name="ai_services never imports the backend",
        rule_number=5,
        module_prefix="engines",
        forbidden=("app", "backend"),
        reason=(
            "§4.1(5): ai_services must not import backend/app. The only coupling is the result "
            "contract, so engines stay independently testable and independently releasable. An "
            "engine that imports the backend cannot run in a GPU worker without dragging the API's "
            "dependency graph — and its attack surface — along with it."
        ),
        source=AI_SERVICES_ROOT,
    ),
)


def _within(candidate: str, prefix: str) -> bool:
    """True when ``candidate`` is ``prefix`` or a submodule of it.

    Matching on the dotted boundary rather than on a string prefix is what keeps this honest:
    a plain ``candidate.startswith("app")`` would condemn ``appdirs``, ``applicationinsights``
    and every other legitimate third-party package whose name happens to begin with those
    letters. A false positive here teaches people to ignore the check, which is how a real
    boundary test dies.
    """
    return candidate == prefix or candidate.startswith(prefix + ".")


def _package_of(module: str, *, is_init: bool) -> str:
    """The package a relative import is resolved against."""
    return module if is_init else module.rpartition(".")[0]


def _resolve_relative(package: str, level: int) -> str:
    """Resolve ``level`` dots against ``package`` the way the interpreter does."""
    parts = package.split(".") if package else []
    climb = level - 1
    if climb > len(parts):
        return ""
    return ".".join(parts[: len(parts) - climb] if climb else parts)


def collect_imports(path: Path, module: str) -> frozenset[str]:
    """Every absolute module name ``path`` imports, relative imports resolved.

    Relative imports must be resolved, not skipped: ``from ..services import case`` inside
    ``app/api/v1/router.py`` is exactly the violation rule 2 exists to catch, and it does not
    mention ``app.services`` anywhere in the source text. A checker that only matched literal
    dotted strings would miss the most natural way to write the offence.

    Both the imported module and each ``module.name`` combination are reported, so
    ``from app import models`` is caught as ``app.models`` and not waved through as ``app``.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _package_of(module, is_init=path.name == "__init__.py")
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                anchor = _resolve_relative(package, node.level)
                if anchor and node.module:
                    base = f"{anchor}.{node.module}"
                elif anchor:
                    base = anchor
            if not base:
                continue
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names)
    return frozenset(found)


def iter_modules(rule: BoundaryRule) -> tuple[tuple[str, Path], ...]:
    """The modules a rule governs: everything under its prefix, skipping non-production code."""
    root = rule.source / Path(*rule.module_prefix.split(".")) if rule.module_prefix else rule.source
    if not root.is_dir():
        return ()
    modules: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(rule.source)
        parts = list(relative.parts)
        if parts[-1] == "__init__.py":
            parts.pop()
        else:
            parts[-1] = path.stem
        module = ".".join(parts)
        if module.split(".")[0] in NOT_PRODUCTION_CODE or module in EXEMPT:
            continue
        modules.append((module, path))
    return tuple(modules)


def violations(rule: BoundaryRule) -> tuple[str, ...]:
    """Every import that breaks ``rule``, as ``"<module> imports <target>"``.

    ``collect_imports`` reports both the module a ``from`` statement names and each
    ``module.symbol`` it pulls, because ``from app import models`` has to be caught as
    ``app.models``. That makes the raw set redundant — one offending statement yields several
    matching targets — so one representative is reported per module *per forbidden prefix*:
    the most general match, which is the actual module rather than a symbol inside it.
    """
    reported: list[str] = []
    for module, path in iter_modules(rule):
        targets = collect_imports(path, module)
        for banned in rule.forbidden:
            matching = [
                target
                for target in targets
                if _within(target, banned)
                and not any(_within(target, permitted) for permitted in rule.allowed)
            ]
            if matching:
                general = min(matching, key=lambda target: (len(target), target))
                reported.append(f"{module} imports {general}")
    return tuple(sorted(reported))


@pytest.mark.parametrize(
    "rule",
    BOUNDARY_RULES,
    ids=[entry.name for entry in BOUNDARY_RULES],
)
def test_boundary_rule_holds(rule: BoundaryRule) -> None:
    """Each §4.1 rule must hold across the real source tree.

    The failure message carries the rule's own reason and, where the rule has an exemption, the
    justification for it — so a developer who trips the check learns the decision on the spot
    instead of having to go and find the architecture document.
    """
    found = violations(rule)
    detail = f"\n  §4.1({rule.rule_number}) {rule.name}: {rule.reason}"
    if rule.allowed:
        detail += f"\n  Declared exemption {rule.allowed}: {rule.allowed_because}"
    detail += "\n  If a rule is genuinely wrong, change BOUNDARY_RULES and say why in the commit."
    assert not found, (
        f"{len(found)} boundary violation(s):\n" + "\n".join(f"  - {v}" for v in found) + detail
    )


def test_the_engine_package_exists_and_is_being_policed() -> None:
    """Rule 5 must be scanning something real.

    ``ai_services`` installs as a top-level ``engines`` package. If it were ever renamed or
    moved, ``iter_modules`` would return an empty tuple and the rule would keep passing while
    policing nothing — a green build with no coverage. This asserts the package is there and
    that the scanner actually finds modules in it.
    """
    engines = AI_SERVICES_ROOT / "engines"
    assert engines.is_dir(), f"{engines} is missing; rule 5 would pass vacuously"
    rule = next(r for r in BOUNDARY_RULES if r.name == "ai_services never imports the backend")
    scanned = iter_modules(rule)
    assert scanned, f"no modules found under {engines}; rule 5 would pass vacuously"
    assert any(module == "engines.base" for module, _ in scanned), (
        "engines.base was not scanned — the module-name derivation is wrong, so every rule "
        f"in this file is untrustworthy. Scanned: {sorted(m for m, _ in scanned)}"
    )


def test_main_does_not_build_the_app_at_import_time() -> None:
    """``app.main`` exposes a factory, never a module-level ``app``.

    A module-level ``app`` is picked up implicitly by ``uvicorn app.main:app``, which means
    importing the module constructs the whole application — settings loaded, middleware
    stacked, routes registered — before anything can configure it. The factory keeps
    construction explicit and testable, and the `ci-backend` smoke step
    (``from app.main import create_app; create_app()``) depends on that shape. This scans the
    AST rather than importing, so it cannot be satisfied by an import-time side effect.
    """
    main = BACKEND_ROOT / "app" / "main.py"
    assert main.is_file(), f"{main} is missing"
    tree = ast.parse(main.read_text(encoding="utf-8"), filename=str(main))
    offenders: list[str] = []
    for node in tree.body:  # module level only — a local variable named `app` is fine
        if isinstance(node, ast.Assign):
            offenders.extend(
                t.id for t in node.targets if isinstance(t, ast.Name) and t.id == "app"
            )
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "app"
        ):
            offenders.append(node.target.id)
    assert not offenders, (
        f"app/main.py defines a module-level {offenders}; expose create_app() instead so nothing "
        "is constructed at import time"
    )


def test_every_existing_package_is_accounted_for() -> None:
    """A new package must arrive with a rule that covers it.

    This is the check that keeps the table from rotting. Adding ``app/models`` or
    ``ai_services/models`` without extending ``BOUNDARY_RULES`` would leave it unpoliced while
    every other test stayed green — the quietest possible way to lose an architecture.

    ``accounted`` is a named predicate rather than an inline ``or``-chain on purpose: a
    comprehension filter written as ``... or any(...) is False`` parses as
    ``... or (any(...) is False)`` and silently inverts itself, which is the kind of bug that
    makes a guard pass for the wrong reason.
    """

    def accounted(module: str) -> bool:
        if module in EXEMPT:
            return True
        if module.split(".")[0] in NOT_PRODUCTION_CODE:
            return True
        return any(_within(module, rule.module_prefix) for rule in BOUNDARY_RULES)

    existing: list[str] = []
    for child in sorted((BACKEND_ROOT / "app").iterdir()):
        if child.is_dir() and (child / "__init__.py").is_file():
            existing.append(f"app.{child.name}")
        elif child.suffix == ".py" and child.name != "__init__.py":
            existing.append(f"app.{child.stem}")
    for child in sorted(AI_SERVICES_ROOT.iterdir()):
        if child.is_dir() and (child / "__init__.py").is_file():
            existing.append(child.name)
        elif child.suffix == ".py" and child.name != "__init__.py":
            existing.append(child.stem)

    assert existing, "no packages discovered at all — the paths in this test are wrong"
    unaccounted = [module for module in existing if not accounted(module)]
    assert not unaccounted, (
        f"{unaccounted} exist but no BOUNDARY_RULES entry governs them. Add a rule (and its "
        "reason) or list the module in EXEMPT with a justification. An ungoverned package is "
        "not a gap you can see from the test output alone."
    )


# ── Anti-vacuity: prove the scanner fails when it should ───────────────────────────────────
#
# Every rule above currently passes over packages that do not exist yet, so on its own the
# suite proves nothing about the scanner. These tests build throwaway trees under tmp_path and
# point a *real* rule at them — only ``source`` is replaced, via ``dataclasses.replace``, so
# the code under test is the same code that polices the repository.


def _write_module(root: Path, module: str, body: str = "") -> None:
    """Create ``module`` as a real file under ``root``, with package ``__init__.py`` files."""
    parts = module.split(".")
    target = root.joinpath(*parts).with_suffix(".py")
    target.parent.mkdir(parents=True, exist_ok=True)
    for depth in range(1, len(parts)):
        marker = root.joinpath(*parts[:depth]) / "__init__.py"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch(exist_ok=True)
    target.write_text(body, encoding="utf-8")


def _source_root_for(rule: BoundaryRule, tmp_path: Path) -> Path:
    """The synthetic equivalent of a rule's real source root."""
    return tmp_path / rule.source.name


def test_the_checker_catches_a_core_module_reaching_into_the_api(tmp_path: Path) -> None:
    """§4.1(6): core must not import upward. Inject the violation and demand it is reported."""
    rule = next(r for r in BOUNDARY_RULES if r.name == "core imports nothing from the application")
    root = _source_root_for(rule, tmp_path)
    _write_module(root, "app.api.v1.router")
    _write_module(root, "app.core.health", "import app.api.v1.router\n")

    found = violations(replace(rule, source=root))

    assert "app.core.health imports app.api.v1.router" in found, (
        "the scanner stayed silent about a forbidden upward import, so every passing boundary "
        f"test in this file is vacuous. Reported: {found}"
    )


def test_the_checker_catches_a_relative_import_that_hides_the_layer(tmp_path: Path) -> None:
    """§4.1(2): the offence written the way people actually write it.

    ``from ..api.v1 import router`` never mentions ``app.api`` anywhere in the source text, so a
    checker that matched literal dotted strings would wave it through — and a relative import is
    the *most* natural way to reach a sibling layer from inside a package.
    """
    rule = next(r for r in BOUNDARY_RULES if r.name == "services own the rules")
    root = _source_root_for(rule, tmp_path)
    _write_module(root, "app.api.v1.router")
    _write_module(root, "app.services.case", "from ..api.v1 import router\n")

    found = violations(replace(rule, source=root))

    assert "app.services.case imports app.api.v1" in found, (
        "a relative import escaped the scanner, so every passing boundary test in this file is "
        f"weaker than it looks. Reported: {found}"
    )


def test_the_checker_catches_an_engine_importing_the_backend(tmp_path: Path) -> None:
    """§4.1(5): an engine reaching into the backend is the coupling that must never appear."""
    rule = next(r for r in BOUNDARY_RULES if r.name == "ai_services never imports the backend")
    root = _source_root_for(rule, tmp_path)
    _write_module(root, "engines.base", "from app.core.config import get_settings\n")

    found = violations(replace(rule, source=root))

    assert "engines.base imports app.core.config" in found, (
        "the scanner let an engine import the backend, which is the one boundary that keeps the "
        f"engine contract independently releasable. Reported: {found}"
    )


def test_the_checker_catches_a_repository_calling_a_service(tmp_path: Path) -> None:
    """§4.1(3): a repository that can call a service can open a transaction inside one."""
    rule = next(r for r in BOUNDARY_RULES if r.name == "repositories only reach models")
    root = _source_root_for(rule, tmp_path)
    _write_module(root, "app.services.case")
    _write_module(root, "app.repositories.evidence", "import app.services.case\n")

    found = violations(replace(rule, source=root))

    assert "app.repositories.evidence imports app.services.case" in found, (
        f"the scanner missed a repository calling a service. Reported: {found}"
    )


def test_the_dotted_boundary_does_not_condemn_a_similarly_named_package(tmp_path: Path) -> None:
    """A false positive is how a boundary check gets ignored, then deleted.

    ``appdirs`` and ``applicationinsights`` begin with ``app``; ``backend``'s rule must not
    reach them. This is the other half of the anti-vacuity argument: the scanner has to fire
    on real violations *and* stay quiet on legitimate third-party imports.
    """
    rule = next(r for r in BOUNDARY_RULES if r.name == "ai_services never imports the backend")
    root = _source_root_for(rule, tmp_path)
    _write_module(
        root,
        "engines.paths",
        "import appdirs\nimport applicationinsights\nfrom appconfig import load\n",
    )

    found = violations(replace(rule, source=root))

    assert not found, (
        "the scanner matched on a bare string prefix instead of the dotted boundary, so ordinary "
        f"third-party packages are condemned: {found}"
    )


def test_the_declared_exemption_is_narrow(tmp_path: Path) -> None:
    """The ``core -> app.db`` exemption must not become a hole the size of the application.

    ``app.db`` is allowed because health probes it. ``app.db.session`` sits under that dotted
    prefix and is therefore allowed too, which is intended. ``app.models`` is not, and must
    still be reported — otherwise the exemption would quietly widen into "core may import
    whatever it likes".
    """
    rule = next(r for r in BOUNDARY_RULES if r.name == "core imports nothing from the application")
    root = _source_root_for(rule, tmp_path)
    _write_module(root, "app.core.health", "import app.db.session\n")
    _write_module(root, "app.core.reporting", "import app.models.case\n")

    found = violations(replace(rule, source=root))

    assert "app.core.reporting imports app.models.case" in found, (
        f"the exemption swallowed a real violation. Reported: {found}"
    )
    assert not any("app.db" in entry for entry in found), (
        f"app.db is a declared exemption but was reported anyway: {found}"
    )
