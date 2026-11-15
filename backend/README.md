# TruthLens X — backend

FastAPI application for a self-hosted forensic evidence-analysis platform.

**Milestone status: M1 (foundation).** What is implemented here is the platform's *spine* —
configuration, logging, the error model, middleware and health probes. There is **no database
schema, no authentication, no case management and no forensic capability**. Evidence ingest begins
at M5. See [`../docs/IMPLEMENTATION_ROADMAP.md`](../docs/IMPLEMENTATION_ROADMAP.md).

## Layout

```
app/
├── core/
│   ├── config.py               # fail-closed settings; one validation rule per ratified decision
│   ├── logging.py              # structlog pipeline with redaction as the LAST processor
│   ├── errors.py               # stable error codes + RFC 9457 problem documents
│   ├── middleware.py           # request-id normalisation, security headers, access log
│   ├── health.py               # liveness (never fails) + readiness (fail-closed registry)
│   └── exception_handlers.py   # every non-2xx response is application/problem+json
├── api/v1/system.py            # /healthz, /readyz, /api/v1/status
└── main.py                     # create_app() factory with fail-closed lifespan startup
tests/
├── unit/                       # config policy, redaction, error model, health, middleware
├── contract/                   # the M1 endpoints and the OpenAPI guarantees
└── security/                   # cross-module leakage assertions (ADR-backed)
```

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'        # add ,[db] for the PostgreSQL driver

pytest                         # 329 tests
ruff check app tests
ruff format --check app tests
mypy app tests                 # strict
```

`pip install -e '.[db]'` is required for the database readiness probe to report anything other than
"driver not installed"; without it the probe degrades honestly rather than failing.

## Running

```bash
uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
```

The `--factory` flag is **required**. There is deliberately no module-level `app` object: constructing
one at import time would validate configuration as a side effect of importing, which makes the module
unimportable in any environment whose ambient variables are invalid. Configuration is validated when
the server starts, in each worker.

Startup is **fail-closed**: invalid configuration raises `ConfigurationError` and the process exits
rather than serving with a weakened policy. Every rule names the ADR or security requirement it
enforces. Copy [`../.env.example`](../.env.example) to `.env` for the full variable reference — 239
variables, none with a real value.

## Endpoints (M1)

| Path | Purpose |
|---|---|
| `GET /healthz` | Liveness. Returns 200 whenever the process can serve, even with every dependency down. |
| `GET /readyz` | Readiness. 200 when required dependencies answer; otherwise **503** with a `report` naming each failing check. |
| `GET /api/v1/status` | Build/version, milestone honesty, and which secrets are configured — **names and booleans only, never values**. |

The OpenAPI document carries **no `license` and no `contact` field**, because the repository is
deliberately unlicensed ([ADR-0008](../docs/adr/ADR-0008-repository-remains-unlicensed.md)). A
contract test asserts this, so it cannot be added by accident.

## Non-negotiables encoded here

* **Redaction runs last** in the logging pipeline, so it sees the fully assembled event including
  exception text. Sensitive key names are matched at *every* nesting depth; `bytes` and
  binary-looking strings are replaced with a length, never rendered.
* **`audit_reason` and `context` cannot reach a client.** `ProblemDetail` has no field for either —
  leaking them would require changing the model, not a careless call.
* **Case-access denial is 404 `NOT_FOUND`** to the client while the server records
  `FORBIDDEN_CASE_ACCESS` in the audit log ([ADR-0004](../docs/adr/ADR-0004-single-organisation-capability-rbac.md)).
* **`ALPR_ALLOW_REGISTRY_LOOKUP=true` is refused in every environment**, including development
  ([ADR-0013](../docs/adr/ADR-0013-alpr-no-default-formats-no-registry.md)).
* **External AI requires four independent switches plus a real key**, and never falls back to a cloud
  provider automatically ([ADR-0021](../docs/adr/ADR-0021-ai-egress-minimisation-no-fallback.md)).
* **`RETENTION_STATUTORY_DAYS` has no default.** Unset means retention jobs delete nothing and the
  admin dashboard warns persistently ([ADR-0020](../docs/adr/ADR-0020-retention-defaults-operator-specified.md)).
