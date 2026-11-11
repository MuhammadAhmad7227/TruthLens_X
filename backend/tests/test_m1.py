from fastapi.testclient import TestClient
from app.main import create_app

client = TestClient(create_app())

def test_healthz(): assert client.get("/healthz").status_code == 200
def test_healthz_body(): assert client.get("/healthz").json()["status"] == "ok"
def test_readyz(): assert client.get("/readyz").status_code == 200
def test_readyz_body(): assert client.get("/readyz").json()["status"] == "ready"
def test_status(): assert client.get("/api/v1/status").status_code == 200
def test_status_service(): assert client.get("/api/v1/status").json()["service"] == "truthlens-x-api"
def test_request_id_is_returned(): assert client.get("/healthz", headers={"X-Request-ID":"m1-test"}).headers["X-Request-ID"] == "m1-test"
def test_request_id_is_generated(): assert client.get("/healthz").headers.get("X-Request-ID")
def test_problem_media_type(): 
    from app.core.errors import AppError
    from fastapi import FastAPI
    a = FastAPI()
    from app.core.errors import app_error_handler
    a.add_exception_handler(AppError, app_error_handler)
    @a.get("/boom")
    async def boom(): raise AppError("TEST", "bad request")
    c = TestClient(a)
    assert c.get("/boom").headers["content-type"].startswith("application/problem+json")
def test_production_secret_guard(monkeypatch):
    from app.core.config import Settings
    from pydantic import SecretStr
    s = Settings(environment="production", secret_key=SecretStr("dev-only-change-me"))
    try: s.validate_security()
    except RuntimeError: return
    assert False, "production must reject the development secret"
