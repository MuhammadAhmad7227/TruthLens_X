from app.core.config import Settings
from app.core.errors import AppError, app_error_handler
from app.main import create_app
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr


client = TestClient(create_app())


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_healthz_body():
    assert client.get("/healthz").json()["status"] == "ok"


def test_readyz():
    assert client.get("/readyz").status_code == 200


def test_readyz_body():
    assert client.get("/readyz").json()["status"] == "ready"


def test_status():
    assert client.get("/api/v1/status").status_code == 200


def test_status_service():
    assert client.get("/api/v1/status").json()["service"] == "truthlens-x-api"


def test_request_id_is_returned():
    response = client.get("/healthz", headers={"X-Request-ID": "m1-test"})
    assert response.headers["X-Request-ID"] == "m1-test"


def test_request_id_is_generated():
    assert client.get("/healthz").headers.get("X-Request-ID")


def test_problem_media_type():
    app = FastAPI()
    app.add_exception_handler(AppError, app_error_handler)

    @app.get("/boom")
    async def boom():
        raise AppError("TEST", "bad request")

    response = TestClient(app).get("/boom")
    assert response.headers["content-type"].startswith("application/problem+json")


def test_production_secret_guard():
    settings = Settings(
        environment="production",
        secret_key=SecretStr("dev-only-change-me"),
    )

    try:
        settings.validate_security()
    except RuntimeError:
        return

    raise AssertionError("production must reject the development secret")
