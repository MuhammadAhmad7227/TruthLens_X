from contextlib import asynccontextmanager
import uuid
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from structlog.contextvars import bind_contextvars, clear_contextvars
from .core.config import get_settings
from .core.errors import AppError, app_error_handler
from .core.logging import configure_logging
from sqlalchemy import create_engine, text

@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    structlog.get_logger().info("application_started", environment=settings.environment)
    yield
    structlog.get_logger().info("application_stopped")

def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
    app.add_exception_handler(AppError, app_error_handler)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        clear_contextvars()
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        bind_contextvars(request_id=request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.get("/healthz", tags=["health"])
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    async def readyz():
        # M1 readiness is process-level; dependency checks arrive with M2/M7.
        return {"status": "ready"}

    @app.get(f"{settings.api_prefix}/status", tags=["system"])
    async def status():
        return {"service": "truthlens-x-api", "version": "0.1.0", "status": "ok"}

    return app

app = create_app()
