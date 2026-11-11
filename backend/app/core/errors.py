from fastapi import Request
from fastapi.responses import JSONResponse

class AppError(Exception):
    def __init__(self, code: str, detail: str, status_code: int = 400) -> None:
        self.code, self.detail, self.status_code = code, detail, status_code
        super().__init__(detail)

async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": "about:blank",
            "title": exc.code,
            "status": exc.status_code,
            "detail": exc.detail,
        },
        media_type="application/problem+json",
    )
