from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.auth.router import router as auth_router
from app.core.config import settings
from app.core.exceptions import (
    AppException,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.db.session import engine

APP_VERSION = "0.1.0"

EXCEPTION_STATUS_CODES: tuple[tuple[type[AppException], int], ...] = (
    (NotFoundError, 404),
    (ConflictError, 409),
    (UnauthorizedError, 401),
    (ForbiddenError, 403),
    (ValidationError, 422),
)


def get_exception_status_code(exc: AppException) -> int:
    """Resolve the HTTP status code for a domain exception."""
    for exception_type, status_code in EXCEPTION_STATUS_CODES:
        if isinstance(exc, exception_type):
            return status_code
    return 500


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Verify database connectivity when the application starts."""
    async with engine.begin() as connection:
        await connection.execute(text("SELECT 1"))
    yield


async def app_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Return domain errors using a stable error envelope."""
    app_exc = cast(AppException, exc)
    return JSONResponse(
        status_code=get_exception_status_code(app_exc),
        content={"error": {"code": app_exc.code, "message": app_exc.message}},
    )


async def http_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Return HTTP errors using the same stable error envelope."""
    http_exc = cast(HTTPException, exc)
    message = http_exc.detail if isinstance(http_exc.detail, str) else "HTTP error."
    code = "HTTP_ERROR"
    if http_exc.status_code == 401:
        code = "UNAUTHORIZED"
    elif http_exc.status_code == 403:
        code = "FORBIDDEN"
    elif http_exc.status_code == 404:
        code = "NOT_FOUND"

    return JSONResponse(
        status_code=http_exc.status_code,
        content={"error": {"code": code, "message": message}},
        headers=http_exc.headers,
    )


async def validation_exception_handler(
    _request: Request,
    _exc: Exception,
) -> JSONResponse:
    """Return request validation errors using a stable error envelope."""
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed.",
            }
        },
    )


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    fastapi_app = FastAPI(
        title=settings.APP_NAME,
        debug=settings.DEBUG,
        version=APP_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    fastapi_app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    fastapi_app.add_exception_handler(AppException, app_exception_handler)
    fastapi_app.add_exception_handler(HTTPException, http_exception_handler)
    fastapi_app.add_exception_handler(RequestValidationError, validation_exception_handler)
    fastapi_app.include_router(auth_router)

    @fastapi_app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": APP_VERSION}

    return fastapi_app


app = create_app()
