"""FastAPI application factory with structured logging."""
from __future__ import annotations

import structlog
from fastapi import FastAPI

from app.middleware.rate_limit import RateLimitMiddleware
from app.routes.api import router as api_router
from app.routes.pages import router as pages_router

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(title="WarpGen - WARP Configuration Generator")
    application.add_middleware(RateLimitMiddleware)
    application.include_router(api_router)
    application.include_router(pages_router)
    return application


app = create_app()
