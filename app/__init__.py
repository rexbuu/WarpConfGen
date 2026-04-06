"""FastAPI application factory with structured logging."""
from __future__ import annotations

import structlog
from fastapi import FastAPI

from app.middleware.rate_limit import RateLimitMiddleware
from app.routes.api import router as api_router
from app.routes.bot import router as bot_router
from app.routes.pages import router as pages_router, TEMPLATE_DIR

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
)


from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(title="WarpGen")
    
    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger = structlog.get_logger()
        logger.error("unhandled_exception", path=request.url.path, error=str(exc))
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "detail": str(exc)},
        )

    @application.get("/api/health")
    def health_check():
        return {"status": "ok", "templates": TEMPLATE_DIR}

    application.add_middleware(RateLimitMiddleware)
    application.include_router(api_router)
    application.include_router(bot_router)
    application.include_router(pages_router)
    return application


app = create_app()
