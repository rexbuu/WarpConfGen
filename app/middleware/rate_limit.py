"""Rate limiting middleware for FastAPI."""
from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
import time

import structlog
from fastapi import Request
from fastapi.responses import PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings

logger = structlog.get_logger()

_rate_limit_lock = Lock()
_rate_limit_buckets: defaultdict[str, deque] = defaultdict(deque)


def get_client_ip(request: Request) -> str:
    """Extract client IP from request headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter by client IP."""

    PROTECTED_PATHS = {"/", "/api/generate", "/api/scan"}

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if request.url.path not in self.PROTECTED_PATHS:
            return await call_next(request)

        client_ip = get_client_ip(request)
        now = time.time()

        with _rate_limit_lock:
            bucket = _rate_limit_buckets[client_ip]
            while bucket and bucket[0] <= now - settings.rate_limit_window_seconds:
                bucket.popleft()
            if len(bucket) >= settings.rate_limit_max_requests:
                logger.warning("rate_limit_exceeded", client_ip=client_ip)
                return PlainTextResponse("Too many requests", status_code=429)
            bucket.append(now)

        return await call_next(request)
