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

    # Path-specific rate limits (requests per window)
    LIMITS = {
        "/": 15,
        "/api/generate": 15,
        "/api/v2sub": 100,  # Higher limit for subscription syncs
    }

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        path = request.url.path
        
        # Check for exact match or prefix for /api/v2sub
        target_path = None
        if path in self.LIMITS:
            target_path = path
        elif path.startswith("/api/v2sub/"):
            target_path = "/api/v2sub"

        if not target_path:
            return await call_next(request)

        client_ip = get_client_ip(request)
        now = time.time()
        limit = self.LIMITS[target_path]

        with _rate_limit_lock:
            # Bucket per (client_ip, path) to allow separate limits
            bucket_key = f"{client_ip}:{target_path}"
            bucket = _rate_limit_buckets[bucket_key]
            while bucket and bucket[0] <= now - settings.rate_limit_window_seconds:
                bucket.popleft()
            
            if len(bucket) >= limit:
                logger.warning("rate_limit_exceeded", client_ip=client_ip, path=path)
                return PlainTextResponse("Too many requests", status_code=429)
            bucket.append(now)

        return await call_next(request)
