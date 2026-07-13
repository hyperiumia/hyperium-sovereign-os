"""Rate Limiting Middleware — Sliding window per-IP. Disabled by default, enable via SOVEREIGN_RATE_LIMIT."""
import os, time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

EXEMPT = ["/health", "/metrics", "/docs", "/openapi.json", "/redoc", "/static"]


class RateLimiter(BaseHTTPMiddleware):

    def __init__(self, app):
        super().__init__(app)
        self.hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request, call_next):
        rpm = int(os.getenv("SOVEREIGN_RATE_LIMIT", "0"))
        path = request.url.path

        if rpm <= 0 or path == "/" or any(path.startswith(p) for p in EXEMPT):
            resp = await call_next(request)
            if rpm > 0:
                resp.headers["X-RateLimit-Limit"] = str(rpm)
            return resp

        client = request.client.host if request.client else "unknown"
        now = time.time()
        cutoff = now - 60
        self.hits[client] = [t for t in self.hits[client] if t > cutoff]
        current = len(self.hits[client])

        if current >= rpm:
            retry = int(self.hits[client][0] + 60 - now) + 1
            r = JSONResponse(status_code=429,
                             content={"detail": "Rate limit exceeded", "retry_after": retry})
            r.headers["Retry-After"] = str(retry)
            r.headers["X-RateLimit-Limit"] = str(rpm)
            r.headers["X-RateLimit-Remaining"] = "0"
            return r

        self.hits[client].append(now)
        resp = await call_next(request)
        resp.headers["X-RateLimit-Limit"] = str(rpm)
        resp.headers["X-RateLimit-Remaining"] = str(max(0, rpm - current - 1))
        resp.headers["X-RateLimit-Reset"] = str(int(now + 60))
        return resp
