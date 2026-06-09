from __future__ import annotations

import time

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from src.api.middleware.auth import decode_token
from src.core.config import get_config
from src.core.logging import get_logger

logger = get_logger(__name__)


def _get_role_limits() -> dict[str | None, int]:
    cfg = get_config()
    return {
        "admin": cfg.rate_limit_admin,
        "senior_analyst": cfg.rate_limit_senior_analyst,
        "analyst": cfg.rate_limit_analyst,
        None: cfg.rate_limit_anonymous,
    }


BURST_MULTIPLIER: dict[str | None, float] = {
    "admin": 1.5,
    "senior_analyst": 1.33,
    "analyst": 1.5,
    None: 1.0,
}


class SlidingWindowCounter:
    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.entries: list[float] = []

    def allow(self) -> tuple[bool, int, float]:
        now = time.time()
        cutoff = now - self.window_seconds
        self.entries = [t for t in self.entries if t > cutoff]
        if len(self.entries) < self.limit:
            self.entries.append(now)
            remaining = self.limit - len(self.entries)
            reset_at = cutoff + self.window_seconds if self.entries else now + self.window_seconds
            return True, remaining, reset_at
        reset_at = self.entries[0] + self.window_seconds if self.entries else now + self.window_seconds
        return False, 0, reset_at


class PerRoleRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self: PerRoleRateLimitMiddleware, app: ASGIApp) -> None:
        super().__init__(app)
        self.counters: dict[str, SlidingWindowCounter] = {}
        self._last_cleanup: float = 0.0

    SKIP_PATHS = {"/metrics", "/health", "/ready", "/", "/docs", "/redoc", "/openapi.json", "/api/v1/health", "/api/v1/ready"}

    def _should_skip(self: PerRoleRateLimitMiddleware, request: Request) -> bool:
        return request.url.path in self.SKIP_PATHS or request.url.path.startswith(("/docs/", "/redoc/"))

    def _get_client_key(self: PerRoleRateLimitMiddleware, request: Request) -> tuple[str | None, str]:
        ip = request.client.host if request.client and request.client.host else "127.0.0.1"
        auth = request.headers.get("Authorization", "")
        role: str | None = None
        if auth.startswith("Bearer "):
            try:
                payload = decode_token(auth.split(" ", 1)[1])
                role = payload.get("role", "analyst")
            except Exception:
                role = None
        return role, ip

    def _get_counter(self: PerRoleRateLimitMiddleware, key: str, limit: int) -> SlidingWindowCounter:
        if key not in self.counters:
            self.counters[key] = SlidingWindowCounter(limit=limit)
        return self.counters[key]

    def _cleanup_stale(self: PerRoleRateLimitMiddleware) -> None:
        now = time.time()
        if now - self._last_cleanup < 300:
            return
        self._last_cleanup = now
        stale = [k for k, c in self.counters.items() if c.entries and (now - c.entries[-1]) > 600]
        for k in stale:
            del self.counters[k]

    async def dispatch(
        self: PerRoleRateLimitMiddleware,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        import os
        if self._should_skip(request) or os.getenv("APP_ENV") == "testing":
            return await call_next(request)
        role, ip = self._get_client_key(request)
        cfg = get_config()
        role_limits = _get_role_limits()
        limit = role_limits.get(role, role_limits[None])
        burst_mult = BURST_MULTIPLIER.get(role, BURST_MULTIPLIER[None])
        burst_limit = min(int(limit * burst_mult), cfg.rate_limit_burst)

        sustained_key = f"{role}:{ip}:sustained"
        burst_key = f"{role}:{ip}:burst"

        sustained_counter = self._get_counter(sustained_key, limit)
        burst_counter = self._get_counter(burst_key, burst_limit)

        allowed_sustained, sustained_remaining, sustained_reset = sustained_counter.allow()
        allowed_burst, burst_remaining, burst_reset = burst_counter.allow()

        is_allowed = allowed_sustained or allowed_burst
        remaining = max(sustained_remaining, burst_remaining) if is_allowed else 0
        reset_at = min(sustained_reset, burst_reset)

        headers: dict[str, str] = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Burst-Limit": str(burst_limit),
            "X-RateLimit-Remaining": str(max(0, remaining)),
            "X-RateLimit-Reset": str(int(reset_at)),
        }

        if not is_allowed:
            retry_after = int(reset_at - time.time())
            headers["Retry-After"] = str(max(1, retry_after))
            logger.warning(
                "rate_limit_exceeded",
                extra={"role": role, "ip": ip, "limit": limit, "burst": burst_limit},
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers=headers,
            )

        response = await call_next(request)
        for k, v in headers.items():
            response.headers[k] = v
        return response
