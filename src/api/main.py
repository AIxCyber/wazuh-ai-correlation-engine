from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from src.core.metrics import api_request_duration
from slowapi.util import get_remote_address
from starlette.responses import Response

from src.api.middleware.rate_limit import PerRoleRateLimitMiddleware
from src.api.routes.incidents import router as incidents_router
from src.core.config import get_config
from src.core.database import init_db
from src.core.logging import get_logger, setup_logging

setup_logging()
logger = get_logger(__name__)

cfg = get_config()

burst_limit = cfg.rate_limit_burst
sustained_limit = cfg.rate_limit_per_minute
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{burst_limit}/minute"],
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    logger.info("starting_api", extra={"host": cfg.api_host, "port": cfg.api_port})
    init_db()
    yield


app = FastAPI(
    title="Wazuh AI Correlation Engine API",
    description="AI-Powered Security Incident Correlation & Response Platform for Wazuh SIEM",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(PerRoleRateLimitMiddleware)

origins = ["*"]
if cfg.jwt_secret != "change-me-in-production":
    origins = [f"http://{cfg.dashboard_host}:{cfg.dashboard_port}", f"http://localhost:{cfg.dashboard_port}"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    import time
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    api_request_duration.labels(
        endpoint=request.url.path, method=request.method, status=response.status_code,
    ).observe(duration)
    logger.info(
        "api_request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round(duration * 1000, 2),
        },
    )
    return response


app.include_router(incidents_router, prefix="/api/v1")


@app.get("/metrics")
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
def root():
    return {
        "service": cfg.app_name,
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health",
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_exception", extra={"path": request.url.path, "error": str(exc)})
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
