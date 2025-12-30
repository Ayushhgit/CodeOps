"""
CodeOps AI — GitHub-Native AI Engineering Copilot

Main FastAPI application entry point.

This system operates with the following priorities (in order):
1. Trust
2. Safety
3. Auditability
4. Business risk reduction
5. Speed (last)
"""

from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api import router
from app.api.middleware import (
    CorrelationIdMiddleware,
    InputValidationMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    get_correlation_id,
)
from app.core.config import settings


# Configure structured logging with correlation ID support
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,  # Merge correlation ID from context
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer() if settings.is_production else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager."""
    logger.info(
        "Starting CodeOps AI",
        version=__version__,
        environment=settings.app_env,
    )

    # Log configuration (without secrets)
    logger.info(
        "Configuration loaded",
        github_app_id=settings.github_app_id or "not configured",
        ai_provider=settings.ai_provider,
        ai_model=settings.ai_model,
        max_permission_level=settings.get_max_permission_level(),
        write_enabled=settings.enable_write_mode,
    )

    yield

    logger.info("Shutting down CodeOps AI")


# Create FastAPI application
app = FastAPI(
    title="CodeOps AI",
    description="GitHub-Native AI Engineering Copilot with controlled write access",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# Middleware stack (order matters - first added = last executed)
# 1. CORS middleware (outermost - handles preflight)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["https://github.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# 3. Correlation ID middleware (for distributed tracing)
app.add_middleware(CorrelationIdMiddleware)

# 4. Input validation middleware (reject bad requests early)
app.add_middleware(InputValidationMiddleware)

# 5. Rate limiting middleware (protect against abuse)
app.add_middleware(RateLimitMiddleware)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests with correlation ID."""
    start_time = datetime.utcnow()

    # Skip health check logging in production
    if settings.is_production and request.url.path in ("/health", "/health/live"):
        return await call_next(request)

    response = await call_next(request)

    duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

    logger.info(
        "Request processed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration_ms, 2),
        correlation_id=get_correlation_id(),
    )

    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unhandled exceptions with correlation ID."""
    correlation_id = get_correlation_id()

    logger.error(
        "Unhandled exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        correlation_id=correlation_id,
        exc_info=exc,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "message": str(exc) if settings.debug else "An unexpected error occurred",
            "correlation_id": correlation_id,
        },
        headers={"X-Correlation-ID": correlation_id},
    )


# Include API routes
app.include_router(router)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with system information."""
    return {
        "name": "CodeOps AI",
        "version": __version__,
        "description": "GitHub-Native AI Engineering Copilot",
        "documentation": "/docs" if settings.debug else None,
        "status": "operational",
        "safety_model": {
            "max_permission_level": settings.get_max_permission_level(),
            "write_enabled": settings.enable_write_mode,
            "ci_gating_enabled": settings.enable_ci_bound_write,
            "note": "CodeOps AI NEVER pushes directly to main/master",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )
