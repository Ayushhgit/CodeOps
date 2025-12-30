"""Health check endpoints."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.base import get_db

router = APIRouter()


@router.get("/health")
async def health_check() -> dict[str, Any]:
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.1.0",
        "environment": settings.app_env,
    }


@router.get("/health/ready")
async def readiness_check(
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Readiness check that verifies all dependencies.

    Returns 200 if the service is ready to accept traffic.
    """
    checks: dict[str, Any] = {
        "database": False,
        "github_configured": False,
    }
    all_healthy = True

    # Check database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as e:
        checks["database_error"] = str(e)
        all_healthy = False

    # Check GitHub App configuration
    if settings.github_app_id and settings.github_app_private_key:
        checks["github_configured"] = True
    else:
        all_healthy = False

    return {
        "status": "ready" if all_healthy else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    }


@router.get("/health/live")
async def liveness_check() -> dict[str, str]:
    """
    Liveness check for Kubernetes.

    Returns 200 if the process is running.
    """
    return {"status": "alive"}
