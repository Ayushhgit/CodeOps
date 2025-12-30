"""API route modules."""

from fastapi import APIRouter

from app.api.routes.webhooks import router as webhooks_router
from app.api.routes.health import router as health_router
from app.api.routes.repositories import router as repositories_router
from app.api.routes.commands import router as commands_router

router = APIRouter()

# Include sub-routers
router.include_router(health_router, tags=["health"])
router.include_router(webhooks_router, prefix="/webhooks", tags=["webhooks"])
router.include_router(repositories_router, prefix="/repositories", tags=["repositories"])
router.include_router(commands_router, prefix="/commands", tags=["commands"])
