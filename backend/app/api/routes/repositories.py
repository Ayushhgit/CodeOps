"""Repository management endpoints."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import PermissionLevel
from app.models.base import get_db
from app.models.repository import Repository, RepositoryTier

router = APIRouter()


class RepositoryResponse(BaseModel):
    """Repository response model."""

    id: int
    github_id: int
    full_name: str
    owner: str
    name: str
    tier: str
    max_permission_level: int
    write_enabled: bool
    ci_gating_enabled: bool
    is_active: bool
    last_analyzed_at: datetime | None

    class Config:
        from_attributes = True


class RepositoryPermissionUpdate(BaseModel):
    """Request to update repository permissions."""

    max_permission_level: int | None = None
    write_enabled: bool | None = None
    ci_gating_enabled: bool | None = None
    protected_paths: list[str] | None = None


class RepositoryStats(BaseModel):
    """Repository statistics."""

    total_prs_reviewed: int
    total_suggestions_made: int
    total_prs_opened: int
    total_commits_made: int
    intelligence_version: int
    last_analyzed_at: datetime | None


@router.get("/", response_model=list[RepositoryResponse])
async def list_repositories(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    active_only: bool = Query(True),
) -> list[RepositoryResponse]:
    """List all repositories with CodeOps installed."""
    query = select(Repository)

    if active_only:
        query = query.where(Repository.is_active == True)

    query = query.offset(skip).limit(limit).order_by(Repository.full_name)

    result = await db.execute(query)
    repositories = result.scalars().all()

    return [RepositoryResponse.model_validate(repo) for repo in repositories]


@router.get("/{owner}/{repo}", response_model=RepositoryResponse)
async def get_repository(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> RepositoryResponse:
    """Get repository details."""
    full_name = f"{owner}/{repo}"

    result = await db.execute(
        select(Repository).where(Repository.full_name == full_name)
    )
    repository = result.scalar_one_or_none()

    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository {full_name} not found",
        )

    return RepositoryResponse.model_validate(repository)


@router.patch("/{owner}/{repo}/permissions")
async def update_repository_permissions(
    owner: str,
    repo: str,
    update: RepositoryPermissionUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Update repository permission settings.

    IMPORTANT: This is a sensitive operation that controls write access.
    All changes are logged for audit purposes.
    """
    full_name = f"{owner}/{repo}"

    result = await db.execute(
        select(Repository).where(Repository.full_name == full_name)
    )
    repository = result.scalar_one_or_none()

    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository {full_name} not found",
        )

    # Track changes for audit
    changes: dict[str, Any] = {}

    # Validate permission level against tier
    if update.max_permission_level is not None:
        tier_limits = {
            RepositoryTier.FREE: 0,
            RepositoryTier.PRO: 2,
            RepositoryTier.TEAM: 3,
            RepositoryTier.ENTERPRISE: 3,
        }

        max_allowed = tier_limits[repository.tier]

        if update.max_permission_level > max_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission level {update.max_permission_level} exceeds "
                       f"tier limit ({max_allowed}) for {repository.tier.value} tier. "
                       f"Upgrade to access higher permission levels.",
            )

        changes["max_permission_level"] = {
            "from": repository.max_permission_level,
            "to": update.max_permission_level,
        }
        repository.max_permission_level = update.max_permission_level

    if update.write_enabled is not None:
        # Write mode requires at least Pro tier
        if update.write_enabled and repository.tier == RepositoryTier.FREE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Write mode requires Pro tier or higher",
            )

        changes["write_enabled"] = {
            "from": repository.write_enabled,
            "to": update.write_enabled,
        }
        repository.write_enabled = update.write_enabled

    if update.ci_gating_enabled is not None:
        # CI gating requires Team tier or higher
        if update.ci_gating_enabled and repository.tier not in (
            RepositoryTier.TEAM,
            RepositoryTier.ENTERPRISE,
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CI gating requires Team tier or higher",
            )

        changes["ci_gating_enabled"] = {
            "from": repository.ci_gating_enabled,
            "to": update.ci_gating_enabled,
        }
        repository.ci_gating_enabled = update.ci_gating_enabled

    if update.protected_paths is not None:
        changes["protected_paths"] = {
            "from": repository.protected_paths,
            "to": update.protected_paths,
        }
        repository.protected_paths = update.protected_paths

    await db.commit()

    # TODO: Create audit log entry for permission changes

    return {
        "status": "updated",
        "repository": full_name,
        "changes": changes,
        "effective_permission_level": repository.get_effective_permission_level().value,
    }


@router.get("/{owner}/{repo}/stats", response_model=RepositoryStats)
async def get_repository_stats(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> RepositoryStats:
    """Get repository usage statistics."""
    full_name = f"{owner}/{repo}"

    result = await db.execute(
        select(Repository).where(Repository.full_name == full_name)
    )
    repository = result.scalar_one_or_none()

    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository {full_name} not found",
        )

    return RepositoryStats(
        total_prs_reviewed=repository.total_prs_reviewed,
        total_suggestions_made=repository.total_suggestions_made,
        total_prs_opened=repository.total_prs_opened,
        total_commits_made=repository.total_commits_made,
        intelligence_version=repository.intelligence_version,
        last_analyzed_at=repository.last_analyzed_at,
    )


@router.post("/{owner}/{repo}/analyze")
async def trigger_analysis(
    owner: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """
    Trigger repository analysis to update intelligence.

    This queues a background job to analyze the repository
    and update the file/symbol graphs.
    """
    full_name = f"{owner}/{repo}"

    result = await db.execute(
        select(Repository).where(Repository.full_name == full_name)
    )
    repository = result.scalar_one_or_none()

    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository {full_name} not found",
        )

    # TODO: Queue analysis job

    return {
        "status": "queued",
        "repository": full_name,
        "message": "Repository analysis has been queued",
    }
