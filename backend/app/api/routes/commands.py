"""
Command execution endpoints for CodeOps AI.

These endpoints handle the execution of commands like:
- /explain
- /review
- /generate-tests
- /generate-docs
- /suggest
"""

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import PermissionLevel
from app.models.base import get_db
from app.models.repository import Repository

router = APIRouter()


class ExplainRequest(BaseModel):
    """Request to explain part of a repository."""

    repo_full_name: str
    target: str  # "repo", "file:path", "impact:pr_number"
    context: dict[str, Any] | None = None


class ReviewRequest(BaseModel):
    """Request to review a pull request."""

    repo_full_name: str
    pr_number: int
    focus_areas: list[str] | None = None  # security, performance, etc.


class GenerateTestsRequest(BaseModel):
    """Request to generate tests."""

    repo_full_name: str
    file_path: str
    test_type: Literal["unit", "integration", "e2e"] = "unit"
    create_pr: bool = False


class GenerateDocsRequest(BaseModel):
    """Request to generate documentation."""

    repo_full_name: str
    target: str  # "api", "file:path", "readme"
    format: Literal["markdown", "openapi", "jsdoc"] = "markdown"
    create_pr: bool = False


class SuggestRequest(BaseModel):
    """Request to suggest code changes."""

    repo_full_name: str
    pr_number: int
    description: str
    create_pr: bool = False


class CommandResponse(BaseModel):
    """Response from command execution."""

    status: Literal["queued", "completed", "error"]
    job_id: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


async def get_repository_or_404(
    repo_full_name: str,
    db: AsyncSession,
) -> Repository:
    """Get repository or raise 404."""
    result = await db.execute(
        select(Repository).where(Repository.full_name == repo_full_name)
    )
    repository = result.scalar_one_or_none()

    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository {repo_full_name} not found",
        )

    if not repository.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Repository {repo_full_name} is not active",
        )

    return repository


def check_permission_level(
    repository: Repository,
    required_level: PermissionLevel,
) -> None:
    """Check if repository has required permission level."""
    effective_level = repository.get_effective_permission_level()

    if effective_level < required_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This operation requires permission level {required_level.value} "
                   f"({required_level.name}), but repository is at level "
                   f"{effective_level.value} ({effective_level.name})",
        )


@router.post("/explain", response_model=CommandResponse)
async def explain_command(
    request: ExplainRequest,
    db: AsyncSession = Depends(get_db),
) -> CommandResponse:
    """
    Execute /explain command.

    Supports:
    - /explain repo - Explain repository architecture
    - /explain file:src/auth/* - Explain specific files
    - /explain impact:123 - Explain PR impact

    This is a Level 0 (read-only) operation.
    """
    repository = await get_repository_or_404(request.repo_full_name, db)

    # Parse target
    if request.target == "repo":
        job_type = "explain_repo"
        target_details = {"scope": "full"}
    elif request.target.startswith("file:"):
        job_type = "explain_file"
        target_details = {"path": request.target[5:]}
    elif request.target.startswith("impact:"):
        job_type = "explain_impact"
        target_details = {"pr_number": int(request.target[7:])}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid explain target: {request.target}",
        )

    # TODO: Queue job with AI service
    job_id = f"explain-{repository.id}-{datetime.utcnow().timestamp()}"

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": job_type,
            "target": target_details,
            "repository": repository.full_name,
        },
    )


@router.post("/review", response_model=CommandResponse)
async def review_command(
    request: ReviewRequest,
    db: AsyncSession = Depends(get_db),
) -> CommandResponse:
    """
    Execute /review command.

    Reviews a pull request for:
    - Security issues
    - Performance risks
    - Concurrency hazards
    - Cost explosions

    This is a Level 0 (read-only) operation - no write access.
    """
    repository = await get_repository_or_404(request.repo_full_name, db)

    # TODO: Queue review job
    job_id = f"review-{repository.id}-{request.pr_number}-{datetime.utcnow().timestamp()}"

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": "review_pr",
            "pr_number": request.pr_number,
            "focus_areas": request.focus_areas or ["security", "performance", "correctness"],
            "repository": repository.full_name,
        },
    )


@router.post("/generate-tests", response_model=CommandResponse)
async def generate_tests_command(
    request: GenerateTestsRequest,
    db: AsyncSession = Depends(get_db),
) -> CommandResponse:
    """
    Execute /generate-tests command.

    Generates tests for a file. Can optionally create a PR.

    Permission requirements:
    - Without PR: Level 1 (suggest mode) - posts tests in comment
    - With PR: Level 2 (PR author mode) - creates branch and PR
    """
    repository = await get_repository_or_404(request.repo_full_name, db)

    # Check permissions based on whether we're creating a PR
    if request.create_pr:
        check_permission_level(repository, PermissionLevel.PR_AUTHOR_MODE)
    else:
        check_permission_level(repository, PermissionLevel.SUGGEST_MODE)

    # TODO: Queue test generation job
    job_id = f"tests-{repository.id}-{datetime.utcnow().timestamp()}"

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": "generate_tests",
            "file_path": request.file_path,
            "test_type": request.test_type,
            "create_pr": request.create_pr,
            "repository": repository.full_name,
        },
    )


@router.post("/generate-docs", response_model=CommandResponse)
async def generate_docs_command(
    request: GenerateDocsRequest,
    db: AsyncSession = Depends(get_db),
) -> CommandResponse:
    """
    Execute /generate-docs command.

    Generates documentation. Can optionally create a PR.

    Permission requirements:
    - Without PR: Level 1 (suggest mode) - posts docs in comment
    - With PR: Level 2 (PR author mode) - creates branch and PR
    """
    repository = await get_repository_or_404(request.repo_full_name, db)

    # Check permissions based on whether we're creating a PR
    if request.create_pr:
        check_permission_level(repository, PermissionLevel.PR_AUTHOR_MODE)
    else:
        check_permission_level(repository, PermissionLevel.SUGGEST_MODE)

    # TODO: Queue documentation generation job
    job_id = f"docs-{repository.id}-{datetime.utcnow().timestamp()}"

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": "generate_docs",
            "target": request.target,
            "format": request.format,
            "create_pr": request.create_pr,
            "repository": repository.full_name,
        },
    )


@router.post("/suggest", response_model=CommandResponse)
async def suggest_command(
    request: SuggestRequest,
    db: AsyncSession = Depends(get_db),
) -> CommandResponse:
    """
    Execute /suggest command.

    Generates code suggestions based on description. Can optionally create a PR.

    Permission requirements:
    - Without PR: Level 1 (suggest mode) - posts suggestion in comment
    - With PR: Level 2 (PR author mode) - creates branch and PR
    """
    repository = await get_repository_or_404(request.repo_full_name, db)

    # Check permissions based on whether we're creating a PR
    if request.create_pr:
        check_permission_level(repository, PermissionLevel.PR_AUTHOR_MODE)
    else:
        check_permission_level(repository, PermissionLevel.SUGGEST_MODE)

    # TODO: Queue suggestion job
    job_id = f"suggest-{repository.id}-{request.pr_number}-{datetime.utcnow().timestamp()}"

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": "suggest",
            "pr_number": request.pr_number,
            "description": request.description,
            "create_pr": request.create_pr,
            "repository": repository.full_name,
        },
    )


@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Get the status of a queued job."""
    # TODO: Implement job status tracking
    return {
        "job_id": job_id,
        "status": "pending",
        "message": "Job status tracking not yet implemented",
    }
