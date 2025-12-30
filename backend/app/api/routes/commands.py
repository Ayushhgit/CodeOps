"""
Command execution endpoints for CodeOps AI.

These endpoints handle the execution of commands like:
- /explain
- /review
- /generate-tests
- /generate-docs
- /suggest
"""

import uuid
from datetime import datetime
from typing import Any, Literal

import structlog
from arq.connections import ArqRedis, create_pool
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.middleware import validate_repo_full_name, validate_file_path
from app.core.config import settings
from app.core.permissions import PermissionLevel
from app.models.base import get_db
from app.models.repository import Repository
from app.services.jobs import JobService, JobStatus

router = APIRouter()
logger = structlog.get_logger(__name__)


class ExplainRequest(BaseModel):
    """Request to explain part of a repository."""

    repo_full_name: str = Field(..., min_length=3, max_length=200)
    target: str = Field(..., min_length=1, max_length=500)  # "repo", "file:path", "impact:pr_number"
    context: dict[str, Any] | None = None

    @field_validator("repo_full_name")
    @classmethod
    def validate_repo_name(cls, v: str) -> str:
        return validate_repo_full_name(v)


class ReviewRequest(BaseModel):
    """Request to review a pull request."""

    repo_full_name: str = Field(..., min_length=3, max_length=200)
    pr_number: int = Field(..., ge=1, le=999999999)
    focus_areas: list[str] | None = None  # security, performance, etc.

    @field_validator("repo_full_name")
    @classmethod
    def validate_repo_name(cls, v: str) -> str:
        return validate_repo_full_name(v)

    @field_validator("focus_areas")
    @classmethod
    def validate_focus_areas(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        valid_areas = {"security", "performance", "correctness", "maintainability", "testing"}
        for area in v:
            if area.lower() not in valid_areas:
                raise ValueError(f"Invalid focus area: {area}. Valid: {valid_areas}")
        return [a.lower() for a in v]


class GenerateTestsRequest(BaseModel):
    """Request to generate tests."""

    repo_full_name: str = Field(..., min_length=3, max_length=200)
    file_path: str = Field(..., min_length=1, max_length=1000)
    test_type: Literal["unit", "integration", "e2e"] = "unit"
    create_pr: bool = False

    @field_validator("repo_full_name")
    @classmethod
    def validate_repo_name(cls, v: str) -> str:
        return validate_repo_full_name(v)

    @field_validator("file_path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        return validate_file_path(v)


class GenerateDocsRequest(BaseModel):
    """Request to generate documentation."""

    repo_full_name: str = Field(..., min_length=3, max_length=200)
    target: str = Field(..., min_length=1, max_length=500)  # "api", "file:path", "readme"
    format: Literal["markdown", "openapi", "jsdoc"] = "markdown"
    create_pr: bool = False

    @field_validator("repo_full_name")
    @classmethod
    def validate_repo_name(cls, v: str) -> str:
        return validate_repo_full_name(v)


class SuggestRequest(BaseModel):
    """Request to suggest code changes."""

    repo_full_name: str = Field(..., min_length=3, max_length=200)
    pr_number: int = Field(..., ge=1, le=999999999)
    description: str = Field(..., min_length=10, max_length=10000)
    create_pr: bool = False

    @field_validator("repo_full_name")
    @classmethod
    def validate_repo_name(cls, v: str) -> str:
        return validate_repo_full_name(v)


class CommandResponse(BaseModel):
    """Response from command execution."""

    status: Literal["queued", "running", "completed", "failed", "error"]
    job_id: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


class JobStatusResponse(BaseModel):
    """Response for job status queries."""

    job_id: str
    job_type: str
    status: str
    progress: int
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
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


async def _create_job_and_enqueue(
    job_type: str,
    task_name: str,
    repo_full_name: str,
    metadata: dict[str, Any],
    **task_kwargs,
) -> str:
    """
    Create a job in the JobService and enqueue the task.

    Returns the job ID.
    """
    job_id = f"{job_type}-{uuid.uuid4().hex[:12]}"

    # Create job in JobService
    job_service = JobService()
    try:
        await job_service.create_job(
            job_id=job_id,
            job_type=job_type,
            metadata={
                "repo_full_name": repo_full_name,
                **metadata,
            },
        )

        # Enqueue task to ARQ worker
        try:
            from arq.connections import RedisSettings
            pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            await pool.enqueue_job(
                task_name,
                repo_full_name=repo_full_name,
                job_id=job_id,
                **task_kwargs,
            )
            await pool.close()
        except Exception as e:
            logger.warning(
                "Failed to enqueue job to ARQ, job created but not queued",
                job_id=job_id,
                error=str(e),
            )
            # Job is created but not queued - still return the ID
            # The job will show as pending until a worker picks it up

        logger.info(
            "Job created and enqueued",
            job_id=job_id,
            job_type=job_type,
            repo=repo_full_name,
        )

        return job_id

    finally:
        await job_service.close()


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

    # Parse and validate target
    if request.target == "repo":
        target_type = "repo"
    elif request.target.startswith("file:"):
        target_type = "file"
        # Validate the file path
        file_path = request.target[5:]
        validate_file_path(file_path)
    elif request.target.startswith("impact:"):
        target_type = "impact"
        try:
            pr_number = int(request.target[7:])
            if pr_number < 1:
                raise ValueError()
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid PR number in impact target",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid explain target: {request.target}. Use 'repo', 'file:path', or 'impact:pr_number'",
        )

    job_id = await _create_job_and_enqueue(
        job_type="explain",
        task_name="explain_codebase",
        repo_full_name=repository.full_name,
        metadata={"target": request.target, "target_type": target_type},
        installation_id=repository.installation_id,
        target=request.target,
    )

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": "explain",
            "target": request.target,
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

    focus_areas = request.focus_areas or ["security", "performance", "correctness"]

    job_id = await _create_job_and_enqueue(
        job_type="review",
        task_name="review_pull_request",
        repo_full_name=repository.full_name,
        metadata={"pr_number": request.pr_number, "focus_areas": focus_areas},
        installation_id=repository.installation_id,
        pr_number=request.pr_number,
        focus_areas=focus_areas,
    )

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": "review",
            "pr_number": request.pr_number,
            "focus_areas": focus_areas,
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

    job_id = await _create_job_and_enqueue(
        job_type="generate_tests",
        task_name="generate_tests",
        repo_full_name=repository.full_name,
        metadata={
            "file_path": request.file_path,
            "test_type": request.test_type,
            "create_pr": request.create_pr,
        },
        installation_id=repository.installation_id,
        file_path=request.file_path,
        test_type=request.test_type,
        create_pr=request.create_pr,
    )

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

    job_id = await _create_job_and_enqueue(
        job_type="generate_docs",
        task_name="generate_documentation",
        repo_full_name=repository.full_name,
        metadata={
            "target": request.target,
            "format": request.format,
            "create_pr": request.create_pr,
        },
        installation_id=repository.installation_id,
        target=request.target,
        format=request.format,
        create_pr=request.create_pr,
    )

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

    # Note: suggest uses a different approach - we'd need to implement this task
    job_id = f"suggest-{uuid.uuid4().hex[:12]}"

    # For now, create job but note that task isn't implemented
    job_service = JobService()
    try:
        await job_service.create_job(
            job_id=job_id,
            job_type="suggest",
            metadata={
                "repo_full_name": repository.full_name,
                "pr_number": request.pr_number,
                "description": request.description[:500],  # Truncate for metadata
                "create_pr": request.create_pr,
            },
        )
    finally:
        await job_service.close()

    return CommandResponse(
        status="queued",
        job_id=job_id,
        result={
            "job_type": "suggest",
            "pr_number": request.pr_number,
            "description": request.description[:200] + "..." if len(request.description) > 200 else request.description,
            "create_pr": request.create_pr,
            "repository": repository.full_name,
            "note": "Suggest task implementation pending",
        },
    )


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str,
) -> JobStatusResponse:
    """Get the status of a queued job."""
    job_service = JobService()
    try:
        job = await job_service.get_job(job_id)

        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {job_id} not found",
            )

        return JobStatusResponse(
            job_id=job.job_id,
            job_type=job.job_type,
            status=job.status.value,
            progress=job.progress,
            created_at=job.created_at.isoformat(),
            started_at=job.started_at.isoformat() if job.started_at else None,
            completed_at=job.completed_at.isoformat() if job.completed_at else None,
            result=job.result,
            error=job.error,
        )

    finally:
        await job_service.close()


@router.get("/jobs/repo/{repo_full_name}")
async def get_repository_jobs(
    repo_full_name: str,
    status_filter: str | None = None,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Get recent jobs for a repository."""
    # Validate repo name
    try:
        validate_repo_full_name(repo_full_name)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Ensure repository exists and user has access
    await get_repository_or_404(repo_full_name, db)

    # Parse status filter if provided
    filter_status = None
    if status_filter:
        try:
            filter_status = JobStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter: {status_filter}",
            )

    job_service = JobService()
    try:
        jobs = await job_service.get_jobs_for_repo(
            repo_full_name=repo_full_name,
            status_filter=filter_status,
            limit=min(limit, 100),
        )

        return {
            "repository": repo_full_name,
            "count": len(jobs),
            "jobs": [
                {
                    "job_id": job.job_id,
                    "job_type": job.job_type,
                    "status": job.status.value,
                    "progress": job.progress,
                    "created_at": job.created_at.isoformat(),
                    "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                }
                for job in jobs
            ],
        }

    finally:
        await job_service.close()
