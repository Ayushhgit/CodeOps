"""
Job Service — Track and manage background jobs.

Provides job status tracking for async operations like:
- Repository analysis
- PR reviews
- Test generation
- Documentation generation
"""

import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import redis.asyncio as redis
import structlog

from app.core.config import settings


logger = structlog.get_logger(__name__)


class JobStatus(str, Enum):
    """Job status values."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    """Represents a background job."""

    job_id: str
    job_type: str
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    progress: int = 0  # 0-100
    result: dict[str, Any] | None = None
    error: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "job_type": self.job_type,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "progress": self.progress,
            "result": self.result,
            "error": self.error,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Job":
        """Create from dictionary."""
        return cls(
            job_id=data["job_id"],
            job_type=data["job_type"],
            status=JobStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            progress=data.get("progress", 0),
            result=data.get("result"),
            error=data.get("error"),
            metadata=data.get("metadata"),
        )


class JobService:
    """
    Service for tracking background job status.

    Uses Redis for distributed job tracking across instances.
    """

    JOB_TTL = 86400  # 24 hours
    JOB_PREFIX = "job:"

    def __init__(self, redis_url: str | None = None):
        """
        Initialize the job service.

        Args:
            redis_url: Redis connection URL (defaults to settings)
        """
        self._redis_url = redis_url or settings.redis_url
        self._redis: redis.Redis | None = None

    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._redis

    def _job_key(self, job_id: str) -> str:
        """Get Redis key for a job."""
        return f"{self.JOB_PREFIX}{job_id}"

    async def create_job(
        self,
        job_id: str,
        job_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> Job:
        """
        Create a new job.

        Args:
            job_id: Unique job identifier
            job_type: Type of job (analyze, review, etc.)
            metadata: Optional metadata

        Returns:
            Created job
        """
        job = Job(
            job_id=job_id,
            job_type=job_type,
            status=JobStatus.PENDING,
            created_at=datetime.utcnow(),
            metadata=metadata,
        )

        r = await self._get_redis()
        await r.setex(
            self._job_key(job_id),
            self.JOB_TTL,
            json.dumps(job.to_dict()),
        )

        logger.info("Job created", job_id=job_id, job_type=job_type)
        return job

    async def get_job(self, job_id: str) -> Job | None:
        """
        Get a job by ID.

        Args:
            job_id: Job identifier

        Returns:
            Job if found, None otherwise
        """
        r = await self._get_redis()
        data = await r.get(self._job_key(job_id))

        if not data:
            return None

        return Job.from_dict(json.loads(data))

    async def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        progress: int | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> Job | None:
        """
        Update job status.

        Args:
            job_id: Job identifier
            status: New status
            progress: Progress percentage (0-100)
            result: Result data (for completed jobs)
            error: Error message (for failed jobs)

        Returns:
            Updated job or None if not found
        """
        job = await self.get_job(job_id)
        if not job:
            return None

        job.status = status

        if progress is not None:
            job.progress = progress

        if status == JobStatus.RUNNING and not job.started_at:
            job.started_at = datetime.utcnow()

        if status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
            job.completed_at = datetime.utcnow()
            job.progress = 100 if status == JobStatus.COMPLETED else job.progress

        if result is not None:
            job.result = result

        if error is not None:
            job.error = error

        r = await self._get_redis()
        await r.setex(
            self._job_key(job_id),
            self.JOB_TTL,
            json.dumps(job.to_dict()),
        )

        logger.info(
            "Job updated",
            job_id=job_id,
            status=status.value,
            progress=job.progress,
        )

        return job

    async def start_job(self, job_id: str) -> Job | None:
        """Mark a job as running."""
        return await self.update_job_status(job_id, JobStatus.RUNNING)

    async def complete_job(
        self,
        job_id: str,
        result: dict[str, Any] | None = None,
    ) -> Job | None:
        """Mark a job as completed."""
        return await self.update_job_status(
            job_id,
            JobStatus.COMPLETED,
            progress=100,
            result=result,
        )

    async def fail_job(
        self,
        job_id: str,
        error: str,
    ) -> Job | None:
        """Mark a job as failed."""
        return await self.update_job_status(
            job_id,
            JobStatus.FAILED,
            error=error,
        )

    async def cancel_job(self, job_id: str) -> Job | None:
        """Mark a job as cancelled."""
        return await self.update_job_status(job_id, JobStatus.CANCELLED)

    async def update_progress(
        self,
        job_id: str,
        progress: int,
    ) -> Job | None:
        """Update job progress."""
        job = await self.get_job(job_id)
        if not job:
            return None

        job.progress = min(100, max(0, progress))

        r = await self._get_redis()
        await r.setex(
            self._job_key(job_id),
            self.JOB_TTL,
            json.dumps(job.to_dict()),
        )

        return job

    async def get_jobs_for_repo(
        self,
        repo_full_name: str,
        status_filter: JobStatus | None = None,
        limit: int = 50,
    ) -> list[Job]:
        """
        Get jobs for a repository.

        Note: This requires storing a secondary index.
        For simplicity, we scan keys with pattern matching.
        In production, use a more efficient approach.
        """
        r = await self._get_redis()

        # Get all job keys
        keys = []
        async for key in r.scan_iter(f"{self.JOB_PREFIX}*"):
            keys.append(key)
            if len(keys) >= 1000:  # Safety limit
                break

        jobs = []
        for key in keys:
            data = await r.get(key)
            if not data:
                continue

            job = Job.from_dict(json.loads(data))

            # Filter by repo
            if job.metadata and job.metadata.get("repo_full_name") == repo_full_name:
                if status_filter is None or job.status == status_filter:
                    jobs.append(job)

            if len(jobs) >= limit:
                break

        # Sort by created_at descending
        jobs.sort(key=lambda j: j.created_at, reverse=True)

        return jobs[:limit]

    async def cleanup_old_jobs(self, max_age_hours: int = 24) -> int:
        """
        Clean up jobs older than max_age_hours.

        Returns number of jobs deleted.
        """
        r = await self._get_redis()
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        deleted = 0

        async for key in r.scan_iter(f"{self.JOB_PREFIX}*"):
            data = await r.get(key)
            if not data:
                continue

            job = Job.from_dict(json.loads(data))
            if job.created_at < cutoff:
                await r.delete(key)
                deleted += 1

        logger.info("Cleaned up old jobs", deleted=deleted)
        return deleted

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None


# Global job service instance
job_service = JobService()
