"""
Background Workers for CodeOps AI.

Handles async job processing for:
- Repository analysis
- PR reviews
- Test generation
- Documentation generation
"""

from arq import cron
from arq.connections import RedisSettings

from app.core.config import settings


class WorkerSettings:
    """ARQ worker configuration."""

    # Redis connection
    redis_settings = RedisSettings.from_dsn(settings.redis_url)

    # Job functions
    functions = [
        "app.workers.tasks.analyze_repository",
        "app.workers.tasks.review_pull_request",
        "app.workers.tasks.generate_tests",
        "app.workers.tasks.generate_documentation",
        "app.workers.tasks.explain_codebase",
    ]

    # Cron jobs
    cron_jobs = [
        # Cleanup old audit logs (runs daily at 3am)
        cron(
            "app.workers.tasks.cleanup_old_logs",
            hour=3,
            minute=0,
        ),
    ]

    # Worker configuration
    max_jobs = 10
    job_timeout = 600  # 10 minutes max per job
    keep_result = 3600  # Keep results for 1 hour
    health_check_interval = 30
