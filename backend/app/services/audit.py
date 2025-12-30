"""
Audit Logging Service — Immutable record of all CodeOps operations.

Every action logs:
- Trigger (command, label, PR)
- Files touched
- Reasoning summary
- Model version
- User approval context

Audit logs are immutable.
"""

from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditAction, AuditLog


logger = structlog.get_logger(__name__)


class AuditService:
    """
    Service for creating and querying audit logs.

    All audit logs are immutable once created.
    """

    def __init__(self, db: AsyncSession):
        """
        Initialize the audit service.

        Args:
            db: Database session
        """
        self.db = db

    async def log_action(
        self,
        action: AuditAction,
        trigger_type: str,
        trigger_source: str,
        model_version: str,
        repo_full_name: str | None = None,
        repo_id: int | None = None,
        user_id: str | None = None,
        user_login: str | None = None,
        permission_level: int = 0,
        files_read: list[str] | None = None,
        files_modified: list[str] | None = None,
        files_created: list[str] | None = None,
        files_deleted: list[str] | None = None,
        reasoning_summary: str | None = None,
        prompt_hash: str | None = None,
        token_usage: dict[str, int] | None = None,
        action_details: dict[str, Any] | None = None,
        safety_analysis: dict[str, Any] | None = None,
        approval_required: bool = False,
        approval_received: bool = False,
        approved_by: str | None = None,
        preflight_passed: bool | None = None,
        success: bool = True,
        error_message: str | None = None,
        duration_ms: int | None = None,
    ) -> AuditLog:
        """
        Create an immutable audit log entry.

        Args:
            action: The action being logged
            trigger_type: Type of trigger (command, webhook, label, scheduled)
            trigger_source: Source identifier (PR URL, command string, etc.)
            model_version: AI model used
            repo_full_name: Repository full name (optional)
            repo_id: Repository database ID (optional)
            user_id: GitHub user ID (optional)
            user_login: GitHub username (optional)
            permission_level: Permission level used (0-3)
            files_read: List of files read
            files_modified: List of files modified
            files_created: List of files created
            files_deleted: List of files deleted
            reasoning_summary: AI reasoning summary
            prompt_hash: Hash of the prompt for reproducibility
            token_usage: Token usage stats
            action_details: Additional action-specific details
            safety_analysis: Safety analysis results
            approval_required: Whether approval was required
            approval_received: Whether approval was received
            approved_by: Who approved the action
            preflight_passed: Whether preflight checks passed
            success: Whether the action succeeded
            error_message: Error message if failed
            duration_ms: Duration in milliseconds

        Returns:
            Created audit log entry
        """
        log_entry = AuditLog(
            action=action,
            trigger_type=trigger_type,
            trigger_source=trigger_source,
            model_version=model_version,
            repo_full_name=repo_full_name,
            repo_id=repo_id,
            user_id=user_id,
            user_login=user_login,
            permission_level=permission_level,
            files_read=files_read or [],
            files_modified=files_modified or [],
            files_created=files_created or [],
            files_deleted=files_deleted or [],
            reasoning_summary=reasoning_summary,
            prompt_hash=prompt_hash,
            token_usage=token_usage or {},
            action_details=action_details or {},
            safety_analysis=safety_analysis or {},
            approval_required=approval_required,
            approval_received=approval_received,
            approved_by=approved_by,
            approved_at=datetime.utcnow() if approved_by else None,
            preflight_passed=preflight_passed,
            success=success,
            error_message=error_message,
            duration_ms=duration_ms,
        )

        self.db.add(log_entry)
        await self.db.flush()

        logger.info(
            "Audit log created",
            log_id=log_entry.id,
            action=action.value,
            repo=repo_full_name,
            user=user_login,
            success=success,
        )

        return log_entry

    async def log_read_operation(
        self,
        action: AuditAction,
        trigger_source: str,
        model_version: str,
        files_read: list[str],
        **kwargs,
    ) -> AuditLog:
        """
        Log a read-only operation.

        Convenience method for Level 0 operations.
        """
        return await self.log_action(
            action=action,
            trigger_type="command",
            trigger_source=trigger_source,
            model_version=model_version,
            permission_level=0,
            files_read=files_read,
            **kwargs,
        )

    async def log_write_operation(
        self,
        action: AuditAction,
        trigger_source: str,
        model_version: str,
        permission_level: int,
        files_modified: list[str] | None = None,
        files_created: list[str] | None = None,
        files_deleted: list[str] | None = None,
        safety_analysis: dict[str, Any] | None = None,
        preflight_passed: bool = True,
        **kwargs,
    ) -> AuditLog:
        """
        Log a write operation with safety information.

        Convenience method for Level 2+ operations.
        """
        if permission_level < 2:
            raise ValueError("Write operations require permission level 2+")

        return await self.log_action(
            action=action,
            trigger_type="command",
            trigger_source=trigger_source,
            model_version=model_version,
            permission_level=permission_level,
            files_modified=files_modified,
            files_created=files_created,
            files_deleted=files_deleted,
            safety_analysis=safety_analysis,
            preflight_passed=preflight_passed,
            approval_required=True,
            **kwargs,
        )

    async def get_logs_for_repo(
        self,
        repo_full_name: str,
        limit: int = 100,
        offset: int = 0,
        action_filter: AuditAction | None = None,
    ) -> list[AuditLog]:
        """
        Get audit logs for a repository.

        Args:
            repo_full_name: Repository full name
            limit: Maximum logs to return
            offset: Offset for pagination
            action_filter: Optional action type filter

        Returns:
            List of audit logs
        """
        query = (
            select(AuditLog)
            .where(AuditLog.repo_full_name == repo_full_name)
            .order_by(AuditLog.logged_at.desc())
            .offset(offset)
            .limit(limit)
        )

        if action_filter:
            query = query.where(AuditLog.action == action_filter)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_logs_for_user(
        self,
        user_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLog]:
        """
        Get audit logs for a user.

        Args:
            user_id: GitHub user ID
            limit: Maximum logs to return
            offset: Offset for pagination

        Returns:
            List of audit logs
        """
        query = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.logged_at.desc())
            .offset(offset)
            .limit(limit)
        )

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_recent_write_operations(
        self,
        repo_full_name: str,
        since: datetime | None = None,
    ) -> list[AuditLog]:
        """
        Get recent write operations for a repository.

        Useful for understanding what changes CodeOps has made.
        """
        write_actions = [
            AuditAction.BRANCH_CREATED,
            AuditAction.COMMIT_MADE,
            AuditAction.PR_OPENED,
            AuditAction.PR_UPDATED,
        ]

        query = (
            select(AuditLog)
            .where(AuditLog.repo_full_name == repo_full_name)
            .where(AuditLog.action.in_(write_actions))
            .order_by(AuditLog.logged_at.desc())
        )

        if since:
            query = query.where(AuditLog.logged_at >= since)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_failed_operations(
        self,
        repo_full_name: str | None = None,
        limit: int = 50,
    ) -> list[AuditLog]:
        """
        Get failed operations for debugging.

        Args:
            repo_full_name: Optional repository filter
            limit: Maximum logs to return

        Returns:
            List of failed audit logs
        """
        query = (
            select(AuditLog)
            .where(AuditLog.success == False)
            .order_by(AuditLog.logged_at.desc())
            .limit(limit)
        )

        if repo_full_name:
            query = query.where(AuditLog.repo_full_name == repo_full_name)

        result = await self.db.execute(query)
        return list(result.scalars().all())
