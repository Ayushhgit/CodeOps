"""
Audit logging models — Immutable record of all CodeOps operations.

Every action logs:
- Trigger (command, label, PR)
- Files touched
- Reasoning summary
- Model version
- User approval context

Audit logs are immutable.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import JSON, DateTime, Enum as SQLEnum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class AuditAction(str, Enum):
    """Types of actions that are audited."""

    # Read operations
    REPO_ANALYZED = "repo_analyzed"
    FILE_READ = "file_read"
    PR_REVIEWED = "pr_reviewed"
    EXPLAIN_REQUESTED = "explain_requested"

    # Suggest operations (Level 1)
    DIFF_GENERATED = "diff_generated"
    PATCH_COMMENTED = "patch_commented"
    SUGGESTION_MADE = "suggestion_made"

    # Write operations (Level 2+)
    BRANCH_CREATED = "branch_created"
    COMMIT_MADE = "commit_made"
    PR_OPENED = "pr_opened"
    PR_UPDATED = "pr_updated"

    # CI-bound operations (Level 3)
    CI_CHECK_PASSED = "ci_check_passed"
    CI_CHECK_FAILED = "ci_check_failed"
    SECURITY_CHECK_PASSED = "security_check_passed"
    SECURITY_CHECK_FAILED = "security_check_failed"

    # Permission operations
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_REVOKED = "permission_revoked"

    # Error states
    ACTION_BLOCKED = "action_blocked"
    ACTION_FAILED = "action_failed"
    RATE_LIMITED = "rate_limited"


class AuditLog(Base):
    """
    Immutable audit log entry.

    This table is append-only. No updates or deletes are allowed.
    """

    __tablename__ = "audit_logs"

    # Trigger information
    trigger_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Type: command, webhook, label, scheduled",
    )
    trigger_source: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Source identifier (PR URL, command string, etc.)",
    )

    # Action details
    action: Mapped[AuditAction] = mapped_column(
        SQLEnum(AuditAction),
        nullable=False,
        index=True,
    )
    action_details: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Structured details about the action",
    )

    # Repository context
    repo_id: Mapped[int | None] = mapped_column(
        ForeignKey("repositories.id"),
        nullable=True,
        index=True,
    )
    repo_full_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    # Files touched
    files_read: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    files_modified: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    files_created: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    files_deleted: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    # AI reasoning
    reasoning_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="AI's reasoning for the action",
    )
    model_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="AI model used (e.g., claude-3-5-sonnet-20241022)",
    )
    prompt_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Hash of the prompt for reproducibility",
    )
    token_usage: Mapped[dict[str, int]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Token usage: input, output, total",
    )

    # User context
    user_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="GitHub user who triggered the action",
    )
    user_login: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # Approval context
    approval_required: Mapped[bool] = mapped_column(
        default=False,
    )
    approval_received: Mapped[bool] = mapped_column(
        default=False,
    )
    approved_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Permission level used
    permission_level: Mapped[int] = mapped_column(
        default=0,
        comment="0=read, 1=suggest, 2=pr_author, 3=ci_bound",
    )

    # Safety checks
    preflight_passed: Mapped[bool | None] = mapped_column(
        nullable=True,
        comment="Whether preflight checks passed",
    )
    safety_analysis: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Safety analysis results",
    )

    # Outcome
    success: Mapped[bool] = mapped_column(
        default=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    error_traceback: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Performance
    duration_ms: Mapped[int | None] = mapped_column(
        nullable=True,
        comment="Action duration in milliseconds",
    )

    # Immutability timestamp
    logged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Immutable log timestamp",
    )

    # Relationships
    repository = relationship("Repository", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.id} {self.action.value} @ {self.logged_at}>"

    @classmethod
    def create_read_log(
        cls,
        action: AuditAction,
        trigger_type: str,
        trigger_source: str,
        model_version: str,
        **kwargs,
    ) -> "AuditLog":
        """Factory for read-only operation logs."""
        return cls(
            action=action,
            trigger_type=trigger_type,
            trigger_source=trigger_source,
            model_version=model_version,
            permission_level=0,
            **kwargs,
        )

    @classmethod
    def create_write_log(
        cls,
        action: AuditAction,
        trigger_type: str,
        trigger_source: str,
        model_version: str,
        permission_level: int,
        approval_required: bool = True,
        **kwargs,
    ) -> "AuditLog":
        """Factory for write operation logs with safety requirements."""
        if permission_level < 2:
            raise ValueError("Write logs require permission level 2+")

        return cls(
            action=action,
            trigger_type=trigger_type,
            trigger_source=trigger_source,
            model_version=model_version,
            permission_level=permission_level,
            approval_required=approval_required,
            **kwargs,
        )
