"""Repository models for CodeOps AI."""

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.core.permissions import PermissionLevel


class RepositoryTier(str, Enum):
    """Repository subscription tier."""

    FREE = "free"        # Read-only operations
    PRO = "pro"          # Test + docs PRs
    TEAM = "team"        # CI-bound writes
    ENTERPRISE = "enterprise"  # Policy-driven writes


class Repository(Base):
    """
    Repository model with permission and intelligence tracking.

    Stores persistent information about repositories that CodeOps
    has been installed on.
    """

    __tablename__ = "repositories"

    # GitHub identifiers
    github_id: Mapped[int] = mapped_column(
        BigInteger,
        unique=True,
        nullable=False,
        index=True,
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="owner/repo format",
    )
    owner: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Installation context
    installation_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        index=True,
    )
    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    installed_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # Repository metadata
    default_branch: Mapped[str] = mapped_column(
        String(255),
        default="main",
    )
    is_private: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    language: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Subscription tier
    tier: Mapped[RepositoryTier] = mapped_column(
        SQLEnum(RepositoryTier),
        default=RepositoryTier.FREE,
        nullable=False,
    )

    # Permission configuration
    max_permission_level: Mapped[int] = mapped_column(
        default=0,
        comment="Maximum permission level allowed (0-3)",
    )
    write_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        comment="Explicit opt-in for write operations",
    )
    ci_gating_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        comment="Require CI checks before commits",
    )

    # Protected paths (never modify these)
    protected_paths: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Paths that CodeOps should never modify",
    )

    # Intelligence state
    last_analyzed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_commit_analyzed: Mapped[str | None] = mapped_column(
        String(40),
        nullable=True,
        comment="SHA of last analyzed commit",
    )
    intelligence_version: Mapped[int] = mapped_column(
        default=0,
        comment="Version of the intelligence model",
    )

    # Statistics
    total_prs_reviewed: Mapped[int] = mapped_column(default=0)
    total_suggestions_made: Mapped[int] = mapped_column(default=0)
    total_prs_opened: Mapped[int] = mapped_column(default=0)
    total_commits_made: Mapped[int] = mapped_column(default=0)

    # Status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    suspended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    suspension_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    permissions = relationship(
        "RepositoryPermission",
        back_populates="repository",
        cascade="all, delete-orphan",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="repository",
    )
    file_nodes = relationship(
        "FileNode",
        back_populates="repository",
        cascade="all, delete-orphan",
    )
    symbol_nodes = relationship(
        "SymbolNode",
        back_populates="repository",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Repository {self.full_name}>"

    def get_effective_permission_level(self) -> PermissionLevel:
        """Get the effective permission level based on tier and config."""
        # Tier-based limits
        tier_limits = {
            RepositoryTier.FREE: 0,       # Read only
            RepositoryTier.PRO: 2,        # PR Author mode
            RepositoryTier.TEAM: 3,       # CI-bound
            RepositoryTier.ENTERPRISE: 3,  # Policy-driven
        }

        tier_max = tier_limits[self.tier]
        configured_max = self.max_permission_level

        # Return the minimum of tier limit and configured limit
        effective = min(tier_max, configured_max)

        # If write not explicitly enabled, cap at suggest mode
        if not self.write_enabled and effective > 1:
            effective = 1

        return PermissionLevel(effective)

    def can_write(self) -> bool:
        """Check if any write operations are allowed."""
        return self.write_enabled and self.max_permission_level >= 2

    def is_path_protected(self, path: str) -> bool:
        """Check if a path is protected from modifications."""
        for protected in self.protected_paths:
            if path.startswith(protected) or path == protected:
                return True
        return False


class RepositoryPermission(Base):
    """
    Granular permission grants for repositories.

    Tracks explicit permission grants with expiration and scope.
    """

    __tablename__ = "repository_permissions"
    __table_args__ = (
        UniqueConstraint("repo_id", "user_id", "permission_type"),
    )

    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"),
        nullable=False,
        index=True,
    )

    # Who has the permission
    user_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="GitHub user ID",
    )
    user_login: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Permission details
    permission_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Type: write, approve, admin",
    )
    permission_level: Mapped[int] = mapped_column(
        default=0,
        comment="Maximum level this grant allows",
    )

    # Scope
    allowed_paths: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Paths this permission covers (empty = all)",
    )
    allowed_actions: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Actions this permission allows",
    )

    # Validity
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    granted_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # Relationships
    repository = relationship("Repository", back_populates="permissions")

    def is_valid(self) -> bool:
        """Check if the permission is currently valid."""
        if self.revoked_at:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True
