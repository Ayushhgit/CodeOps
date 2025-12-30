"""
Repository Intelligence Engine Models.

Maintains a persistent, evolving model of the repository:
- File dependency graph
- Symbol graph (functions, classes, APIs)
- Service boundaries
- Data flow
- Test coverage signals
- Risk hotspots

This intelligence:
- Updates incrementally per commit
- Is reused across all features
- Is referenced before every write action
"""

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class FileType(str, Enum):
    """Types of files in the repository."""

    SOURCE = "source"           # Source code files
    TEST = "test"               # Test files
    CONFIG = "config"           # Configuration files
    DOCUMENTATION = "documentation"  # Docs, README, etc.
    BUILD = "build"             # Build scripts, CI configs
    DATA = "data"               # Data files, fixtures
    ASSET = "asset"             # Images, static files
    OTHER = "other"


class SymbolType(str, Enum):
    """Types of code symbols."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    INTERFACE = "interface"
    TYPE = "type"
    CONSTANT = "constant"
    VARIABLE = "variable"
    MODULE = "module"
    ENDPOINT = "endpoint"       # API endpoints
    EVENT = "event"             # Event handlers
    HOOK = "hook"               # Framework hooks


class RiskLevel(str, Enum):
    """Risk levels for code areas."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FileNode(Base):
    """
    Represents a file in the repository with its metadata and relationships.

    Part of the file dependency graph.
    """

    __tablename__ = "file_nodes"
    __table_args__ = (
        UniqueConstraint("repo_id", "path"),
    )

    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"),
        nullable=False,
        index=True,
    )

    # File identification
    path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        index=True,
    )
    file_type: Mapped[FileType] = mapped_column(
        SQLEnum(FileType),
        default=FileType.SOURCE,
    )
    language: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    # Content metadata
    size_bytes: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )
    line_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )
    last_commit_sha: Mapped[str | None] = mapped_column(
        String(40),
        nullable=True,
    )
    last_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Complexity metrics
    cyclomatic_complexity: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    cognitive_complexity: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    # Change frequency (for risk assessment)
    change_count_30d: Mapped[int] = mapped_column(
        Integer,
        default=0,
        comment="Number of changes in last 30 days",
    )
    change_count_90d: Mapped[int] = mapped_column(
        Integer,
        default=0,
        comment="Number of changes in last 90 days",
    )

    # Test coverage
    has_tests: Mapped[bool] = mapped_column(default=False)
    test_file_path: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )
    coverage_percent: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    # Dependencies (stored as JSON for flexibility)
    imports: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Files/modules this file imports",
    )
    imported_by: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Files that import this file",
    )

    # Service boundary detection
    service_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Detected service boundary",
    )

    # Risk assessment
    risk_level: Mapped[RiskLevel] = mapped_column(
        SQLEnum(RiskLevel),
        default=RiskLevel.LOW,
    )
    risk_factors: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    # Summary for AI context
    ai_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="AI-generated summary of file purpose",
    )

    # Relationships
    repository = relationship("Repository", back_populates="file_nodes")
    symbols = relationship(
        "SymbolNode",
        back_populates="file",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<FileNode {self.path}>"


class SymbolNode(Base):
    """
    Represents a code symbol (function, class, etc.) in the repository.

    Part of the symbol graph for understanding code structure.
    """

    __tablename__ = "symbol_nodes"
    __table_args__ = (
        UniqueConstraint("file_id", "name", "symbol_type", "line_start"),
    )

    file_id: Mapped[int] = mapped_column(
        ForeignKey("file_nodes.id"),
        nullable=False,
        index=True,
    )
    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"),
        nullable=False,
        index=True,
    )

    # Symbol identification
    name: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )
    qualified_name: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        comment="Fully qualified name including module path",
    )
    symbol_type: Mapped[SymbolType] = mapped_column(
        SQLEnum(SymbolType),
        nullable=False,
    )

    # Location
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    column_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    column_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Signature and documentation
    signature: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Function/method signature",
    )
    docstring: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    return_type: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    parameters: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    # Visibility
    is_public: Mapped[bool] = mapped_column(default=True)
    is_exported: Mapped[bool] = mapped_column(default=False)

    # For API endpoints
    http_method: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
        comment="HTTP method for API endpoints",
    )
    route_path: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Route path for API endpoints",
    )

    # References
    calls: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Symbols this symbol calls",
    )
    called_by: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Symbols that call this symbol",
    )

    # Complexity
    complexity: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    # AI summary
    ai_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    file = relationship("FileNode", back_populates="symbols")
    repository = relationship("Repository", back_populates="symbol_nodes")

    def __repr__(self) -> str:
        return f"<SymbolNode {self.symbol_type.value} {self.qualified_name}>"


class DependencyEdge(Base):
    """
    Represents a dependency relationship between files or symbols.

    Used for building the dependency graph and understanding data flow.
    """

    __tablename__ = "dependency_edges"
    __table_args__ = (
        UniqueConstraint("repo_id", "source_path", "target_path", "dependency_type"),
    )

    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"),
        nullable=False,
        index=True,
    )

    # Edge endpoints
    source_path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        index=True,
    )
    target_path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        index=True,
    )

    # Dependency type
    dependency_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="import, call, inherit, implement, etc.",
    )

    # Weight (for graph algorithms)
    weight: Mapped[float] = mapped_column(
        Float,
        default=1.0,
    )

    # Additional context
    context: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    def __repr__(self) -> str:
        return f"<DependencyEdge {self.source_path} -> {self.target_path}>"


class RiskHotspot(Base):
    """
    Identified risk hotspots in the repository.

    These are areas that require extra caution before modification.
    """

    __tablename__ = "risk_hotspots"

    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"),
        nullable=False,
        index=True,
    )

    # Location
    file_path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        index=True,
    )
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Risk assessment
    risk_level: Mapped[RiskLevel] = mapped_column(
        SQLEnum(RiskLevel),
        nullable=False,
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Numeric risk score 0-100",
    )

    # Risk factors
    risk_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="security, performance, complexity, fragility, etc.",
    )
    risk_factors: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    risk_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Impact assessment
    affected_services: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    downstream_files: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    potential_blast_radius: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="small, medium, large, critical",
    )

    # Recommendations
    mitigation_suggestions: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    # Detection metadata
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    detected_by: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Analysis method: static, ai, historical, etc.",
    )

    # Resolution tracking
    is_resolved: Mapped[bool] = mapped_column(default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<RiskHotspot {self.risk_level.value} @ {self.file_path}>"
