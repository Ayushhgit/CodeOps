"""
Write Permission Safety Model — The Core of CodeOps Security.

This module implements the non-negotiable permission system that ensures
CodeOps AI NEVER breaks production.

Permission Levels:
    Level 0 — Read Only (Default)
        - Repo parsing
        - PR reviews
        - Explanations
        - Docs previews

    Level 1 — Suggest Mode
        - Generates diffs
        - Posts patches in PR comments
        - No commits

    Level 2 — PR Author Mode
        - Creates a branch
        - Commits changes
        - Opens a PR
        - Requires explicit repo opt-in

    Level 3 — CI-Bound Write Mode (Enterprise only)
        - Commits gated by:
            - Passing tests
            - Security checks
            - Explicit labels
        - Still NEVER merges

ABSOLUTE RULE: CodeOps AI NEVER pushes directly to main/master.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Literal


class PermissionLevel(IntEnum):
    """Permission levels for repository access."""

    READ_ONLY = 0
    SUGGEST_MODE = 1
    PR_AUTHOR_MODE = 2
    CI_BOUND_WRITE = 3

    @property
    def can_read(self) -> bool:
        """All levels can read."""
        return True

    @property
    def can_suggest(self) -> bool:
        """Level 1+ can suggest changes."""
        return self >= PermissionLevel.SUGGEST_MODE

    @property
    def can_create_branch(self) -> bool:
        """Level 2+ can create branches."""
        return self >= PermissionLevel.PR_AUTHOR_MODE

    @property
    def can_commit(self) -> bool:
        """Level 2+ can commit (never to main)."""
        return self >= PermissionLevel.PR_AUTHOR_MODE

    @property
    def can_open_pr(self) -> bool:
        """Level 2+ can open PRs."""
        return self >= PermissionLevel.PR_AUTHOR_MODE

    @property
    def requires_ci_gate(self) -> bool:
        """Level 3 requires CI gates."""
        return self == PermissionLevel.CI_BOUND_WRITE


# Protected branches that CodeOps AI can NEVER push to directly
PROTECTED_BRANCHES = frozenset({
    "main",
    "master",
    "develop",
    "development",
    "production",
    "prod",
    "release",
    "staging",
})


@dataclass(frozen=True)
class WritePermission:
    """
    Immutable record of a write permission grant.

    This is created when a write action is authorized and serves
    as an audit trail for all write operations.
    """

    repo_full_name: str
    permission_level: PermissionLevel
    granted_by: str  # User or system that granted permission
    granted_at: datetime
    expires_at: datetime | None = None
    allowed_paths: frozenset[str] = field(default_factory=frozenset)
    denied_paths: frozenset[str] = field(default_factory=frozenset)
    reason: str = ""

    def is_expired(self) -> bool:
        """Check if the permission has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def allows_path(self, path: str) -> bool:
        """Check if a file path is allowed by this permission."""
        # Explicit denies always win
        for denied in self.denied_paths:
            if path.startswith(denied) or path == denied:
                return False

        # If allowed_paths is empty, all paths are allowed (except denied)
        if not self.allowed_paths:
            return True

        # Check if path matches any allowed pattern
        for allowed in self.allowed_paths:
            if path.startswith(allowed) or path == allowed:
                return True

        return False


@dataclass
class WritePreflightCheck:
    """
    Mandatory preflight check before any write operation.

    Before ANY commit, you MUST:
    1. Explain what will change
    2. Explain why it's safe
    3. Explain blast radius
    4. Explain rollback strategy
    5. Ask for confirmation

    If any of the above is unclear → DO NOT WRITE
    """

    # What will change
    files_to_modify: list[str]
    files_to_create: list[str]
    files_to_delete: list[str]
    change_summary: str

    # Why it's safe
    safety_analysis: str
    breaking_changes: list[str]
    security_implications: list[str]

    # Blast radius
    affected_services: list[str]
    affected_tests: list[str]
    downstream_impacts: list[str]

    # Rollback strategy
    rollback_steps: list[str]
    rollback_difficulty: Literal["trivial", "easy", "moderate", "hard", "impossible"]

    # Confirmation
    requires_human_approval: bool = True
    approval_received: bool = False
    approved_by: str | None = None
    approved_at: datetime | None = None

    def is_ready_to_write(self) -> bool:
        """Check if all preflight requirements are met."""
        # Must have change summary
        if not self.change_summary:
            return False

        # Must have safety analysis
        if not self.safety_analysis:
            return False

        # Must have rollback strategy
        if not self.rollback_steps:
            return False

        # If approval required, must have it
        if self.requires_human_approval and not self.approval_received:
            return False

        return True

    def to_pr_description(self) -> str:
        """Generate PR description from preflight check."""
        sections = []

        # Summary
        sections.append(f"## Summary\n\n{self.change_summary}")

        # Changes
        changes = []
        if self.files_to_modify:
            changes.append(f"**Modified:** {', '.join(self.files_to_modify)}")
        if self.files_to_create:
            changes.append(f"**Created:** {', '.join(self.files_to_create)}")
        if self.files_to_delete:
            changes.append(f"**Deleted:** {', '.join(self.files_to_delete)}")
        if changes:
            sections.append("## Changes\n\n" + "\n".join(changes))

        # Safety
        sections.append(f"## Safety Analysis\n\n{self.safety_analysis}")

        if self.breaking_changes:
            sections.append(
                "### Breaking Changes\n\n" +
                "\n".join(f"- {bc}" for bc in self.breaking_changes)
            )

        if self.security_implications:
            sections.append(
                "### Security Implications\n\n" +
                "\n".join(f"- {si}" for si in self.security_implications)
            )

        # Blast Radius
        if self.affected_services or self.downstream_impacts:
            blast = []
            if self.affected_services:
                blast.append(f"**Services:** {', '.join(self.affected_services)}")
            if self.downstream_impacts:
                blast.append("**Downstream:**\n" +
                           "\n".join(f"- {di}" for di in self.downstream_impacts))
            sections.append("## Blast Radius\n\n" + "\n".join(blast))

        # Rollback
        sections.append(
            f"## Rollback Strategy\n\n"
            f"**Difficulty:** {self.rollback_difficulty}\n\n"
            f"**Steps:**\n" +
            "\n".join(f"{i}. {step}" for i, step in enumerate(self.rollback_steps, 1))
        )

        return "\n\n".join(sections)


def validate_branch_name(branch: str) -> bool:
    """
    Validate that a branch is safe to push to.

    Returns True if safe, False if protected.
    """
    normalized = branch.lower().strip()

    # Remove refs/heads/ prefix if present
    if normalized.startswith("refs/heads/"):
        normalized = normalized[11:]

    # Check against protected branches
    return normalized not in PROTECTED_BRANCHES


def get_safe_branch_name(repo: str, feature: str) -> str:
    """
    Generate a safe branch name for CodeOps operations.

    Format: codeops/{feature}/{timestamp}
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    # Sanitize feature name
    safe_feature = "".join(c if c.isalnum() or c == "-" else "-" for c in feature.lower())
    return f"codeops/{safe_feature}/{timestamp}"
