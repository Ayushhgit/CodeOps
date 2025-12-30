"""
GitHub API Client for CodeOps AI.

Handles all interactions with the GitHub API including:
- Repository operations
- Pull request management
- Branch operations
- Commit operations
- Check runs

IMPORTANT: All write operations go through the safety model.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
import jwt

from app.core.config import settings
from app.core.permissions import (
    PROTECTED_BRANCHES,
    PermissionLevel,
    validate_branch_name,
)


@dataclass
class GitHubFile:
    """Represents a file in a GitHub repository."""

    path: str
    content: str | None
    sha: str
    size: int
    encoding: str = "base64"


@dataclass
class GitHubPR:
    """Represents a GitHub Pull Request."""

    number: int
    title: str
    body: str | None
    state: str
    head_ref: str
    base_ref: str
    user_login: str
    created_at: datetime
    updated_at: datetime
    merged: bool
    mergeable: bool | None
    html_url: str
    diff_url: str
    additions: int
    deletions: int
    changed_files: int


@dataclass
class GitHubCommit:
    """Represents a GitHub commit."""

    sha: str
    message: str
    author_name: str
    author_email: str
    author_date: datetime
    files: list[str]


class GitHubClientError(Exception):
    """Base exception for GitHub client errors."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class GitHubRateLimitError(GitHubClientError):
    """Raised when GitHub rate limit is exceeded."""

    pass


class GitHubPermissionError(GitHubClientError):
    """Raised when operation is not permitted."""

    pass


class GitHubClient:
    """
    GitHub API client with safety controls.

    All write operations are gated by permission checks.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self, installation_id: int):
        """
        Initialize GitHub client for an installation.

        Args:
            installation_id: GitHub App installation ID
        """
        self.installation_id = installation_id
        self._token: str | None = None
        self._token_expires: datetime | None = None
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=30.0,
        )

    async def __aenter__(self):
        await self._ensure_token()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._client.aclose()

    async def _ensure_token(self) -> None:
        """Ensure we have a valid installation access token."""
        if self._token and self._token_expires and datetime.utcnow() < self._token_expires:
            return

        # Generate JWT for app authentication
        app_jwt = self._generate_app_jwt()

        # Get installation access token
        response = await self._client.post(
            f"/app/installations/{self.installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

        if response.status_code != 201:
            raise GitHubClientError(
                f"Failed to get installation token: {response.text}",
                response.status_code,
            )

        data = response.json()
        self._token = data["token"]
        # Token expires in 1 hour, refresh 5 minutes early
        self._token_expires = datetime.utcnow() + timedelta(minutes=55)

    def _generate_app_jwt(self) -> str:
        """Generate JWT for GitHub App authentication."""
        if not settings.github_app_private_key:
            raise GitHubClientError("GitHub App private key not configured")

        now = datetime.utcnow()
        payload = {
            "iat": now,
            "exp": now + timedelta(minutes=10),
            "iss": settings.github_app_id,
        }

        return jwt.encode(
            payload,
            settings.github_app_private_key,
            algorithm="RS256",
        )

    def _headers(self) -> dict[str, str]:
        """Get headers for API requests."""
        if not self._token:
            raise GitHubClientError("No access token available")

        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Make an API request with error handling."""
        await self._ensure_token()

        response = await self._client.request(
            method,
            path,
            headers=self._headers(),
            **kwargs,
        )

        if response.status_code == 403:
            if "rate limit" in response.text.lower():
                raise GitHubRateLimitError("GitHub rate limit exceeded")
            raise GitHubPermissionError(f"Permission denied: {response.text}")

        if response.status_code >= 400:
            raise GitHubClientError(
                f"GitHub API error: {response.text}",
                response.status_code,
            )

        if response.status_code == 204:
            return {}

        return response.json()

    # =========================================================================
    # READ OPERATIONS (Level 0+)
    # =========================================================================

    async def get_repository(self, owner: str, repo: str) -> dict[str, Any]:
        """Get repository information."""
        return await self._request("GET", f"/repos/{owner}/{repo}")

    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str | None = None,
    ) -> GitHubFile:
        """Get file content from repository."""
        params = {}
        if ref:
            params["ref"] = ref

        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/contents/{path}",
            params=params,
        )

        return GitHubFile(
            path=data["path"],
            content=data.get("content"),
            sha=data["sha"],
            size=data["size"],
            encoding=data.get("encoding", "base64"),
        )

    async def get_tree(
        self,
        owner: str,
        repo: str,
        tree_sha: str,
        recursive: bool = True,
    ) -> list[dict[str, Any]]:
        """Get repository tree."""
        params = {"recursive": "1"} if recursive else {}
        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/git/trees/{tree_sha}",
            params=params,
        )
        return data.get("tree", [])

    async def get_pull_request(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> GitHubPR:
        """Get pull request details."""
        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pr_number}",
        )

        return GitHubPR(
            number=data["number"],
            title=data["title"],
            body=data.get("body"),
            state=data["state"],
            head_ref=data["head"]["ref"],
            base_ref=data["base"]["ref"],
            user_login=data["user"]["login"],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")),
            merged=data.get("merged", False),
            mergeable=data.get("mergeable"),
            html_url=data["html_url"],
            diff_url=data["diff_url"],
            additions=data.get("additions", 0),
            deletions=data.get("deletions", 0),
            changed_files=data.get("changed_files", 0),
        )

    async def get_pull_request_files(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        """Get files changed in a pull request."""
        return await self._request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
        )

    async def get_pull_request_diff(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> str:
        """Get the diff for a pull request."""
        await self._ensure_token()

        response = await self._client.get(
            f"/repos/{owner}/{repo}/pulls/{pr_number}",
            headers={
                **self._headers(),
                "Accept": "application/vnd.github.diff",
            },
        )

        if response.status_code >= 400:
            raise GitHubClientError(
                f"Failed to get PR diff: {response.text}",
                response.status_code,
            )

        return response.text

    async def get_commits(
        self,
        owner: str,
        repo: str,
        sha: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        per_page: int = 30,
    ) -> list[GitHubCommit]:
        """Get commits from repository."""
        params: dict[str, Any] = {"per_page": per_page}
        if sha:
            params["sha"] = sha
        if since:
            params["since"] = since.isoformat()
        if until:
            params["until"] = until.isoformat()

        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/commits",
            params=params,
        )

        commits = []
        for item in data:
            commit = item["commit"]
            commits.append(GitHubCommit(
                sha=item["sha"],
                message=commit["message"],
                author_name=commit["author"]["name"],
                author_email=commit["author"]["email"],
                author_date=datetime.fromisoformat(
                    commit["author"]["date"].replace("Z", "+00:00")
                ),
                files=[],  # Would need separate call to get files
            ))

        return commits

    # =========================================================================
    # SUGGEST OPERATIONS (Level 1+)
    # =========================================================================

    async def create_pr_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict[str, Any]:
        """
        Create a comment on a pull request.

        This is a Level 1 operation - suggestions only.
        """
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
            json={"body": body},
        )

    async def create_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        commit_id: str,
        path: str,
        line: int,
        side: str = "RIGHT",
    ) -> dict[str, Any]:
        """
        Create a review comment on a specific line.

        This is a Level 1 operation - suggestions only.
        """
        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/comments",
            json={
                "body": body,
                "commit_id": commit_id,
                "path": path,
                "line": line,
                "side": side,
            },
        )

    async def create_pr_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        event: str = "COMMENT",  # APPROVE, REQUEST_CHANGES, COMMENT
        comments: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Create a pull request review.

        This is a Level 1 operation - suggestions only.
        """
        payload: dict[str, Any] = {
            "body": body,
            "event": event,
        }
        if comments:
            payload["comments"] = comments

        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
            json=payload,
        )

    # =========================================================================
    # WRITE OPERATIONS (Level 2+) - REQUIRE PERMISSION CHECKS
    # =========================================================================

    async def create_branch(
        self,
        owner: str,
        repo: str,
        branch_name: str,
        from_sha: str,
        permission_level: PermissionLevel,
    ) -> dict[str, Any]:
        """
        Create a new branch.

        SAFETY: Validates branch name is not protected.

        Args:
            owner: Repository owner
            repo: Repository name
            branch_name: Name for the new branch
            from_sha: SHA to branch from
            permission_level: Current permission level

        Returns:
            Created ref data
        """
        if permission_level < PermissionLevel.PR_AUTHOR_MODE:
            raise GitHubPermissionError(
                "Branch creation requires PR Author Mode (Level 2+)"
            )

        if not validate_branch_name(branch_name):
            raise GitHubPermissionError(
                f"Cannot create protected branch: {branch_name}"
            )

        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/git/refs",
            json={
                "ref": f"refs/heads/{branch_name}",
                "sha": from_sha,
            },
        )

    async def create_or_update_file(
        self,
        owner: str,
        repo: str,
        path: str,
        message: str,
        content: str,
        branch: str,
        sha: str | None = None,
        permission_level: PermissionLevel = PermissionLevel.READ_ONLY,
    ) -> dict[str, Any]:
        """
        Create or update a file in the repository.

        SAFETY: Validates target branch is not protected.

        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            message: Commit message
            content: File content (will be base64 encoded)
            branch: Target branch
            sha: Current file SHA (required for updates)
            permission_level: Current permission level

        Returns:
            Commit data
        """
        if permission_level < PermissionLevel.PR_AUTHOR_MODE:
            raise GitHubPermissionError(
                "File creation/update requires PR Author Mode (Level 2+)"
            )

        if not validate_branch_name(branch):
            raise GitHubPermissionError(
                f"Cannot commit to protected branch: {branch}"
            )

        import base64
        encoded_content = base64.b64encode(content.encode()).decode()

        payload: dict[str, Any] = {
            "message": message,
            "content": encoded_content,
            "branch": branch,
        }

        if sha:
            payload["sha"] = sha

        return await self._request(
            "PUT",
            f"/repos/{owner}/{repo}/contents/{path}",
            json=payload,
        )

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
        permission_level: PermissionLevel,
        draft: bool = False,
    ) -> GitHubPR:
        """
        Create a pull request.

        SAFETY: CodeOps PRs are clearly labeled and explained.

        Args:
            owner: Repository owner
            repo: Repository name
            title: PR title
            body: PR description with safety analysis
            head: Head branch
            base: Base branch
            permission_level: Current permission level
            draft: Create as draft PR

        Returns:
            Created PR data
        """
        if permission_level < PermissionLevel.PR_AUTHOR_MODE:
            raise GitHubPermissionError(
                "PR creation requires PR Author Mode (Level 2+)"
            )

        # Prefix title to make CodeOps PRs identifiable
        prefixed_title = f"[CodeOps] {title}"

        # Add footer to body
        footer = (
            "\n\n---\n"
            "🤖 *This PR was created by CodeOps AI*\n"
            "Review carefully before merging."
        )

        data = await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": prefixed_title,
                "body": body + footer,
                "head": head,
                "base": base,
                "draft": draft,
            },
        )

        return GitHubPR(
            number=data["number"],
            title=data["title"],
            body=data.get("body"),
            state=data["state"],
            head_ref=data["head"]["ref"],
            base_ref=data["base"]["ref"],
            user_login=data["user"]["login"],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")),
            merged=False,
            mergeable=None,
            html_url=data["html_url"],
            diff_url=data["diff_url"],
            additions=0,
            deletions=0,
            changed_files=0,
        )

    # =========================================================================
    # CHECK RUNS (Level 3 - CI-Bound)
    # =========================================================================

    async def create_check_run(
        self,
        owner: str,
        repo: str,
        name: str,
        head_sha: str,
        status: str = "in_progress",
        conclusion: str | None = None,
        output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Create a check run for CI integration.

        Used for Level 3 CI-bound write mode.
        """
        payload: dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }

        if conclusion:
            payload["conclusion"] = conclusion
            payload["status"] = "completed"

        if output:
            payload["output"] = output

        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/check-runs",
            json=payload,
        )

    async def update_check_run(
        self,
        owner: str,
        repo: str,
        check_run_id: int,
        status: str | None = None,
        conclusion: str | None = None,
        output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Update an existing check run."""
        payload: dict[str, Any] = {}

        if status:
            payload["status"] = status
        if conclusion:
            payload["conclusion"] = conclusion
            payload["status"] = "completed"
        if output:
            payload["output"] = output

        return await self._request(
            "PATCH",
            f"/repos/{owner}/{repo}/check-runs/{check_run_id}",
            json=payload,
        )

    async def get_check_runs_for_ref(
        self,
        owner: str,
        repo: str,
        ref: str,
    ) -> list[dict[str, Any]]:
        """Get all check runs for a reference."""
        data = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/commits/{ref}/check-runs",
        )
        return data.get("check_runs", [])

    async def all_checks_passed(
        self,
        owner: str,
        repo: str,
        ref: str,
    ) -> bool:
        """
        Check if all CI checks have passed for a reference.

        Required for Level 3 CI-bound write operations.
        """
        check_runs = await self.get_check_runs_for_ref(owner, repo, ref)

        if not check_runs:
            return False

        for check in check_runs:
            if check["status"] != "completed":
                return False
            if check["conclusion"] not in ("success", "neutral", "skipped"):
                return False

        return True
