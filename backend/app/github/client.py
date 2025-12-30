"""
GitHub API Client for CodeOps AI.

Handles all interactions with the GitHub API including:
- Repository operations
- Pull request management
- Branch operations
- Commit operations
- Check runs

IMPORTANT: All write operations go through the safety model.

Features:
- Token refresh with locking (prevents token refresh storm)
- Circuit breaker pattern (prevents cascading failures)
- Retry with exponential backoff
- Comprehensive error handling
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import httpx
import jwt
import structlog

from app.core.config import settings
from app.core.permissions import (
    PermissionLevel,
    validate_branch_name,
)


logger = structlog.get_logger(__name__)


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

    def __init__(self, message: str, status_code: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


class GitHubRateLimitError(GitHubClientError):
    """Raised when GitHub rate limit is exceeded."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message, status_code=429, retryable=True)
        self.retry_after = retry_after


class GitHubPermissionError(GitHubClientError):
    """Raised when operation is not permitted."""

    def __init__(self, message: str):
        super().__init__(message, status_code=403, retryable=False)


class GitHubNotFoundError(GitHubClientError):
    """Raised when resource is not found."""

    def __init__(self, message: str):
        super().__init__(message, status_code=404, retryable=False)


class CircuitBreakerState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreaker:
    """
    Circuit breaker pattern implementation.

    Prevents cascading failures by failing fast when a service is down.
    """

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3

    _state: CircuitBreakerState = field(default=CircuitBreakerState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float | None = field(default=None, init=False)
    _half_open_calls: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    @property
    def state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        return self._state

    async def can_execute(self) -> bool:
        """Check if a request can be executed."""
        async with self._lock:
            if self._state == CircuitBreakerState.CLOSED:
                return True

            if self._state == CircuitBreakerState.OPEN:
                # Check if recovery timeout has passed
                if self._last_failure_time and \
                   time.time() - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info("Circuit breaker entering half-open state")
                    return True
                return False

            if self._state == CircuitBreakerState.HALF_OPEN:
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False

            return False

    async def record_success(self) -> None:
        """Record a successful request."""
        async with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._state = CircuitBreakerState.CLOSED
                logger.info("Circuit breaker closed - service recovered")
            self._failure_count = 0

    async def record_failure(self) -> None:
        """Record a failed request."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitBreakerState.HALF_OPEN:
                self._state = CircuitBreakerState.OPEN
                logger.warning("Circuit breaker reopened - service still failing")
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitBreakerState.OPEN
                logger.warning(
                    "Circuit breaker opened",
                    failure_count=self._failure_count,
                )


class GitHubClient:
    """
    GitHub API client with safety controls.

    All write operations are gated by permission checks.

    Features:
    - Thread-safe token refresh with locking
    - Circuit breaker for fault tolerance
    - Retry with exponential backoff
    """

    BASE_URL = "https://api.github.com"
    MAX_RETRIES = 3
    BASE_RETRY_DELAY = 1.0  # seconds

    def __init__(self, installation_id: int):
        """
        Initialize GitHub client for an installation.

        Args:
            installation_id: GitHub App installation ID
        """
        self.installation_id = installation_id
        self._token: str | None = None
        self._token_expires: float | None = None  # Unix timestamp
        self._token_lock = asyncio.Lock()
        self._circuit_breaker = CircuitBreaker()
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )

    async def __aenter__(self):
        await self._ensure_token()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._client.aclose()

    async def _ensure_token(self) -> None:
        """
        Ensure we have a valid installation access token.

        Uses locking to prevent multiple concurrent refresh attempts.
        """
        # Quick check without lock
        if self._token and self._token_expires and time.time() < self._token_expires:
            return

        # Acquire lock for token refresh
        async with self._token_lock:
            # Double-check after acquiring lock (another coroutine may have refreshed)
            if self._token and self._token_expires and time.time() < self._token_expires:
                return

            logger.debug("Refreshing GitHub installation token")

            # Generate JWT for app authentication
            app_jwt = self._generate_app_jwt()

            # Get installation access token with retry
            for attempt in range(self.MAX_RETRIES):
                try:
                    response = await self._client.post(
                        f"/app/installations/{self.installation_id}/access_tokens",
                        headers={
                            "Authorization": f"Bearer {app_jwt}",
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )

                    if response.status_code == 201:
                        data = response.json()
                        self._token = data["token"]
                        # Token expires in 1 hour, refresh 5 minutes early
                        self._token_expires = time.time() + (55 * 60)
                        logger.debug("GitHub token refreshed successfully")
                        return

                    if response.status_code >= 500:
                        # Server error, retry
                        if attempt < self.MAX_RETRIES - 1:
                            delay = self.BASE_RETRY_DELAY * (2 ** attempt)
                            await asyncio.sleep(delay)
                            continue

                    raise GitHubClientError(
                        f"Failed to get installation token: {response.text}",
                        response.status_code,
                    )

                except httpx.RequestError as e:
                    if attempt < self.MAX_RETRIES - 1:
                        delay = self.BASE_RETRY_DELAY * (2 ** attempt)
                        await asyncio.sleep(delay)
                        continue
                    raise GitHubClientError(f"Network error: {str(e)}", retryable=True)

    def _generate_app_jwt(self) -> str:
        """Generate JWT for GitHub App authentication."""
        if not settings.github_app_private_key:
            raise GitHubClientError("GitHub App private key not configured")

        # Use integer timestamps for JWT claims
        now = int(time.time())
        payload = {
            "iat": now,
            "exp": now + (10 * 60),  # 10 minutes
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
        retry: bool = True,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Make an API request with error handling, circuit breaker, and retry.

        Args:
            method: HTTP method
            path: API path
            retry: Whether to retry on failure
            **kwargs: Additional arguments for httpx

        Returns:
            JSON response data
        """
        # Check circuit breaker
        if not await self._circuit_breaker.can_execute():
            raise GitHubClientError(
                "Circuit breaker is open - GitHub API temporarily unavailable",
                retryable=True,
            )

        await self._ensure_token()

        last_error: Exception | None = None
        max_attempts = self.MAX_RETRIES if retry else 1

        for attempt in range(max_attempts):
            try:
                response = await self._client.request(
                    method,
                    path,
                    headers=self._headers(),
                    **kwargs,
                )

                # Handle different status codes
                if response.status_code == 204:
                    await self._circuit_breaker.record_success()
                    return {}

                if response.status_code < 300:
                    await self._circuit_breaker.record_success()
                    return response.json()

                # Error handling
                if response.status_code == 401:
                    # Token might be invalid, clear it and retry
                    self._token = None
                    self._token_expires = None
                    if attempt < max_attempts - 1:
                        await self._ensure_token()
                        continue
                    raise GitHubClientError("Authentication failed", 401)

                if response.status_code == 403:
                    error_text = response.text.lower()
                    if "rate limit" in error_text:
                        retry_after = response.headers.get("Retry-After")
                        await self._circuit_breaker.record_failure()
                        raise GitHubRateLimitError(
                            "GitHub rate limit exceeded",
                            retry_after=int(retry_after) if retry_after else None,
                        )
                    raise GitHubPermissionError(f"Permission denied: {response.text}")

                if response.status_code == 404:
                    raise GitHubNotFoundError(f"Not found: {path}")

                if response.status_code >= 500:
                    # Server error, retry with backoff
                    await self._circuit_breaker.record_failure()
                    if attempt < max_attempts - 1:
                        delay = self.BASE_RETRY_DELAY * (2 ** attempt)
                        logger.warning(
                            "GitHub server error, retrying",
                            status_code=response.status_code,
                            attempt=attempt + 1,
                            delay=delay,
                        )
                        await asyncio.sleep(delay)
                        continue

                raise GitHubClientError(
                    f"GitHub API error: {response.text}",
                    response.status_code,
                )

            except httpx.RequestError as e:
                await self._circuit_breaker.record_failure()
                last_error = e
                if attempt < max_attempts - 1:
                    delay = self.BASE_RETRY_DELAY * (2 ** attempt)
                    logger.warning(
                        "Network error, retrying",
                        error=str(e),
                        attempt=attempt + 1,
                        delay=delay,
                    )
                    await asyncio.sleep(delay)
                    continue

        raise GitHubClientError(f"Request failed after {max_attempts} attempts: {last_error}")

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
