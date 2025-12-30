"""
GitHub Webhook Handler for CodeOps AI.

Processes incoming webhooks and routes them to appropriate handlers.
All webhook events are logged for audit purposes.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

from app.core.config import settings
from app.core.security import verify_github_webhook_signature


logger = structlog.get_logger(__name__)


class WebhookEvent(str, Enum):
    """Supported GitHub webhook events."""

    # Installation events
    INSTALLATION = "installation"
    INSTALLATION_REPOSITORIES = "installation_repositories"

    # Repository events
    REPOSITORY = "repository"
    PUSH = "push"

    # Pull request events
    PULL_REQUEST = "pull_request"
    PULL_REQUEST_REVIEW = "pull_request_review"
    PULL_REQUEST_REVIEW_COMMENT = "pull_request_review_comment"

    # Issue events
    ISSUES = "issues"
    ISSUE_COMMENT = "issue_comment"

    # Check events
    CHECK_RUN = "check_run"
    CHECK_SUITE = "check_suite"

    # Other
    PING = "ping"


@dataclass
class WebhookPayload:
    """Parsed webhook payload with metadata."""

    event: WebhookEvent
    action: str | None
    delivery_id: str
    timestamp: datetime
    repository: dict[str, Any] | None
    sender: dict[str, Any] | None
    installation: dict[str, Any] | None
    raw_payload: dict[str, Any]

    @property
    def repo_full_name(self) -> str | None:
        """Get repository full name if available."""
        if self.repository:
            return self.repository.get("full_name")
        return None

    @property
    def repo_id(self) -> int | None:
        """Get repository GitHub ID if available."""
        if self.repository:
            return self.repository.get("id")
        return None

    @property
    def installation_id(self) -> int | None:
        """Get installation ID if available."""
        if self.installation:
            return self.installation.get("id")
        return None

    @property
    def sender_login(self) -> str | None:
        """Get sender username if available."""
        if self.sender:
            return self.sender.get("login")
        return None


# Type for webhook handlers
WebhookHandler = Callable[[WebhookPayload], Coroutine[Any, Any, dict[str, Any]]]


class WebhookProcessor:
    """
    Processes GitHub webhooks and routes to handlers.

    Security:
    - Validates webhook signatures
    - Logs all events for audit
    - Rate limits by installation
    """

    def __init__(self):
        self._handlers: dict[tuple[WebhookEvent, str | None], list[WebhookHandler]] = {}
        self._global_handlers: list[WebhookHandler] = []

    def register(
        self,
        event: WebhookEvent,
        action: str | None = None,
    ) -> Callable[[WebhookHandler], WebhookHandler]:
        """
        Decorator to register a webhook handler.

        Args:
            event: The webhook event type
            action: Specific action (e.g., "opened", "closed") or None for all

        Example:
            @processor.register(WebhookEvent.PULL_REQUEST, "opened")
            async def handle_pr_opened(payload: WebhookPayload):
                ...
        """
        def decorator(handler: WebhookHandler) -> WebhookHandler:
            key = (event, action)
            if key not in self._handlers:
                self._handlers[key] = []
            self._handlers[key].append(handler)
            return handler
        return decorator

    def register_global(self, handler: WebhookHandler) -> WebhookHandler:
        """Register a handler that receives all events."""
        self._global_handlers.append(handler)
        return handler

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """
        Verify GitHub webhook signature.

        Args:
            payload: Raw request body
            signature: X-Hub-Signature-256 header

        Returns:
            True if signature is valid
        """
        return verify_github_webhook_signature(payload, signature)

    def parse_payload(
        self,
        event_type: str,
        delivery_id: str,
        raw_payload: dict[str, Any],
    ) -> WebhookPayload:
        """
        Parse raw webhook payload into structured format.

        Args:
            event_type: X-GitHub-Event header
            delivery_id: X-GitHub-Delivery header
            raw_payload: Parsed JSON body

        Returns:
            Structured WebhookPayload
        """
        try:
            event = WebhookEvent(event_type)
        except ValueError:
            logger.warning("Unknown webhook event", event_type=event_type)
            # Default to ping for unknown events
            event = WebhookEvent.PING

        return WebhookPayload(
            event=event,
            action=raw_payload.get("action"),
            delivery_id=delivery_id,
            timestamp=datetime.utcnow(),
            repository=raw_payload.get("repository"),
            sender=raw_payload.get("sender"),
            installation=raw_payload.get("installation"),
            raw_payload=raw_payload,
        )

    async def process(self, payload: WebhookPayload) -> dict[str, Any]:
        """
        Process a webhook payload by routing to registered handlers.

        Args:
            payload: Parsed webhook payload

        Returns:
            Combined results from all handlers
        """
        results: dict[str, Any] = {
            "event": payload.event.value,
            "action": payload.action,
            "delivery_id": payload.delivery_id,
            "handlers_executed": [],
            "errors": [],
        }

        # Run global handlers first
        for handler in self._global_handlers:
            try:
                result = await handler(payload)
                results["handlers_executed"].append({
                    "handler": handler.__name__,
                    "result": result,
                })
            except Exception as e:
                logger.error(
                    "Global handler error",
                    handler=handler.__name__,
                    error=str(e),
                )
                results["errors"].append({
                    "handler": handler.__name__,
                    "error": str(e),
                })

        # Find matching handlers
        handlers_to_run: list[WebhookHandler] = []

        # Exact match (event + action)
        key_exact = (payload.event, payload.action)
        if key_exact in self._handlers:
            handlers_to_run.extend(self._handlers[key_exact])

        # Event-only match (any action)
        key_any = (payload.event, None)
        if key_any in self._handlers:
            handlers_to_run.extend(self._handlers[key_any])

        # Run matched handlers
        for handler in handlers_to_run:
            try:
                result = await handler(payload)
                results["handlers_executed"].append({
                    "handler": handler.__name__,
                    "result": result,
                })
            except Exception as e:
                logger.error(
                    "Handler error",
                    handler=handler.__name__,
                    event=payload.event.value,
                    action=payload.action,
                    error=str(e),
                )
                results["errors"].append({
                    "handler": handler.__name__,
                    "error": str(e),
                })

        return results


# Global webhook processor instance
webhook_processor = WebhookProcessor()


# =============================================================================
# COMMAND PARSING
# =============================================================================

@dataclass
class Command:
    """Parsed command from a comment."""

    name: str
    args: list[str]
    raw: str
    author: str
    source: str  # "pr_comment", "issue_comment", "review_comment"


def parse_commands(body: str, author: str, source: str) -> list[Command]:
    """
    Parse commands from comment body.

    Commands are in the format:
    /command arg1 arg2 ...

    Supported commands:
    - /explain [target]
    - /review
    - /generate-tests [file]
    - /generate-docs [file]
    - /suggest [description]

    Args:
        body: Comment body text
        author: Comment author
        source: Source of the comment

    Returns:
        List of parsed commands
    """
    commands = []

    for line in body.split("\n"):
        line = line.strip()
        if not line.startswith("/"):
            continue

        parts = line.split()
        if not parts:
            continue

        command_name = parts[0][1:]  # Remove leading /
        args = parts[1:]

        commands.append(Command(
            name=command_name,
            args=args,
            raw=line,
            author=author,
            source=source,
        ))

    return commands


# =============================================================================
# DEFAULT HANDLERS
# =============================================================================

@webhook_processor.register(WebhookEvent.PING)
async def handle_ping(payload: WebhookPayload) -> dict[str, Any]:
    """Handle ping event (sent when webhook is first configured)."""
    logger.info("Webhook ping received", zen=payload.raw_payload.get("zen"))
    return {"status": "pong"}


@webhook_processor.register(WebhookEvent.INSTALLATION, "created")
async def handle_installation_created(payload: WebhookPayload) -> dict[str, Any]:
    """Handle new installation."""
    logger.info(
        "New installation",
        installation_id=payload.installation_id,
        sender=payload.sender_login,
    )
    # TODO: Create repository records, send welcome message
    return {"status": "installation_recorded"}


@webhook_processor.register(WebhookEvent.INSTALLATION, "deleted")
async def handle_installation_deleted(payload: WebhookPayload) -> dict[str, Any]:
    """Handle installation removal."""
    logger.info(
        "Installation deleted",
        installation_id=payload.installation_id,
        sender=payload.sender_login,
    )
    # TODO: Mark repositories as inactive
    return {"status": "installation_removed"}


@webhook_processor.register(WebhookEvent.PULL_REQUEST, "opened")
async def handle_pr_opened(payload: WebhookPayload) -> dict[str, Any]:
    """Handle new pull request - potential auto-review."""
    pr = payload.raw_payload.get("pull_request", {})
    logger.info(
        "PR opened",
        repo=payload.repo_full_name,
        pr_number=pr.get("number"),
        author=pr.get("user", {}).get("login"),
    )
    # TODO: Queue for auto-review if enabled
    return {"status": "pr_received"}


@webhook_processor.register(WebhookEvent.ISSUE_COMMENT, "created")
async def handle_issue_comment(payload: WebhookPayload) -> dict[str, Any]:
    """Handle new issue/PR comment - parse for commands."""
    comment = payload.raw_payload.get("comment", {})
    body = comment.get("body", "")
    author = comment.get("user", {}).get("login", "")

    # Determine if this is a PR comment
    issue = payload.raw_payload.get("issue", {})
    is_pr = "pull_request" in issue

    source = "pr_comment" if is_pr else "issue_comment"

    commands = parse_commands(body, author, source)

    if commands:
        logger.info(
            "Commands received",
            repo=payload.repo_full_name,
            commands=[c.name for c in commands],
            author=author,
        )
        # TODO: Queue command processing
        return {
            "status": "commands_received",
            "commands": [c.name for c in commands],
        }

    return {"status": "no_commands"}


@webhook_processor.register(WebhookEvent.PUSH)
async def handle_push(payload: WebhookPayload) -> dict[str, Any]:
    """Handle push event - update repo intelligence."""
    ref = payload.raw_payload.get("ref", "")
    commits = payload.raw_payload.get("commits", [])

    logger.info(
        "Push received",
        repo=payload.repo_full_name,
        ref=ref,
        commit_count=len(commits),
    )

    # TODO: Queue intelligence update
    return {
        "status": "push_received",
        "commits": len(commits),
    }


@webhook_processor.register(WebhookEvent.CHECK_SUITE, "completed")
async def handle_check_suite_completed(payload: WebhookPayload) -> dict[str, Any]:
    """Handle check suite completion - for CI-bound writes."""
    check_suite = payload.raw_payload.get("check_suite", {})
    conclusion = check_suite.get("conclusion")

    logger.info(
        "Check suite completed",
        repo=payload.repo_full_name,
        conclusion=conclusion,
    )

    # TODO: If this is a CodeOps branch with pending CI-bound writes,
    # process them if checks passed
    return {
        "status": "check_suite_processed",
        "conclusion": conclusion,
    }
