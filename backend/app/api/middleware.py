"""
API Middleware for CodeOps AI.

Provides:
- Correlation ID tracking for distributed tracing
- Input validation
- Request sanitization
- Security headers
"""

import re
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Callable

import structlog
from fastapi import HTTPException, Request, status
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings


logger = structlog.get_logger(__name__)

# Context variable for correlation ID - accessible throughout the request
correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id", default="")


def get_correlation_id() -> str:
    """Get the current request's correlation ID."""
    return correlation_id_ctx.get()


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle correlation IDs for distributed tracing.

    - Accepts incoming X-Correlation-ID header
    - Generates a new ID if not provided
    - Adds correlation ID to response headers
    - Makes correlation ID available via context variable
    """

    CORRELATION_ID_HEADER = "X-Correlation-ID"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get existing correlation ID or generate new one
        correlation_id = request.headers.get(self.CORRELATION_ID_HEADER)

        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        else:
            # Validate format - must be a valid UUID or alphanumeric with dashes
            if not self._is_valid_correlation_id(correlation_id):
                correlation_id = str(uuid.uuid4())

        # Set in context variable for use throughout the request
        correlation_id_ctx.set(correlation_id)

        # Bind to structlog context for automatic inclusion in logs
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
        )

        # Process request
        response = await call_next(request)

        # Add correlation ID to response headers
        response.headers[self.CORRELATION_ID_HEADER] = correlation_id

        return response

    @staticmethod
    def _is_valid_correlation_id(correlation_id: str) -> bool:
        """Validate correlation ID format."""
        if not correlation_id or len(correlation_id) > 64:
            return False
        # Allow UUIDs and alphanumeric with dashes/underscores
        return bool(re.match(r'^[a-zA-Z0-9\-_]+$', correlation_id))


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Prevent XSS
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        # Strict Transport Security (only in production)
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response


class InputValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for input validation and sanitization.

    - Validates Content-Type for POST/PUT/PATCH
    - Checks request body size limits
    - Validates path parameters for injection attempts
    - Logs suspicious requests
    """

    MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB

    # Patterns that should never appear in URLs
    INJECTION_PATTERNS = [
        r'\.\.',           # Path traversal
        r'%2e%2e',         # URL-encoded path traversal
        r'%252e%252e',     # Double-encoded path traversal
        r'<script',        # XSS attempt
        r'%3cscript',      # URL-encoded XSS
        r'\x00',           # Null byte
        r'%00',            # URL-encoded null byte
    ]

    def __init__(self, app):
        super().__init__(app)
        self._injection_regex = re.compile(
            '|'.join(self.INJECTION_PATTERNS),
            re.IGNORECASE
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check for path injection attempts
        path = request.url.path
        if self._contains_injection_pattern(path):
            logger.warning(
                "Blocked request with suspicious path",
                path=path,
                client_ip=self._get_client_ip(request),
                correlation_id=get_correlation_id(),
            )
            return Response(
                content='{"error": "Invalid request path"}',
                status_code=status.HTTP_400_BAD_REQUEST,
                media_type="application/json",
            )

        # Validate Content-Type for requests with body
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = request.headers.get("content-type", "")

            # For non-webhook endpoints, require JSON content type
            if not path.startswith("/webhooks"):
                if content_type and not self._is_valid_content_type(content_type):
                    return Response(
                        content='{"error": "Unsupported Content-Type. Use application/json"}',
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        media_type="application/json",
                    )

            # Check Content-Length
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self.MAX_BODY_SIZE:
                        logger.warning(
                            "Blocked oversized request",
                            content_length=content_length,
                            max_size=self.MAX_BODY_SIZE,
                            correlation_id=get_correlation_id(),
                        )
                        return Response(
                            content='{"error": "Request body too large"}',
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            media_type="application/json",
                        )
                except ValueError:
                    pass

        return await call_next(request)

    def _contains_injection_pattern(self, path: str) -> bool:
        """Check if path contains injection patterns."""
        return bool(self._injection_regex.search(path))

    @staticmethod
    def _is_valid_content_type(content_type: str) -> bool:
        """Check if content type is acceptable."""
        valid_types = [
            "application/json",
            "application/x-www-form-urlencoded",
        ]
        return any(content_type.startswith(t) for t in valid_types)

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Get client IP, handling proxies."""
        # Check X-Forwarded-For first (for proxied requests)
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Take the first IP in the chain
            return forwarded.split(",")[0].strip()

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiting middleware for API protection.

    Uses the Redis-based rate limiter from security module.
    """

    # Endpoints exempt from rate limiting
    EXEMPT_PATHS = [
        "/health",
        "/health/live",
        "/health/ready",
        "/",
    ]

    # Rate limit window in seconds (1 minute)
    WINDOW_SECONDS = 60

    def __init__(self, app):
        super().__init__(app)
        self._rate_limiter = None

    def _get_rate_limiter(self):
        """Lazy initialization of rate limiter."""
        if self._rate_limiter is None:
            from app.core.security import get_rate_limiter
            self._rate_limiter = get_rate_limiter()
        return self._rate_limiter

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Get client identifier for rate limiting
        client_id = self._get_rate_limit_key(request)

        rate_limiter = self._get_rate_limiter()
        max_requests = settings.rate_limit_requests_per_minute

        # Check rate limit
        allowed = await rate_limiter.is_allowed(
            client_id,
            max_requests,
            self.WINDOW_SECONDS,
        )

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                client_id=client_id,
                path=request.url.path,
                correlation_id=get_correlation_id(),
            )
            # Get remaining info for headers
            remaining, reset_time = await rate_limiter.get_remaining(
                client_id,
                max_requests,
                self.WINDOW_SECONDS,
            )
            response = Response(
                content='{"error": "Rate limit exceeded. Please try again later."}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json",
            )
            response.headers["X-RateLimit-Limit"] = str(max_requests)
            response.headers["X-RateLimit-Remaining"] = "0"
            response.headers["X-RateLimit-Reset"] = str(int(reset_time))
            response.headers["Retry-After"] = str(int(reset_time) + 1)
            return response

        # Process request
        response = await call_next(request)

        # Get remaining for headers
        remaining, reset_time = await rate_limiter.get_remaining(
            client_id,
            max_requests,
            self.WINDOW_SECONDS,
        )

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(reset_time))

        return response

    def _get_rate_limit_key(self, request: Request) -> str:
        """Generate rate limit key from request."""
        # Use IP address as the primary identifier
        # In production, you might want to use authenticated user ID instead
        client_ip = InputValidationMiddleware._get_client_ip(request)

        # Different limits for different endpoints
        path_prefix = request.url.path.split("/")[1] if "/" in request.url.path else ""

        return f"{client_ip}:{path_prefix}"


# Pydantic validators for common input patterns

def validate_repo_full_name(value: str) -> str:
    """
    Validate repository full name (owner/repo format).

    Security: Prevents injection attacks via repo name.
    """
    if not value or len(value) > 200:
        raise ValueError("Invalid repository name length")

    # Must be owner/repo format
    if "/" not in value:
        raise ValueError("Repository name must be in owner/repo format")

    parts = value.split("/")
    if len(parts) != 2:
        raise ValueError("Repository name must be in owner/repo format")

    owner, repo = parts

    # GitHub username/repo restrictions
    pattern = r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?$'

    if not re.match(pattern, owner):
        raise ValueError("Invalid owner name")

    # Repo name can include dots and underscores
    repo_pattern = r'^[a-zA-Z0-9._\-]+$'
    if not re.match(repo_pattern, repo):
        raise ValueError("Invalid repository name")

    return value


def validate_branch_name(value: str) -> str:
    """
    Validate branch name.

    Security: Prevents injection attacks via branch name.
    """
    if not value or len(value) > 250:
        raise ValueError("Invalid branch name length")

    # Forbidden patterns in git branch names
    forbidden = [
        '..',       # Double dots
        '~',        # Tilde
        '^',        # Caret
        ':',        # Colon
        '?',        # Question mark
        '*',        # Asterisk
        '[',        # Square bracket
        '\\',       # Backslash
        '\x00',     # Null byte
    ]

    for char in forbidden:
        if char in value:
            raise ValueError(f"Branch name contains forbidden character: {char}")

    # Cannot start or end with /
    if value.startswith('/') or value.endswith('/'):
        raise ValueError("Branch name cannot start or end with /")

    # Cannot start with -
    if value.startswith('-'):
        raise ValueError("Branch name cannot start with -")

    # Cannot end with .lock
    if value.endswith('.lock'):
        raise ValueError("Branch name cannot end with .lock")

    return value


def validate_file_path(value: str) -> str:
    """
    Validate file path.

    Security: Prevents path traversal attacks.
    """
    if not value or len(value) > 1000:
        raise ValueError("Invalid file path length")

    # Normalize and validate
    from app.core.permissions import normalize_path

    normalized = normalize_path(value)
    if not normalized:
        raise ValueError("Invalid file path")

    # Check for suspicious patterns
    forbidden_patterns = [
        '..',           # Parent directory
        '~',            # Home directory
        '$',            # Variable expansion
        '`',            # Command substitution
        '\x00',         # Null byte
    ]

    for pattern in forbidden_patterns:
        if pattern in value:
            raise ValueError(f"File path contains forbidden pattern: {pattern}")

    return normalized


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize a string input.

    - Strips leading/trailing whitespace
    - Removes null bytes
    - Truncates to max length
    """
    if not value:
        return ""

    # Remove null bytes
    value = value.replace('\x00', '')

    # Strip whitespace
    value = value.strip()

    # Truncate
    if len(value) > max_length:
        value = value[:max_length]

    return value
