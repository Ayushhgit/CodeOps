"""Security utilities for CodeOps AI."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import settings


def verify_github_webhook_signature(payload: bytes, signature: str) -> bool:
    """
    Verify GitHub webhook signature.

    Args:
        payload: Raw request body
        signature: X-Hub-Signature-256 header value

    Returns:
        True if signature is valid
    """
    if not settings.github_webhook_secret:
        return False

    expected = hmac.new(
        settings.github_webhook_secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()

    expected_signature = f"sha256={expected}"

    return hmac.compare_digest(expected_signature, signature)


def generate_github_app_jwt() -> str:
    """
    Generate a JWT for GitHub App authentication.

    Returns:
        JWT string for authenticating as the GitHub App
    """
    if not settings.github_app_private_key:
        raise ValueError("GitHub App private key not configured")

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


def generate_installation_token(installation_id: int) -> dict[str, Any]:
    """
    Generate an installation access token for a specific installation.

    This token is used for repository operations.

    Args:
        installation_id: GitHub App installation ID

    Returns:
        Token response from GitHub API
    """
    # This would make an API call to GitHub
    # POST /app/installations/{installation_id}/access_tokens
    raise NotImplementedError("Use GitHubClient.get_installation_token()")


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def hash_sensitive_data(data: str) -> str:
    """
    Hash sensitive data for storage.

    Used for storing tokens, secrets, etc. in audit logs
    without exposing the actual values.
    """
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def create_signed_url(
    resource: str,
    expires_in: int = 3600,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a signed URL for temporary access to a resource.

    Args:
        resource: Resource identifier
        expires_in: Seconds until expiration
        extra_claims: Additional JWT claims

    Returns:
        Signed URL token
    """
    now = datetime.utcnow()
    payload = {
        "sub": resource,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        **(extra_claims or {}),
    }

    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def verify_signed_url(token: str) -> dict[str, Any] | None:
    """
    Verify a signed URL token.

    Args:
        token: The JWT token to verify

    Returns:
        Decoded payload if valid, None otherwise
    """
    try:
        return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


class RateLimiter:
    """
    Simple in-memory rate limiter.

    In production, use Redis-based rate limiting.
    """

    def __init__(self):
        self._requests: dict[str, list[datetime]] = {}

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """
        Check if a request is allowed under rate limits.

        Args:
            key: Identifier (user ID, IP, etc.)
            max_requests: Maximum requests in window
            window_seconds: Time window in seconds

        Returns:
            True if request is allowed
        """
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)

        # Get existing requests for this key
        requests = self._requests.get(key, [])

        # Filter to only requests within window
        requests = [r for r in requests if r > window_start]

        # Check if under limit
        if len(requests) >= max_requests:
            return False

        # Record this request
        requests.append(now)
        self._requests[key] = requests

        return True

    def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        self._requests.pop(key, None)


# Global rate limiter instance
rate_limiter = RateLimiter()
