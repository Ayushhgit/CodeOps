"""Security utilities for CodeOps AI."""

import asyncio
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Any

import jwt
import redis.asyncio as redis
import structlog

from app.core.config import settings


logger = structlog.get_logger(__name__)


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
        logger.error("Webhook secret not configured - rejecting all webhooks")
        return False

    if not signature:
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

    # Use integer timestamps for JWT claims (not datetime objects)
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
    # Use integer timestamps for JWT claims
    now = int(time.time())
    payload = {
        "sub": resource,
        "iat": now,
        "exp": now + expires_in,
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


class RedisRateLimiter:
    """
    Redis-based rate limiter with sliding window algorithm.

    Thread-safe and distributed - works across multiple instances.
    """

    def __init__(self, redis_url: str | None = None):
        """
        Initialize the rate limiter.

        Args:
            redis_url: Redis connection URL (defaults to settings)
        """
        self._redis_url = redis_url or settings.redis_url
        self._redis: redis.Redis | None = None
        self._lock = asyncio.Lock()

    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            async with self._lock:
                if self._redis is None:
                    self._redis = redis.from_url(
                        self._redis_url,
                        encoding="utf-8",
                        decode_responses=True,
                    )
        return self._redis

    async def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> bool:
        """
        Check if a request is allowed under rate limits using sliding window.

        This is atomic and thread-safe.

        Args:
            key: Identifier (user ID, IP, repo, etc.)
            max_requests: Maximum requests in window
            window_seconds: Time window in seconds

        Returns:
            True if request is allowed
        """
        try:
            r = await self._get_redis()
            now = time.time()
            window_start = now - window_seconds

            # Use a sorted set with timestamps as scores
            rate_key = f"ratelimit:{key}"

            # Pipeline for atomic operations
            pipe = r.pipeline()

            # Remove old entries outside the window
            pipe.zremrangebyscore(rate_key, 0, window_start)

            # Count current entries in window
            pipe.zcard(rate_key)

            # Add current request with timestamp as score
            pipe.zadd(rate_key, {str(now): now})

            # Set TTL on the key to auto-cleanup
            pipe.expire(rate_key, window_seconds + 1)

            results = await pipe.execute()
            current_count = results[1]

            # Check if under limit (count was before adding current request)
            if current_count >= max_requests:
                # Remove the request we just added since it's not allowed
                await r.zrem(rate_key, str(now))
                return False

            return True

        except Exception as e:
            logger.error("Rate limiter error, allowing request", error=str(e))
            # Fail open - allow request if Redis is down
            # In production, you might want to fail closed instead
            return True

    async def get_remaining(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[int, float]:
        """
        Get remaining requests and time until reset.

        Args:
            key: Rate limit key
            max_requests: Maximum requests in window
            window_seconds: Time window in seconds

        Returns:
            Tuple of (remaining_requests, seconds_until_reset)
        """
        try:
            r = await self._get_redis()
            now = time.time()
            window_start = now - window_seconds

            rate_key = f"ratelimit:{key}"

            # Count current entries in window
            await r.zremrangebyscore(rate_key, 0, window_start)
            current_count = await r.zcard(rate_key)

            remaining = max(0, max_requests - current_count)

            # Get oldest entry to calculate reset time
            oldest = await r.zrange(rate_key, 0, 0, withscores=True)
            if oldest:
                oldest_time = oldest[0][1]
                reset_in = max(0, (oldest_time + window_seconds) - now)
            else:
                reset_in = 0

            return remaining, reset_in

        except Exception as e:
            logger.error("Rate limiter error", error=str(e))
            return max_requests, 0

    async def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        try:
            r = await self._get_redis()
            await r.delete(f"ratelimit:{key}")
        except Exception as e:
            logger.error("Rate limiter reset error", error=str(e))

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None


class InMemoryRateLimiter:
    """
    Thread-safe in-memory rate limiter for development/testing.

    Uses asyncio.Lock for thread safety.
    NOT suitable for production with multiple instances.
    """

    def __init__(self):
        self._requests: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> bool:
        """
        Check if a request is allowed under rate limits.

        Thread-safe with asyncio.Lock.
        """
        async with self._lock:
            now = time.time()
            window_start = now - window_seconds

            # Get and filter existing requests
            requests = self._requests.get(key, [])
            requests = [r for r in requests if r > window_start]

            # Check if under limit
            if len(requests) >= max_requests:
                self._requests[key] = requests
                return False

            # Record this request
            requests.append(now)
            self._requests[key] = requests

            return True

    async def get_remaining(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[int, float]:
        """Get remaining requests and time until reset."""
        async with self._lock:
            now = time.time()
            window_start = now - window_seconds

            requests = self._requests.get(key, [])
            requests = [r for r in requests if r > window_start]

            remaining = max(0, max_requests - len(requests))

            if requests:
                oldest = min(requests)
                reset_in = max(0, (oldest + window_seconds) - now)
            else:
                reset_in = 0

            return remaining, reset_in

    async def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        async with self._lock:
            self._requests.pop(key, None)

    async def close(self) -> None:
        """No-op for in-memory limiter."""
        pass


def get_rate_limiter() -> RedisRateLimiter | InMemoryRateLimiter:
    """
    Get the appropriate rate limiter based on configuration.

    Uses Redis in production, in-memory for development.
    """
    if settings.redis_url and settings.app_env != "development":
        return RedisRateLimiter()
    else:
        logger.warning("Using in-memory rate limiter - not suitable for production")
        return InMemoryRateLimiter()


# Global rate limiter instance
rate_limiter = get_rate_limiter()
