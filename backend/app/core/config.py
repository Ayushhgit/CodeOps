"""Application configuration with Pydantic settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "CodeOps"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    secret_key: str = Field(..., min_length=32)

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://codeops:codeops@localhost:5432/codeops"
    )

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # GitHub App
    github_app_id: str = ""
    github_app_private_key_path: Path = Path("./github-app-private-key.pem")
    github_webhook_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""

    # AI Providers
    groq_api_key: str = ""  # FREE! Get key at https://console.groq.com
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    ai_provider: Literal["groq", "openai", "anthropic"] = "groq"
    ai_model: str = "llama-3.3-70b-versatile"  # Free on Groq

    # Feature Flags - WRITE ACCESS IS OFF BY DEFAULT
    enable_write_mode: bool = False
    enable_pr_author_mode: bool = False
    enable_ci_bound_write: bool = False

    # Rate Limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_tokens_per_day: int = 100000

    # Audit Logging
    audit_log_retention_days: int = 365

    @field_validator("github_app_private_key_path")
    @classmethod
    def validate_key_path(cls, v: Path) -> Path:
        """Validate GitHub App private key path exists in production."""
        return v

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.app_env == "production"

    @property
    def github_app_private_key(self) -> str | None:
        """Load GitHub App private key from file."""
        if self.github_app_private_key_path.exists():
            return self.github_app_private_key_path.read_text()
        return None

    def get_max_permission_level(self) -> int:
        """
        Get the maximum permission level allowed by configuration.

        Returns:
            0 - Read Only (default)
            1 - Suggest Mode (if write mode enabled)
            2 - PR Author Mode (if PR author mode enabled)
            3 - CI-Bound Write (if CI bound write enabled)
        """
        if self.enable_ci_bound_write:
            return 3
        if self.enable_pr_author_mode:
            return 2
        if self.enable_write_mode:
            return 1
        return 0


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()
