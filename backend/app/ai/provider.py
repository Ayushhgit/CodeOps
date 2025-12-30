"""
AI Provider — Unified interface for AI model interactions.

Supports:
- Groq (FREE, fast inference) - llama-3.3-70b, mixtral
- OpenAI GPT models
- Anthropic Claude models

All responses are structured JSON for determinism and reliability.
"""

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

from app.core.config import settings


logger = structlog.get_logger(__name__)


@dataclass
class AIResponse:
    """Structured response from AI provider."""

    content: dict[str, Any]
    model: str
    provider: str
    prompt_hash: str
    token_usage: dict[str, int]
    latency_ms: float
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def input_tokens(self) -> int:
        return self.token_usage.get("input", 0)

    @property
    def output_tokens(self) -> int:
        return self.token_usage.get("output", 0)

    @property
    def total_tokens(self) -> int:
        return self.token_usage.get("total", self.input_tokens + self.output_tokens)


class AIProviderBase(ABC):
    """Abstract base class for AI providers."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0,
    ) -> AIResponse:
        """
        Generate a response from the AI model.

        Args:
            prompt: The user prompt
            system_prompt: System instructions
            json_schema: Expected JSON output schema
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0 = deterministic)

        Returns:
            AIResponse with structured content
        """
        pass

    @staticmethod
    def hash_prompt(prompt: str, system_prompt: str | None = None) -> str:
        """Create a hash of the prompt for reproducibility tracking."""
        content = f"{system_prompt or ''}\n{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Simple completion helper - returns just the text."""
        response = await self.generate(prompt, system_prompt)
        return response.content.get("text", "")


class GroqProvider(AIProviderBase):
    """
    Groq provider - FREE and blazing fast!

    Available models:
    - llama-3.3-70b-versatile (best quality, free)
    - llama-3.1-8b-instant (fastest, free)
    - mixtral-8x7b-32768 (good for long context, free)
    """

    GROQ_BASE_URL = "https://api.groq.com/openai/v1"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.groq_api_key
        self.model = model or settings.ai_model

        if not self.api_key:
            raise ValueError("Groq API key not configured. Get free key at https://console.groq.com")

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0,
    ) -> AIResponse:
        """Generate response using Groq (OpenAI-compatible API)."""
        from openai import AsyncOpenAI
        from time import time

        client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=self.GROQ_BASE_URL,
        )

        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # Add JSON instruction if schema provided
        if json_schema:
            schema_str = json.dumps(json_schema, indent=2)
            json_instruction = (
                f"\n\nYou MUST respond with valid JSON matching this schema:\n"
                f"```json\n{schema_str}\n```\n"
                f"Output ONLY the JSON, no other text or markdown."
            )
            if messages and messages[0]["role"] == "system":
                messages[0]["content"] += json_instruction
            else:
                messages.insert(0, {"role": "system", "content": json_instruction.strip()})

        messages.append({"role": "user", "content": prompt})

        start_time = time()

        try:
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )

            latency_ms = (time() - start_time) * 1000

            content_text = response.choices[0].message.content or ""

            # Parse JSON if expected
            if json_schema:
                try:
                    # Handle potential markdown code blocks
                    clean_text = content_text.strip()
                    if clean_text.startswith("```json"):
                        clean_text = clean_text[7:]
                    if clean_text.startswith("```"):
                        clean_text = clean_text[3:]
                    if clean_text.endswith("```"):
                        clean_text = clean_text[:-3]
                    content = json.loads(clean_text.strip())
                except json.JSONDecodeError as e:
                    logger.error(
                        "Failed to parse JSON response",
                        error=str(e),
                        content=content_text[:500],
                    )
                    content = {"raw": content_text, "parse_error": str(e)}
            else:
                content = {"text": content_text}

            return AIResponse(
                content=content,
                model=self.model,
                provider="groq",
                prompt_hash=self.hash_prompt(prompt, system_prompt),
                token_usage={
                    "input": response.usage.prompt_tokens if response.usage else 0,
                    "output": response.usage.completion_tokens if response.usage else 0,
                    "total": response.usage.total_tokens if response.usage else 0,
                },
                latency_ms=latency_ms,
            )

        except Exception as e:
            logger.error("Groq API error", error=str(e))
            raise


class AnthropicProvider(AIProviderBase):
    """Anthropic Claude provider."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.anthropic_api_key
        self.model = model or settings.ai_model

        if not self.api_key:
            raise ValueError("Anthropic API key not configured")

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0,
    ) -> AIResponse:
        """Generate response using Anthropic Claude."""
        import anthropic
        from time import time

        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        # Build messages
        messages = [{"role": "user", "content": prompt}]

        # If we want JSON, instruct the model
        if json_schema:
            schema_str = json.dumps(json_schema, indent=2)
            json_instruction = (
                f"\n\nRespond with valid JSON matching this schema:\n"
                f"```json\n{schema_str}\n```\n"
                f"Output ONLY the JSON, no other text."
            )
            if system_prompt:
                system_prompt = system_prompt + json_instruction
            else:
                system_prompt = json_instruction

        start_time = time()

        try:
            response = await client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt or "",
                messages=messages,
            )

            latency_ms = (time() - start_time) * 1000

            # Extract content
            content_text = response.content[0].text

            # Parse JSON if expected
            if json_schema:
                try:
                    # Handle potential markdown code blocks
                    if "```json" in content_text:
                        content_text = content_text.split("```json")[1].split("```")[0]
                    elif "```" in content_text:
                        content_text = content_text.split("```")[1].split("```")[0]

                    content = json.loads(content_text.strip())
                except json.JSONDecodeError as e:
                    logger.error(
                        "Failed to parse JSON response",
                        error=str(e),
                        content=content_text[:500],
                    )
                    content = {"raw": content_text, "parse_error": str(e)}
            else:
                content = {"text": content_text}

            return AIResponse(
                content=content,
                model=self.model,
                provider="anthropic",
                prompt_hash=self.hash_prompt(prompt, system_prompt),
                token_usage={
                    "input": response.usage.input_tokens,
                    "output": response.usage.output_tokens,
                    "total": response.usage.input_tokens + response.usage.output_tokens,
                },
                latency_ms=latency_ms,
            )

        except Exception as e:
            logger.error("Anthropic API error", error=str(e))
            raise


class OpenAIProvider(AIProviderBase):
    """OpenAI GPT provider."""

    def __init__(self, api_key: str | None = None, model: str = "gpt-4-turbo-preview"):
        self.api_key = api_key or settings.openai_api_key
        self.model = model

        if not self.api_key:
            raise ValueError("OpenAI API key not configured")

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        json_schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0,
    ) -> AIResponse:
        """Generate response using OpenAI."""
        from openai import AsyncOpenAI
        from time import time

        client = AsyncOpenAI(api_key=self.api_key)

        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # Request JSON if schema provided
        response_format = None
        if json_schema:
            response_format = {"type": "json_object"}
            # Add schema to system prompt
            schema_str = json.dumps(json_schema, indent=2)
            json_instruction = (
                f"\n\nRespond with valid JSON matching this schema:\n"
                f"```json\n{schema_str}\n```"
            )
            if messages[0]["role"] == "system":
                messages[0]["content"] += json_instruction
            else:
                messages.insert(0, {"role": "system", "content": json_instruction})

        start_time = time()

        try:
            kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if response_format:
                kwargs["response_format"] = response_format

            response = await client.chat.completions.create(**kwargs)

            latency_ms = (time() - start_time) * 1000

            content_text = response.choices[0].message.content or ""

            # Parse JSON if expected
            if json_schema:
                try:
                    content = json.loads(content_text)
                except json.JSONDecodeError as e:
                    logger.error(
                        "Failed to parse JSON response",
                        error=str(e),
                        content=content_text[:500],
                    )
                    content = {"raw": content_text, "parse_error": str(e)}
            else:
                content = {"text": content_text}

            return AIResponse(
                content=content,
                model=self.model,
                provider="openai",
                prompt_hash=self.hash_prompt(prompt, system_prompt),
                token_usage={
                    "input": response.usage.prompt_tokens if response.usage else 0,
                    "output": response.usage.completion_tokens if response.usage else 0,
                    "total": response.usage.total_tokens if response.usage else 0,
                },
                latency_ms=latency_ms,
            )

        except Exception as e:
            logger.error("OpenAI API error", error=str(e))
            raise


def get_ai_provider() -> AIProviderBase:
    """Get the configured AI provider."""
    if settings.ai_provider == "groq":
        return GroqProvider()
    elif settings.ai_provider == "anthropic":
        return AnthropicProvider()
    elif settings.ai_provider == "openai":
        return OpenAIProvider()
    else:
        raise ValueError(f"Unknown AI provider: {settings.ai_provider}")


# Convenience alias
AIProvider = GroqProvider  # Default to Groq (free!)
