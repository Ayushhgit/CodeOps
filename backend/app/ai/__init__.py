"""
AI Provider Abstraction Layer.

Provides a unified interface for different AI providers:
- OpenAI
- Anthropic

Features:
- Structured JSON outputs only
- Deterministic prompts
- Token usage tracking
"""

from app.ai.provider import AIProvider, AIResponse
from app.ai.prompts import PromptBuilder

__all__ = ["AIProvider", "AIResponse", "PromptBuilder"]
