"""
AI Codebase Explainer Feature.

Commands:
- /explain repo     — Explain repository architecture
- /explain file:*   — Explain specific files
- /explain impact   — Explain PR impact

Rules:
- Architecture over implementation
- Plain English first
- No guessing - say "I don't know" if unsure
"""

from dataclasses import dataclass
from typing import Any

import structlog

from app.ai.provider import AIProvider, AIResponse, get_ai_provider
from app.ai.prompts import PromptBuilder
from app.intelligence.graph import DependencyGraph


logger = structlog.get_logger(__name__)


@dataclass
class ExplanationResult:
    """Result of an explanation request."""

    success: bool
    explanation: dict[str, Any]
    ai_response: AIResponse | None = None
    error: str | None = None


class CodebaseExplainer:
    """
    AI-powered codebase explanation feature.

    This is a Level 0 (read-only) feature - no write access needed.
    """

    def __init__(
        self,
        graph: DependencyGraph,
        ai_provider: AIProvider | None = None,
    ):
        """
        Initialize the explainer.

        Args:
            graph: Repository dependency graph
            ai_provider: AI provider (defaults to configured provider)
        """
        self.graph = graph
        self.ai = ai_provider or get_ai_provider()

    async def explain_repository(
        self,
        repo_name: str,
        file_tree: list[str],
        key_files_content: dict[str, str],
    ) -> ExplanationResult:
        """
        Explain the overall repository architecture.

        Args:
            repo_name: Repository name (owner/repo)
            file_tree: List of file paths in the repo
            key_files_content: Content of key files (README, main files, etc.)

        Returns:
            ExplanationResult with architecture explanation
        """
        logger.info(
            "Explaining repository",
            repo=repo_name,
            file_count=len(file_tree),
            key_files=list(key_files_content.keys()),
        )

        try:
            prompt, system_prompt, json_schema = PromptBuilder.explain_repo(
                repo_name=repo_name,
                file_tree=file_tree,
                key_files_content=key_files_content,
            )

            response = await self.ai.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                json_schema=json_schema,
                max_tokens=4096,
                temperature=0,
            )

            return ExplanationResult(
                success=True,
                explanation=response.content,
                ai_response=response,
            )

        except Exception as e:
            logger.error("Failed to explain repository", error=str(e))
            return ExplanationResult(
                success=False,
                explanation={},
                error=str(e),
            )

    async def explain_file(
        self,
        file_path: str,
        file_content: str,
        related_files: dict[str, str] | None = None,
    ) -> ExplanationResult:
        """
        Explain a specific file in detail.

        Args:
            file_path: Path to the file
            file_content: Content of the file
            related_files: Content of related files

        Returns:
            ExplanationResult with file explanation
        """
        logger.info("Explaining file", path=file_path)

        # Get dependencies and dependents from graph
        dependencies = self.graph.get_dependencies(file_path)
        dependents = self.graph.get_dependents(file_path)

        try:
            prompt, system_prompt, json_schema = PromptBuilder.explain_file(
                file_path=file_path,
                file_content=file_content,
                related_files=related_files or {},
                dependencies=dependencies,
                dependents=dependents,
            )

            response = await self.ai.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                json_schema=json_schema,
                max_tokens=4096,
                temperature=0,
            )

            # Enhance with graph information
            explanation = response.content
            explanation["dependencies"] = dependencies
            explanation["dependents"] = dependents
            explanation["blast_radius"] = len(
                self.graph.get_transitive_dependents(file_path)
            )

            return ExplanationResult(
                success=True,
                explanation=explanation,
                ai_response=response,
            )

        except Exception as e:
            logger.error("Failed to explain file", path=file_path, error=str(e))
            return ExplanationResult(
                success=False,
                explanation={},
                error=str(e),
            )

    async def explain_impact(
        self,
        changed_files: list[str],
        file_contents: dict[str, str],
    ) -> ExplanationResult:
        """
        Explain the impact of changes to specific files.

        Used for /explain impact command to understand
        what a PR or set of changes affects.

        Args:
            changed_files: List of changed file paths
            file_contents: Content of changed files

        Returns:
            ExplanationResult with impact analysis
        """
        logger.info(
            "Explaining impact",
            changed_files=changed_files,
        )

        try:
            # Calculate blast radius for each file
            all_affected: set[str] = set()
            file_impacts: dict[str, dict[str, Any]] = {}

            for file_path in changed_files:
                dependents = self.graph.get_transitive_dependents(file_path)
                all_affected.update(dependents)

                file_impacts[file_path] = {
                    "direct_dependents": self.graph.get_dependents(file_path),
                    "transitive_dependents": list(dependents),
                    "blast_radius": len(dependents),
                }

            # Identify services affected
            affected_services = set()
            for file_path in all_affected:
                parts = file_path.split("/")
                for i, part in enumerate(parts):
                    if part in ("services", "apps", "packages") and i + 1 < len(parts):
                        affected_services.add(parts[i + 1])
                        break

            return ExplanationResult(
                success=True,
                explanation={
                    "changed_files": changed_files,
                    "file_impacts": file_impacts,
                    "total_files_affected": len(all_affected),
                    "affected_files": sorted(all_affected)[:100],  # Limit to 100
                    "affected_services": sorted(affected_services),
                    "risk_assessment": self._assess_impact_risk(
                        len(changed_files),
                        len(all_affected),
                        len(affected_services),
                    ),
                },
            )

        except Exception as e:
            logger.error("Failed to explain impact", error=str(e))
            return ExplanationResult(
                success=False,
                explanation={},
                error=str(e),
            )

    def _assess_impact_risk(
        self,
        changed_count: int,
        affected_count: int,
        services_count: int,
    ) -> dict[str, Any]:
        """Assess the risk level of changes based on impact."""
        # Calculate risk score
        score = 0

        # Files affected multiplier
        if affected_count > 50:
            score += 40
        elif affected_count > 20:
            score += 25
        elif affected_count > 10:
            score += 15
        elif affected_count > 5:
            score += 5

        # Services affected multiplier
        if services_count > 3:
            score += 30
        elif services_count > 1:
            score += 15

        # Changed files risk
        if changed_count > 10:
            score += 20
        elif changed_count > 5:
            score += 10

        # Determine level
        if score >= 60:
            level = "critical"
            recommendation = "Requires extensive testing and staged rollout"
        elif score >= 40:
            level = "high"
            recommendation = "Recommend thorough testing and careful review"
        elif score >= 20:
            level = "medium"
            recommendation = "Standard review and testing recommended"
        else:
            level = "low"
            recommendation = "Standard review process"

        return {
            "level": level,
            "score": score,
            "recommendation": recommendation,
        }

    def format_for_github(self, result: ExplanationResult) -> str:
        """
        Format explanation result as GitHub markdown.

        Args:
            result: Explanation result

        Returns:
            Markdown-formatted string
        """
        if not result.success:
            return f"❌ **Error**: {result.error}"

        exp = result.explanation

        sections = []

        # Summary
        if "summary" in exp:
            sections.append(f"## Summary\n\n{exp['summary']}")

        # Purpose
        if "purpose" in exp:
            sections.append(f"## Purpose\n\n{exp['purpose']}")

        # Architecture
        if "architecture" in exp:
            arch = exp["architecture"]
            sections.append(
                f"## Architecture\n\n"
                f"**Pattern**: {arch.get('pattern', 'N/A')}\n\n"
                f"{arch.get('description', '')}"
            )
            if "key_components" in arch:
                components = "\n".join(f"- {c}" for c in arch["key_components"])
                sections.append(f"### Key Components\n\n{components}")

        # Tech Stack
        if "tech_stack" in exp:
            stack = exp["tech_stack"]
            stack_lines = []
            for category, items in stack.items():
                if items:
                    stack_lines.append(f"- **{category.title()}**: {', '.join(items)}")
            if stack_lines:
                sections.append(f"## Tech Stack\n\n" + "\n".join(stack_lines))

        # Services
        if "services" in exp and exp["services"]:
            services_content = []
            for svc in exp["services"]:
                services_content.append(
                    f"### {svc['name']}\n"
                    f"{svc.get('responsibility', '')}"
                )
            sections.append("## Services\n\n" + "\n\n".join(services_content))

        # Risks
        if "risks" in exp and exp["risks"]:
            risks = "\n".join(f"- ⚠️ {r}" for r in exp["risks"])
            sections.append(f"## Potential Risks\n\n{risks}")

        # Impact info
        if "blast_radius" in exp:
            sections.append(
                f"## Impact\n\n"
                f"- **Blast Radius**: {exp['blast_radius']} files potentially affected"
            )

        return "\n\n".join(sections)
