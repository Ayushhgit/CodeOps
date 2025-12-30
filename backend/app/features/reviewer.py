"""
AI Code Reviewer Feature.

This feature is ABSOLUTELY READ-ONLY.

Reviews PRs for:
- Security issues
- Performance risks
- Concurrency hazards
- Cost explosions

Explains business impact, not style.
"""

from dataclasses import dataclass
from typing import Any

import structlog

from app.ai.provider import AIProvider, AIResponse, get_ai_provider
from app.ai.prompts import PromptBuilder
from app.intelligence.analyzer import FileAnalysis
from app.intelligence.graph import DependencyGraph
from app.intelligence.risk import RiskAnalyzer


logger = structlog.get_logger(__name__)


@dataclass
class ReviewResult:
    """Result of a code review."""

    success: bool
    review: dict[str, Any]
    ai_response: AIResponse | None = None
    error: str | None = None


@dataclass
class SecurityIssue:
    """A security issue found during review."""

    severity: str  # low, medium, high, critical
    file: str
    line: int | None
    issue: str
    recommendation: str
    cwe_id: str | None = None  # Common Weakness Enumeration ID


@dataclass
class PerformanceIssue:
    """A performance issue found during review."""

    severity: str
    file: str
    issue: str
    recommendation: str
    estimated_impact: str | None = None


class CodeReviewer:
    """
    AI-powered code review feature.

    IMPORTANT: This is a Level 0 (read-only) feature.
    It NEVER makes changes to the codebase.
    It only reads and comments.
    """

    # Common security patterns to look for
    SECURITY_PATTERNS = {
        "sql_injection": [
            r"execute\s*\(\s*[\"'].*%s",
            r"cursor\.execute\s*\(\s*f[\"']",
            r"\.raw\s*\(",
        ],
        "command_injection": [
            r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True",
            r"os\.system\s*\(",
            r"eval\s*\(",
            r"exec\s*\(",
        ],
        "path_traversal": [
            r"open\s*\(\s*request\.",
            r"\.\.\/",
        ],
        "hardcoded_secrets": [
            r"password\s*=\s*[\"'][^\"']+[\"']",
            r"api_key\s*=\s*[\"'][^\"']+[\"']",
            r"secret\s*=\s*[\"'][^\"']+[\"']",
        ],
        "xss": [
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"\{\{\s*\w+\s*\|\s*safe\s*\}\}",
        ],
    }

    def __init__(
        self,
        graph: DependencyGraph,
        risk_analyzer: RiskAnalyzer,
        ai_provider: AIProvider | None = None,
    ):
        """
        Initialize the reviewer.

        Args:
            graph: Repository dependency graph
            risk_analyzer: Risk analysis engine
            ai_provider: AI provider (defaults to configured provider)
        """
        self.graph = graph
        self.risk_analyzer = risk_analyzer
        self.ai = ai_provider or get_ai_provider()

    async def review_pull_request(
        self,
        pr_title: str,
        pr_description: str | None,
        diff: str,
        affected_files: list[str],
        file_analyses: dict[str, FileAnalysis],
    ) -> ReviewResult:
        """
        Perform a comprehensive code review of a pull request.

        Args:
            pr_title: PR title
            pr_description: PR description/body
            diff: The diff content
            affected_files: List of affected file paths
            file_analyses: Analysis results for affected files

        Returns:
            ReviewResult with detailed findings
        """
        logger.info(
            "Reviewing pull request",
            title=pr_title,
            affected_files=len(affected_files),
        )

        try:
            # Perform risk analysis on affected files
            risk_analysis = self._analyze_risks(affected_files, file_analyses)

            # Build prompt and get AI review
            prompt, system_prompt, json_schema = PromptBuilder.review_pr(
                pr_title=pr_title,
                pr_description=pr_description or "",
                diff=diff,
                affected_files=affected_files,
                risk_analysis=risk_analysis,
            )

            response = await self.ai.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                json_schema=json_schema,
                max_tokens=4096,
                temperature=0,
            )

            # Enhance with static analysis
            static_findings = self._static_security_scan(diff)

            review = response.content
            review["static_analysis"] = static_findings
            review["risk_analysis"] = risk_analysis

            return ReviewResult(
                success=True,
                review=review,
                ai_response=response,
            )

        except Exception as e:
            logger.error("Failed to review PR", error=str(e))
            return ReviewResult(
                success=False,
                review={},
                error=str(e),
            )

    def _analyze_risks(
        self,
        affected_files: list[str],
        file_analyses: dict[str, FileAnalysis],
    ) -> dict[str, Any]:
        """Analyze risks for affected files."""
        risks = {
            "high_risk_files": [],
            "total_blast_radius": 0,
            "affected_services": set(),
            "summary": "",
        }

        total_dependents = set()

        for file_path in affected_files:
            analysis = file_analyses.get(file_path)
            if not analysis:
                continue

            # Get risk assessment
            assessment = self.risk_analyzer.analyze_file(analysis)

            if assessment.overall_risk.value in ("high", "critical"):
                risks["high_risk_files"].append({
                    "path": file_path,
                    "risk_level": assessment.overall_risk.value,
                    "factors": [f.name for f in assessment.factors[:3]],
                })

            # Track affected files
            dependents = self.graph.get_transitive_dependents(file_path)
            total_dependents.update(dependents)

            # Track services
            for service in assessment.affected_services:
                risks["affected_services"].add(service)

        risks["total_blast_radius"] = len(total_dependents)
        risks["affected_services"] = list(risks["affected_services"])

        # Generate summary
        if risks["high_risk_files"]:
            risks["summary"] = (
                f"⚠️ {len(risks['high_risk_files'])} high-risk files affected. "
                f"Total blast radius: {risks['total_blast_radius']} files."
            )
        else:
            risks["summary"] = f"Standard risk. Blast radius: {risks['total_blast_radius']} files."

        return risks

    def _static_security_scan(self, diff: str) -> list[dict[str, Any]]:
        """
        Perform static analysis for common security issues.

        This is a quick pattern-based scan to catch obvious issues.
        """
        import re

        findings = []

        for issue_type, patterns in self.SECURITY_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, diff, re.IGNORECASE):
                    # Get context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(diff), match.end() + 50)
                    context = diff[start:end]

                    # Skip if in a removal line (starts with -)
                    lines = context.split("\n")
                    matched_line = next(
                        (l for l in lines if match.group() in l),
                        ""
                    )
                    if matched_line.startswith("-"):
                        continue

                    findings.append({
                        "type": issue_type,
                        "pattern": pattern,
                        "context": context.strip(),
                        "severity": self._get_issue_severity(issue_type),
                    })

        return findings

    def _get_issue_severity(self, issue_type: str) -> str:
        """Get severity level for an issue type."""
        critical_issues = {"sql_injection", "command_injection"}
        high_issues = {"xss", "path_traversal"}

        if issue_type in critical_issues:
            return "critical"
        elif issue_type in high_issues:
            return "high"
        else:
            return "medium"

    def format_for_github(self, result: ReviewResult) -> str:
        """
        Format review result as GitHub PR comment.

        Args:
            result: Review result

        Returns:
            Markdown-formatted comment
        """
        if not result.success:
            return f"❌ **Review Failed**: {result.error}"

        review = result.review
        sections = []

        # Header with overall assessment
        assessment = review.get("overall_assessment", "needs_discussion")
        risk_level = review.get("risk_level", "unknown")

        emoji_map = {
            "approve": "✅",
            "request_changes": "🔴",
            "needs_discussion": "💬",
        }

        risk_emoji = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
        }

        header = (
            f"## {emoji_map.get(assessment, '📋')} CodeOps AI Review\n\n"
            f"**Assessment**: {assessment.replace('_', ' ').title()}\n"
            f"**Risk Level**: {risk_emoji.get(risk_level, '⚪')} {risk_level.upper()}"
        )
        sections.append(header)

        # Summary
        if "summary" in review:
            sections.append(f"### Summary\n\n{review['summary']}")

        # Security Issues
        security_issues = review.get("security_issues", [])
        if security_issues:
            issues_md = []
            for issue in security_issues:
                severity_badge = {
                    "critical": "🔴 CRITICAL",
                    "high": "🟠 HIGH",
                    "medium": "🟡 MEDIUM",
                    "low": "🟢 LOW",
                }.get(issue.get("severity", "medium"), "⚪")

                issues_md.append(
                    f"#### {severity_badge}\n"
                    f"**File**: `{issue.get('file', 'unknown')}`"
                    f"{f' (line {issue[\"line\"]})' if issue.get('line') else ''}\n\n"
                    f"**Issue**: {issue.get('issue', 'Unknown issue')}\n\n"
                    f"**Recommendation**: {issue.get('recommendation', 'N/A')}"
                )

            sections.append(
                "### 🔒 Security Issues\n\n" +
                "\n\n---\n\n".join(issues_md)
            )

        # Performance Issues
        perf_issues = review.get("performance_issues", [])
        if perf_issues:
            issues_md = []
            for issue in perf_issues:
                issues_md.append(
                    f"**File**: `{issue.get('file', 'unknown')}`\n"
                    f"**Issue**: {issue.get('issue', 'Unknown')}\n"
                    f"**Recommendation**: {issue.get('recommendation', 'N/A')}"
                )
            sections.append(
                "### ⚡ Performance Concerns\n\n" +
                "\n\n".join(issues_md)
            )

        # Logic Issues
        logic_issues = review.get("logic_issues", [])
        if logic_issues:
            issues_md = []
            for issue in logic_issues:
                issues_md.append(
                    f"**File**: `{issue.get('file', 'unknown')}`\n"
                    f"**Issue**: {issue.get('issue', 'Unknown')}\n"
                    f"**Recommendation**: {issue.get('recommendation', 'N/A')}"
                )
            sections.append(
                "### 🧠 Logic Concerns\n\n" +
                "\n\n".join(issues_md)
            )

        # Suggestions
        suggestions = review.get("suggestions", [])
        if suggestions:
            suggestions_md = "\n".join(f"- {s}" for s in suggestions)
            sections.append(f"### 💡 Suggestions\n\n{suggestions_md}")

        # Testing Recommendations
        testing = review.get("testing_recommendations", [])
        if testing:
            testing_md = "\n".join(f"- {t}" for t in testing)
            sections.append(f"### 🧪 Testing Recommendations\n\n{testing_md}")

        # Risk Analysis
        risk_analysis = review.get("risk_analysis", {})
        if risk_analysis.get("summary"):
            sections.append(f"### 📊 Risk Analysis\n\n{risk_analysis['summary']}")

        # Footer
        sections.append(
            "---\n"
            "*🤖 This review was generated by CodeOps AI. "
            "Please review all findings carefully.*"
        )

        return "\n\n".join(sections)

    async def create_review_comments(
        self,
        result: ReviewResult,
    ) -> list[dict[str, Any]]:
        """
        Generate inline review comments for specific issues.

        Returns list of comment objects for GitHub API.
        """
        if not result.success:
            return []

        comments = []
        review = result.review

        # Add comments for security issues
        for issue in review.get("security_issues", []):
            if issue.get("file") and issue.get("line"):
                comments.append({
                    "path": issue["file"],
                    "line": issue["line"],
                    "body": (
                        f"🔒 **Security Issue** ({issue.get('severity', 'medium').upper()})\n\n"
                        f"{issue.get('issue', '')}\n\n"
                        f"**Recommendation**: {issue.get('recommendation', 'N/A')}"
                    ),
                })

        # Add comments for performance issues
        for issue in review.get("performance_issues", []):
            if issue.get("file"):
                comments.append({
                    "path": issue["file"],
                    "body": (
                        f"⚡ **Performance Concern**\n\n"
                        f"{issue.get('issue', '')}\n\n"
                        f"**Recommendation**: {issue.get('recommendation', 'N/A')}"
                    ),
                })

        return comments
