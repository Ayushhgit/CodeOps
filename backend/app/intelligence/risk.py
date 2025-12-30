"""
Risk Analyzer — Identifies and scores risk hotspots.

Analyzes the repository to identify areas of high risk:
- High complexity code
- Frequently changed files
- Critical paths with low test coverage
- Security-sensitive code
- Files with many dependents
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.intelligence.analyzer import FileAnalysis
from app.intelligence.graph import DependencyGraph
from app.models.intelligence import RiskLevel


@dataclass
class RiskFactor:
    """A single risk factor for a file or symbol."""

    name: str
    description: str
    severity: RiskLevel
    score: float  # 0-100
    mitigation: str | None = None


@dataclass
class RiskAssessment:
    """Complete risk assessment for a file."""

    file_path: str
    overall_risk: RiskLevel
    overall_score: float  # 0-100
    factors: list[RiskFactor]
    affected_services: list[str]
    blast_radius: int  # Number of files affected
    recommendations: list[str]


class RiskAnalyzer:
    """
    Analyzes repository to identify risk hotspots.

    Risk is calculated based on multiple factors:
    1. Complexity - High cyclomatic/cognitive complexity
    2. Churn - Frequently modified files
    3. Coverage - Low or no test coverage
    4. Centrality - Many files depend on this
    5. Security - Handles auth, crypto, payments, etc.
    6. Size - Very large files are risky
    """

    # Security-sensitive patterns
    SECURITY_PATTERNS = [
        ("auth", "Authentication code - security critical"),
        ("login", "Login handling - security critical"),
        ("password", "Password handling - security critical"),
        ("crypto", "Cryptographic operations - security critical"),
        ("encrypt", "Encryption code - security critical"),
        ("token", "Token handling - security critical"),
        ("jwt", "JWT handling - security critical"),
        ("oauth", "OAuth implementation - security critical"),
        ("permission", "Permission checks - security critical"),
        ("role", "Role-based access - security critical"),
        ("secret", "Secret handling - security critical"),
        ("key", "Key management - security critical"),
        ("payment", "Payment processing - business critical"),
        ("billing", "Billing code - business critical"),
        ("checkout", "Checkout flow - business critical"),
        ("admin", "Admin functionality - elevated access"),
    ]

    # Thresholds for risk scoring
    COMPLEXITY_HIGH = 20
    COMPLEXITY_CRITICAL = 40
    SIZE_HIGH = 500  # lines
    SIZE_CRITICAL = 1000  # lines
    DEPENDENTS_HIGH = 10
    DEPENDENTS_CRITICAL = 25

    def __init__(self, graph: DependencyGraph):
        """
        Initialize risk analyzer.

        Args:
            graph: The dependency graph for the repository
        """
        self.graph = graph
        self._centrality_cache: dict[str, float] | None = None
        self._cache_timestamp: datetime | None = None
        self._cache_ttl = timedelta(minutes=5)  # Cache TTL

    def invalidate_cache(self) -> None:
        """Invalidate the centrality cache."""
        self._centrality_cache = None
        self._cache_timestamp = None

    def _is_cache_valid(self) -> bool:
        """Check if the centrality cache is still valid."""
        if self._centrality_cache is None:
            return False
        if self._cache_timestamp is None:
            return False
        return datetime.utcnow() - self._cache_timestamp < self._cache_ttl

    def analyze_file(
        self,
        analysis: FileAnalysis,
        change_history: list[datetime] | None = None,
        test_coverage: float | None = None,
    ) -> RiskAssessment:
        """
        Perform full risk analysis on a file.

        Args:
            analysis: File analysis result
            change_history: List of commit timestamps (for churn analysis)
            test_coverage: Test coverage percentage (0-100)

        Returns:
            Complete risk assessment
        """
        factors = []

        # 1. Complexity risk
        complexity_factor = self._assess_complexity(analysis)
        if complexity_factor:
            factors.append(complexity_factor)

        # 2. Size risk
        size_factor = self._assess_size(analysis)
        if size_factor:
            factors.append(size_factor)

        # 3. Churn risk
        if change_history:
            churn_factor = self._assess_churn(analysis.path, change_history)
            if churn_factor:
                factors.append(churn_factor)

        # 4. Coverage risk
        coverage_factor = self._assess_coverage(analysis.path, test_coverage)
        if coverage_factor:
            factors.append(coverage_factor)

        # 5. Centrality risk
        centrality_factor = self._assess_centrality(analysis.path)
        if centrality_factor:
            factors.append(centrality_factor)

        # 6. Security risk
        security_factors = self._assess_security(analysis)
        factors.extend(security_factors)

        # Calculate overall risk
        overall_score = self._calculate_overall_score(factors)
        overall_risk = self._score_to_level(overall_score)

        # Get blast radius
        affected_files = self.graph.get_transitive_dependents(analysis.path)
        blast_radius = len(affected_files)

        # Detect affected services
        affected_services = self._get_affected_services(analysis.path, affected_files)

        # Generate recommendations
        recommendations = self._generate_recommendations(factors, analysis)

        return RiskAssessment(
            file_path=analysis.path,
            overall_risk=overall_risk,
            overall_score=overall_score,
            factors=factors,
            affected_services=affected_services,
            blast_radius=blast_radius,
            recommendations=recommendations,
        )

    def _assess_complexity(self, analysis: FileAnalysis) -> RiskFactor | None:
        """Assess complexity risk."""
        if not analysis.complexity:
            return None

        if analysis.complexity >= self.COMPLEXITY_CRITICAL:
            return RiskFactor(
                name="high_complexity",
                description=f"Cyclomatic complexity of {analysis.complexity:.0f} is critically high",
                severity=RiskLevel.CRITICAL,
                score=90,
                mitigation="Refactor into smaller, focused functions",
            )
        elif analysis.complexity >= self.COMPLEXITY_HIGH:
            return RiskFactor(
                name="elevated_complexity",
                description=f"Cyclomatic complexity of {analysis.complexity:.0f} is elevated",
                severity=RiskLevel.HIGH,
                score=70,
                mitigation="Consider breaking down complex logic",
            )

        return None

    def _assess_size(self, analysis: FileAnalysis) -> RiskFactor | None:
        """Assess file size risk."""
        if analysis.line_count >= self.SIZE_CRITICAL:
            return RiskFactor(
                name="very_large_file",
                description=f"File has {analysis.line_count} lines - very large",
                severity=RiskLevel.HIGH,
                score=75,
                mitigation="Split into multiple focused modules",
            )
        elif analysis.line_count >= self.SIZE_HIGH:
            return RiskFactor(
                name="large_file",
                description=f"File has {analysis.line_count} lines - larger than recommended",
                severity=RiskLevel.MEDIUM,
                score=50,
                mitigation="Consider extracting some functionality",
            )

        return None

    def _assess_churn(
        self,
        file_path: str,
        history: list[datetime],
    ) -> RiskFactor | None:
        """Assess change frequency risk."""
        # Count changes in last 30 days - use timedelta for correct calculation
        now = datetime.utcnow()
        thirty_days_ago = now - timedelta(days=30)

        recent_changes = sum(1 for dt in history if dt > thirty_days_ago)

        if recent_changes >= 20:
            return RiskFactor(
                name="high_churn",
                description=f"Modified {recent_changes} times in last 30 days",
                severity=RiskLevel.HIGH,
                score=80,
                mitigation="Stabilize before making additional changes",
            )
        elif recent_changes >= 10:
            return RiskFactor(
                name="elevated_churn",
                description=f"Modified {recent_changes} times in last 30 days",
                severity=RiskLevel.MEDIUM,
                score=55,
                mitigation="Consider why this file changes frequently",
            )

        return None

    def _assess_coverage(
        self,
        file_path: str,
        coverage: float | None,
    ) -> RiskFactor | None:
        """Assess test coverage risk."""
        if coverage is None:
            return RiskFactor(
                name="unknown_coverage",
                description="Test coverage is unknown",
                severity=RiskLevel.MEDIUM,
                score=40,
                mitigation="Set up coverage reporting",
            )

        if coverage < 10:
            return RiskFactor(
                name="no_tests",
                description=f"Test coverage is only {coverage:.0f}%",
                severity=RiskLevel.HIGH,
                score=85,
                mitigation="Add unit tests before modifying",
            )
        elif coverage < 50:
            return RiskFactor(
                name="low_coverage",
                description=f"Test coverage is {coverage:.0f}%",
                severity=RiskLevel.MEDIUM,
                score=50,
                mitigation="Increase test coverage",
            )

        return None

    def _assess_centrality(self, file_path: str) -> RiskFactor | None:
        """Assess centrality risk (how many files depend on this)."""
        # Check if cache needs refresh
        if not self._is_cache_valid():
            self._centrality_cache = self.graph.get_centrality_scores()
            self._cache_timestamp = datetime.utcnow()

        centrality = self._centrality_cache.get(file_path, 0)
        dependents = self.graph.get_dependents(file_path)
        dependent_count = len(dependents)

        if dependent_count >= self.DEPENDENTS_CRITICAL:
            return RiskFactor(
                name="critical_dependency",
                description=f"{dependent_count} files directly depend on this",
                severity=RiskLevel.CRITICAL,
                score=95,
                mitigation="Changes require extensive testing; consider feature flag",
            )
        elif dependent_count >= self.DEPENDENTS_HIGH:
            return RiskFactor(
                name="high_dependency",
                description=f"{dependent_count} files directly depend on this",
                severity=RiskLevel.HIGH,
                score=70,
                mitigation="Test all dependent modules after changes",
            )

        return None

    def _assess_security(self, analysis: FileAnalysis) -> list[RiskFactor]:
        """Assess security-related risks."""
        factors = []
        path_lower = analysis.path.lower()

        for pattern, description in self.SECURITY_PATTERNS:
            if pattern in path_lower:
                factors.append(RiskFactor(
                    name=f"security_{pattern}",
                    description=description,
                    severity=RiskLevel.HIGH,
                    score=80,
                    mitigation="Require security review for changes",
                ))

        # Check for symbols that might be security-sensitive
        for symbol in analysis.symbols:
            name_lower = symbol.name.lower()
            for pattern, description in self.SECURITY_PATTERNS[:10]:  # Check first 10 patterns
                if pattern in name_lower:
                    factors.append(RiskFactor(
                        name=f"security_symbol_{pattern}",
                        description=f"Symbol '{symbol.name}' appears security-sensitive",
                        severity=RiskLevel.HIGH,
                        score=75,
                        mitigation="Review carefully for security implications",
                    ))
                    break

        return factors

    def _calculate_overall_score(self, factors: list[RiskFactor]) -> float:
        """
        Calculate overall risk score from individual factors.

        Uses weighted maximum - the highest risk factor dominates,
        but additional factors increase the score.
        """
        if not factors:
            return 0

        # Sort by score descending
        sorted_factors = sorted(factors, key=lambda f: f.score, reverse=True)

        # Start with highest score
        overall = sorted_factors[0].score

        # Add diminishing contributions from other factors
        for i, factor in enumerate(sorted_factors[1:], 1):
            contribution = factor.score * (0.5 ** i)
            overall = min(100, overall + contribution * 0.2)

        return overall

    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 85:
            return RiskLevel.CRITICAL
        elif score >= 65:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _get_affected_services(
        self,
        file_path: str,
        affected_files: set[str],
    ) -> list[str]:
        """Identify services affected by changes to a file."""
        services = set()

        # Get service for the target file
        # This would come from the file's metadata in the graph
        # For now, extract from path
        parts = file_path.split("/")
        for i, part in enumerate(parts):
            if part in ("services", "apps", "packages") and i + 1 < len(parts):
                services.add(parts[i + 1])
                break

        # Get services for affected files
        for affected in affected_files:
            parts = affected.split("/")
            for i, part in enumerate(parts):
                if part in ("services", "apps", "packages") and i + 1 < len(parts):
                    services.add(parts[i + 1])
                    break

        return list(services)

    def _generate_recommendations(
        self,
        factors: list[RiskFactor],
        analysis: FileAnalysis,
    ) -> list[str]:
        """Generate actionable recommendations based on risk factors."""
        recommendations = []

        # Add mitigations from factors
        for factor in factors:
            if factor.mitigation:
                recommendations.append(factor.mitigation)

        # Add general recommendations based on overall profile
        has_security_risk = any("security" in f.name for f in factors)
        has_coverage_risk = any("coverage" in f.name for f in factors)
        has_complexity_risk = any("complexity" in f.name for f in factors)

        if has_security_risk and has_coverage_risk:
            recommendations.append(
                "CRITICAL: Security-sensitive code with low test coverage - "
                "add security-focused tests before modifying"
            )

        if has_security_risk:
            recommendations.append(
                "Require peer review from security team for any changes"
            )

        if has_complexity_risk:
            recommendations.append(
                "Consider adding inline documentation for complex logic"
            )

        # Deduplicate while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)

        return unique_recommendations

    def get_hotspots(
        self,
        analyses: list[FileAnalysis],
        limit: int = 20,
    ) -> list[RiskAssessment]:
        """
        Get the riskiest files in the repository.

        Args:
            analyses: List of file analyses
            limit: Maximum number of hotspots to return

        Returns:
            List of risk assessments, sorted by risk score
        """
        assessments = []

        for analysis in analyses:
            assessment = self.analyze_file(analysis)
            if assessment.overall_score > 30:  # Only include notable risks
                assessments.append(assessment)

        # Sort by risk score descending
        assessments.sort(key=lambda a: a.overall_score, reverse=True)

        return assessments[:limit]
