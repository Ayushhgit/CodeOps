"""
Repository Intelligence Engine — The Core Moat of CodeOps.

Maintains a persistent, evolving model of the repository:
- File dependency graph
- Symbol graph (functions, classes, APIs)
- Service boundaries
- Data flow
- Test coverage signals
- Risk hotspots

This intelligence:
- Updates incrementally per commit
- Is reused across all features
- Is referenced before every write action
"""

from app.intelligence.analyzer import RepoAnalyzer
from app.intelligence.graph import DependencyGraph
from app.intelligence.risk import RiskAnalyzer

__all__ = ["RepoAnalyzer", "DependencyGraph", "RiskAnalyzer"]
