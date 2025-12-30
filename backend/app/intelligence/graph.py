"""
Dependency Graph — Maps relationships between files and symbols.

Builds and maintains:
- File dependency graph
- Symbol call graph
- Import/export relationships
- Data flow paths
"""

from dataclasses import dataclass, field
from typing import Any, Iterator

import networkx as nx

from app.intelligence.analyzer import FileAnalysis


@dataclass
class GraphNode:
    """Node in the dependency graph."""

    id: str
    node_type: str  # file, symbol, service
    path: str | None = None
    name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Edge in the dependency graph."""

    source: str
    target: str
    edge_type: str  # imports, calls, implements, extends
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


class DependencyGraph:
    """
    Builds and queries the dependency graph for a repository.

    The graph captures:
    - Which files import which other files
    - Which symbols call which other symbols
    - Service boundaries and cross-service dependencies
    - Data flow through the codebase
    """

    def __init__(self):
        """Initialize an empty dependency graph."""
        self._graph = nx.DiGraph()
        self._file_nodes: dict[str, GraphNode] = {}
        self._symbol_nodes: dict[str, GraphNode] = {}

    def add_file(self, analysis: FileAnalysis) -> GraphNode:
        """
        Add a file to the graph.

        Args:
            analysis: File analysis result

        Returns:
            The created graph node
        """
        node = GraphNode(
            id=f"file:{analysis.path}",
            node_type="file",
            path=analysis.path,
            metadata={
                "file_type": analysis.file_type.value,
                "language": analysis.language,
                "line_count": analysis.line_count,
                "size_bytes": analysis.size_bytes,
            },
        )

        self._file_nodes[analysis.path] = node
        self._graph.add_node(
            node.id,
            **node.metadata,
            node_type=node.node_type,
            path=node.path,
        )

        # Add symbol nodes
        for symbol in analysis.symbols:
            symbol_id = f"symbol:{analysis.path}:{symbol.name}"
            symbol_node = GraphNode(
                id=symbol_id,
                node_type="symbol",
                path=analysis.path,
                name=symbol.name,
                metadata={
                    "symbol_type": symbol.symbol_type.value,
                    "line_start": symbol.line_start,
                    "line_end": symbol.line_end,
                    "is_public": symbol.is_public,
                    "signature": symbol.signature,
                },
            )
            self._symbol_nodes[symbol_id] = symbol_node
            self._graph.add_node(
                symbol_id,
                **symbol_node.metadata,
                node_type="symbol",
                path=symbol_node.path,
                name=symbol_node.name,
            )

            # Connect symbol to its file
            self._graph.add_edge(
                node.id,
                symbol_id,
                edge_type="contains",
            )

        return node

    def add_import(self, source_path: str, imported_module: str) -> None:
        """
        Add an import relationship.

        Args:
            source_path: Path of the importing file
            imported_module: Module or file being imported
        """
        source_id = f"file:{source_path}"

        # Try to resolve the import to a file in the graph
        target_id = self._resolve_import(source_path, imported_module)

        if target_id:
            self._graph.add_edge(
                source_id,
                target_id,
                edge_type="imports",
                module=imported_module,
            )

    def _resolve_import(self, source_path: str, module: str) -> str | None:
        """
        Resolve an import string to a file in the graph.

        Args:
            source_path: Path of the importing file
            module: Import string (e.g., "app.services.auth")

        Returns:
            File node ID if resolved, None otherwise
        """
        # Convert module path to potential file paths
        potential_paths = []

        # Python-style module path
        py_path = module.replace(".", "/")
        potential_paths.extend([
            f"{py_path}.py",
            f"{py_path}/__init__.py",
        ])

        # JavaScript-style imports
        if not module.startswith("."):
            # External package, skip
            return None

        # Relative import - resolve based on source path
        # This is simplified; full resolution would be more complex

        # Check if any potential path exists in our graph
        for path in potential_paths:
            if path in self._file_nodes:
                return f"file:{path}"

        return None

    def add_call(self, caller: str, callee: str) -> None:
        """
        Add a function call relationship.

        Args:
            caller: ID of the calling symbol
            callee: ID of the called symbol
        """
        if caller in self._symbol_nodes and callee in self._symbol_nodes:
            self._graph.add_edge(
                caller,
                callee,
                edge_type="calls",
            )

    def get_dependents(self, file_path: str) -> list[str]:
        """
        Get files that depend on a given file.

        These are files that import the target file.

        Args:
            file_path: Path of the file

        Returns:
            List of file paths that depend on this file
        """
        node_id = f"file:{file_path}"

        if node_id not in self._graph:
            return []

        dependents = []
        for predecessor in self._graph.predecessors(node_id):
            edge_data = self._graph.get_edge_data(predecessor, node_id)
            if edge_data and edge_data.get("edge_type") == "imports":
                if predecessor.startswith("file:"):
                    dependents.append(predecessor[5:])  # Remove "file:" prefix

        return dependents

    def get_dependencies(self, file_path: str) -> list[str]:
        """
        Get files that a given file depends on.

        These are files that the target file imports.

        Args:
            file_path: Path of the file

        Returns:
            List of file paths this file depends on
        """
        node_id = f"file:{file_path}"

        if node_id not in self._graph:
            return []

        dependencies = []
        for successor in self._graph.successors(node_id):
            edge_data = self._graph.get_edge_data(node_id, successor)
            if edge_data and edge_data.get("edge_type") == "imports":
                if successor.startswith("file:"):
                    dependencies.append(successor[5:])

        return dependencies

    def get_transitive_dependents(
        self,
        file_path: str,
        max_depth: int = 10,
    ) -> set[str]:
        """
        Get all files that transitively depend on a file.

        This is the "blast radius" - all files affected if this file changes.

        Args:
            file_path: Path of the file
            max_depth: Maximum depth to traverse

        Returns:
            Set of all dependent file paths
        """
        node_id = f"file:{file_path}"

        if node_id not in self._graph:
            return set()

        visited = set()
        to_visit = [(node_id, 0)]

        while to_visit:
            current, depth = to_visit.pop(0)

            if current in visited or depth > max_depth:
                continue

            visited.add(current)

            for predecessor in self._graph.predecessors(current):
                edge_data = self._graph.get_edge_data(predecessor, current)
                if edge_data and edge_data.get("edge_type") == "imports":
                    if predecessor.startswith("file:"):
                        to_visit.append((predecessor, depth + 1))

        # Remove the original file and convert to paths
        visited.discard(node_id)
        return {v[5:] for v in visited if v.startswith("file:")}

    def get_centrality_scores(self) -> dict[str, float]:
        """
        Calculate centrality scores for all files.

        High centrality = many files depend on this file.
        Changes to high-centrality files are risky.

        Returns:
            Dict mapping file paths to centrality scores
        """
        # Use PageRank for centrality (considers both direct and indirect importance)
        try:
            pagerank = nx.pagerank(self._graph)
        except nx.PowerIterationFailedConvergence:
            # Fall back to degree centrality
            pagerank = nx.in_degree_centrality(self._graph)

        # Filter to only file nodes and normalize
        file_centrality = {}
        for node_id, score in pagerank.items():
            if node_id.startswith("file:"):
                file_centrality[node_id[5:]] = score

        return file_centrality

    def find_circular_dependencies(self) -> list[list[str]]:
        """
        Find circular dependencies in the codebase.

        Circular dependencies can cause issues and are often
        a code smell indicating poor architecture.

        Returns:
            List of cycles, where each cycle is a list of file paths
        """
        # Build subgraph of just file-to-file import edges
        file_graph = nx.DiGraph()

        for source, target, data in self._graph.edges(data=True):
            if (
                source.startswith("file:") and
                target.startswith("file:") and
                data.get("edge_type") == "imports"
            ):
                file_graph.add_edge(source[5:], target[5:])

        # Find all simple cycles
        try:
            cycles = list(nx.simple_cycles(file_graph))
            return cycles
        except Exception:
            return []

    def get_service_boundaries(self) -> dict[str, list[str]]:
        """
        Group files by detected service boundaries.

        Returns:
            Dict mapping service names to lists of file paths
        """
        services: dict[str, list[str]] = {}

        for path, node in self._file_nodes.items():
            service = node.metadata.get("service")
            if service:
                if service not in services:
                    services[service] = []
                services[service].append(path)

        return services

    def get_cross_service_dependencies(self) -> list[tuple[str, str, str, str]]:
        """
        Find dependencies that cross service boundaries.

        Returns:
            List of (source_service, source_file, target_service, target_file) tuples
        """
        cross_deps = []

        for source, target, data in self._graph.edges(data=True):
            if not (source.startswith("file:") and target.startswith("file:")):
                continue

            if data.get("edge_type") != "imports":
                continue

            source_path = source[5:]
            target_path = target[5:]

            source_service = self._file_nodes.get(source_path, GraphNode("", "")).metadata.get("service")
            target_service = self._file_nodes.get(target_path, GraphNode("", "")).metadata.get("service")

            if source_service and target_service and source_service != target_service:
                cross_deps.append((source_service, source_path, target_service, target_path))

        return cross_deps

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "nodes": [
                {
                    "id": node,
                    **self._graph.nodes[node],
                }
                for node in self._graph.nodes
            ],
            "edges": [
                {
                    "source": source,
                    "target": target,
                    **data,
                }
                for source, target, data in self._graph.edges(data=True)
            ],
            "stats": {
                "total_nodes": self._graph.number_of_nodes(),
                "total_edges": self._graph.number_of_edges(),
                "file_count": len(self._file_nodes),
                "symbol_count": len(self._symbol_nodes),
            },
        }
