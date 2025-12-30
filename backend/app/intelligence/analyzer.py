"""
Repository Analyzer — Core Intelligence Builder.

Analyzes repository structure and builds the intelligence model:
- File analysis
- Symbol extraction
- Dependency mapping
- Service detection
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from app.models.intelligence import FileType, SymbolType, RiskLevel


logger = structlog.get_logger(__name__)


# Language detection patterns
LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
}

# File type detection patterns
TEST_PATTERNS = [
    r"test[_/]",
    r"[_/]test",
    r"tests[_/]",
    r"[_/]tests",
    r"spec[_/]",
    r"[_/]spec",
    r"\.test\.",
    r"\.spec\.",
    r"_test\.",
    r"_spec\.",
]

CONFIG_PATTERNS = [
    r"\.config\.",
    r"\.conf$",
    r"config\.",
    r"\.json$",
    r"\.yaml$",
    r"\.yml$",
    r"\.toml$",
    r"\.ini$",
    r"\.env",
]

DOC_PATTERNS = [
    r"\.md$",
    r"\.rst$",
    r"\.txt$",
    r"README",
    r"CHANGELOG",
    r"LICENSE",
    r"CONTRIBUTING",
    r"docs[/\\]",
]


@dataclass
class FileAnalysis:
    """Result of analyzing a single file."""

    path: str
    file_type: FileType
    language: str | None
    size_bytes: int
    line_count: int
    imports: list[str] = field(default_factory=list)
    symbols: list["SymbolAnalysis"] = field(default_factory=list)
    complexity: float | None = None


@dataclass
class SymbolAnalysis:
    """Result of analyzing a code symbol."""

    name: str
    symbol_type: SymbolType
    line_start: int
    line_end: int
    signature: str | None = None
    docstring: str | None = None
    is_public: bool = True
    calls: list[str] = field(default_factory=list)
    # For API endpoints
    http_method: str | None = None
    route_path: str | None = None


class RepoAnalyzer:
    """
    Analyzes repository contents to build intelligence model.

    This is the core of the intelligence engine that parses
    files, extracts symbols, and builds the dependency graph.
    """

    def __init__(self, repo_path: str | Path):
        """
        Initialize analyzer for a repository.

        Args:
            repo_path: Path to the repository root
        """
        self.repo_path = Path(repo_path)

    def detect_file_type(self, path: str) -> FileType:
        """Detect the type of a file based on its path."""
        path_lower = path.lower()

        # Check test patterns
        for pattern in TEST_PATTERNS:
            if re.search(pattern, path_lower):
                return FileType.TEST

        # Check doc patterns
        for pattern in DOC_PATTERNS:
            if re.search(pattern, path_lower):
                return FileType.DOCUMENTATION

        # Check config patterns
        for pattern in CONFIG_PATTERNS:
            if re.search(pattern, path_lower):
                return FileType.CONFIG

        # Check build files
        build_files = {
            "makefile", "cmakelists.txt", "build.gradle",
            "pom.xml", "cargo.toml", "package.json",
            "requirements.txt", "setup.py", "pyproject.toml",
            ".github", "dockerfile", "docker-compose",
            "jenkinsfile", ".travis.yml", ".circleci",
        }
        if any(bf in path_lower for bf in build_files):
            return FileType.BUILD

        # Check for source code
        ext = Path(path).suffix.lower()
        if ext in LANGUAGE_EXTENSIONS:
            return FileType.SOURCE

        # Check for data files
        data_extensions = {".json", ".xml", ".csv", ".sql", ".graphql"}
        if ext in data_extensions:
            return FileType.DATA

        # Check for assets
        asset_extensions = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".ttf"}
        if ext in asset_extensions:
            return FileType.ASSET

        return FileType.OTHER

    def detect_language(self, path: str) -> str | None:
        """Detect programming language from file extension."""
        ext = Path(path).suffix.lower()
        return LANGUAGE_EXTENSIONS.get(ext)

    async def analyze_file(self, file_path: str, content: str) -> FileAnalysis:
        """
        Analyze a single file.

        Args:
            file_path: Path relative to repo root
            content: File content

        Returns:
            FileAnalysis with extracted information
        """
        file_type = self.detect_file_type(file_path)
        language = self.detect_language(file_path)

        lines = content.split("\n")
        line_count = len(lines)
        size_bytes = len(content.encode("utf-8"))

        analysis = FileAnalysis(
            path=file_path,
            file_type=file_type,
            language=language,
            size_bytes=size_bytes,
            line_count=line_count,
        )

        # Extract imports and symbols based on language
        if language == "python":
            analysis.imports = self._extract_python_imports(content)
            analysis.symbols = self._extract_python_symbols(content, lines)
        elif language in ("javascript", "typescript"):
            analysis.imports = self._extract_js_imports(content)
            analysis.symbols = self._extract_js_symbols(content, lines)
        elif language == "go":
            analysis.imports = self._extract_go_imports(content)
            analysis.symbols = self._extract_go_symbols(content, lines)

        return analysis

    def _extract_python_imports(self, content: str) -> list[str]:
        """Extract Python imports."""
        imports = []

        # Match 'import x' and 'from x import y'
        import_pattern = r"^(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))"

        for line in content.split("\n"):
            line = line.strip()
            match = re.match(import_pattern, line)
            if match:
                module = match.group(1) or match.group(2)
                if module:
                    imports.append(module)

        return imports

    def _extract_python_symbols(self, content: str, lines: list[str]) -> list[SymbolAnalysis]:
        """Extract Python functions and classes."""
        symbols = []

        # Match function definitions
        func_pattern = r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\((.*?)\)(?:\s*->\s*(\S+))?\s*:"
        class_pattern = r"^(\s*)class\s+(\w+)(?:\s*\((.*?)\))?\s*:"

        in_docstring = False
        current_symbol: SymbolAnalysis | None = None

        for i, line in enumerate(lines, 1):
            # Check for class
            class_match = re.match(class_pattern, line)
            if class_match:
                indent, name, bases = class_match.groups()
                current_symbol = SymbolAnalysis(
                    name=name,
                    symbol_type=SymbolType.CLASS,
                    line_start=i,
                    line_end=i,  # Will be updated
                    is_public=not name.startswith("_"),
                )
                symbols.append(current_symbol)
                continue

            # Check for function/method
            func_match = re.match(func_pattern, line)
            if func_match:
                indent, name, params, return_type = func_match.groups()

                # Determine if it's a method (indented) or function
                is_method = len(indent) > 0
                symbol_type = SymbolType.METHOD if is_method else SymbolType.FUNCTION

                current_symbol = SymbolAnalysis(
                    name=name,
                    symbol_type=symbol_type,
                    line_start=i,
                    line_end=i,
                    signature=f"def {name}({params})" + (f" -> {return_type}" if return_type else ""),
                    is_public=not name.startswith("_"),
                )
                symbols.append(current_symbol)

        return symbols

    def _extract_js_imports(self, content: str) -> list[str]:
        """Extract JavaScript/TypeScript imports."""
        imports = []

        # Match ES6 imports
        import_pattern = r"import\s+.*?\s+from\s+['\"](.+?)['\"]"
        require_pattern = r"require\s*\(\s*['\"](.+?)['\"]"

        for match in re.finditer(import_pattern, content):
            imports.append(match.group(1))

        for match in re.finditer(require_pattern, content):
            imports.append(match.group(1))

        return imports

    def _extract_js_symbols(self, content: str, lines: list[str]) -> list[SymbolAnalysis]:
        """Extract JavaScript/TypeScript functions and classes."""
        symbols = []

        # Match function declarations
        func_patterns = [
            r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(",
            r"(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\(",
            r"(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?function",
        ]

        class_pattern = r"(?:export\s+)?class\s+(\w+)"
        interface_pattern = r"(?:export\s+)?interface\s+(\w+)"
        type_pattern = r"(?:export\s+)?type\s+(\w+)"

        for i, line in enumerate(lines, 1):
            # Check for class
            class_match = re.search(class_pattern, line)
            if class_match:
                symbols.append(SymbolAnalysis(
                    name=class_match.group(1),
                    symbol_type=SymbolType.CLASS,
                    line_start=i,
                    line_end=i,
                    is_public="export" in line,
                ))
                continue

            # Check for interface (TypeScript)
            interface_match = re.search(interface_pattern, line)
            if interface_match:
                symbols.append(SymbolAnalysis(
                    name=interface_match.group(1),
                    symbol_type=SymbolType.INTERFACE,
                    line_start=i,
                    line_end=i,
                    is_public="export" in line,
                ))
                continue

            # Check for type alias (TypeScript)
            type_match = re.search(type_pattern, line)
            if type_match:
                symbols.append(SymbolAnalysis(
                    name=type_match.group(1),
                    symbol_type=SymbolType.TYPE,
                    line_start=i,
                    line_end=i,
                    is_public="export" in line,
                ))
                continue

            # Check for functions
            for pattern in func_patterns:
                func_match = re.search(pattern, line)
                if func_match:
                    symbols.append(SymbolAnalysis(
                        name=func_match.group(1),
                        symbol_type=SymbolType.FUNCTION,
                        line_start=i,
                        line_end=i,
                        is_public="export" in line,
                    ))
                    break

        return symbols

    def _extract_go_imports(self, content: str) -> list[str]:
        """Extract Go imports."""
        imports = []

        # Match single import
        single_pattern = r'import\s+"([^"]+)"'
        for match in re.finditer(single_pattern, content):
            imports.append(match.group(1))

        # Match import block
        block_pattern = r'import\s*\(\s*(.*?)\s*\)'
        for match in re.finditer(block_pattern, content, re.DOTALL):
            block = match.group(1)
            for line in block.split("\n"):
                line = line.strip()
                pkg_match = re.search(r'"([^"]+)"', line)
                if pkg_match:
                    imports.append(pkg_match.group(1))

        return imports

    def _extract_go_symbols(self, content: str, lines: list[str]) -> list[SymbolAnalysis]:
        """Extract Go functions and types."""
        symbols = []

        func_pattern = r"func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\("
        type_pattern = r"type\s+(\w+)\s+(struct|interface)"

        for i, line in enumerate(lines, 1):
            # Check for type definitions
            type_match = re.search(type_pattern, line)
            if type_match:
                name, kind = type_match.groups()
                symbol_type = SymbolType.CLASS if kind == "struct" else SymbolType.INTERFACE
                symbols.append(SymbolAnalysis(
                    name=name,
                    symbol_type=symbol_type,
                    line_start=i,
                    line_end=i,
                    is_public=name[0].isupper(),
                ))
                continue

            # Check for functions
            func_match = re.search(func_pattern, line)
            if func_match:
                name = func_match.group(1)
                # Check if it's a method (has receiver)
                is_method = ")" in line.split("func")[1].split(name)[0]
                symbols.append(SymbolAnalysis(
                    name=name,
                    symbol_type=SymbolType.METHOD if is_method else SymbolType.FUNCTION,
                    line_start=i,
                    line_end=i,
                    is_public=name[0].isupper(),
                ))

        return symbols

    def detect_api_endpoints(self, content: str, language: str) -> list[SymbolAnalysis]:
        """Detect API endpoints in code."""
        endpoints = []

        if language == "python":
            # FastAPI/Flask patterns
            patterns = [
                (r'@app\.(\w+)\s*\(\s*["\']([^"\']+)["\']', "flask"),
                (r'@router\.(\w+)\s*\(\s*["\']([^"\']+)["\']', "fastapi"),
                (r'@api\.(\w+)\s*\(\s*["\']([^"\']+)["\']', "flask-restx"),
            ]

            for pattern, framework in patterns:
                for match in re.finditer(pattern, content):
                    method, path = match.groups()
                    endpoints.append(SymbolAnalysis(
                        name=path,
                        symbol_type=SymbolType.ENDPOINT,
                        line_start=0,  # Would need line tracking
                        line_end=0,
                        http_method=method.upper(),
                        route_path=path,
                    ))

        elif language in ("javascript", "typescript"):
            # Express patterns
            patterns = [
                r'app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                r'router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            ]

            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    method, path = match.groups()
                    endpoints.append(SymbolAnalysis(
                        name=path,
                        symbol_type=SymbolType.ENDPOINT,
                        line_start=0,
                        line_end=0,
                        http_method=method.upper(),
                        route_path=path,
                    ))

        return endpoints

    def detect_service_boundary(self, file_path: str, imports: list[str]) -> str | None:
        """
        Detect which service a file belongs to.

        Uses directory structure and import patterns to identify
        service boundaries in the codebase.
        """
        parts = Path(file_path).parts

        # Common service directory patterns
        service_indicators = {"services", "apps", "packages", "modules", "domains"}

        for i, part in enumerate(parts[:-1]):
            if part.lower() in service_indicators and i + 1 < len(parts):
                return parts[i + 1]

        # Check for monorepo package structure
        if "packages" in parts:
            idx = parts.index("packages")
            if idx + 1 < len(parts):
                return parts[idx + 1]

        return None
