"""
Prompt Builder — Deterministic prompts for AI operations.

All prompts are:
- Structured and versioned
- Focused on factual analysis
- Include safety reminders
- Request JSON outputs
"""

from typing import Any


class PromptBuilder:
    """
    Builds deterministic prompts for AI operations.

    Each prompt type has a specific structure and version.
    """

    # Prompt versions for tracking
    VERSIONS = {
        "explain_repo": "1.0",
        "explain_file": "1.0",
        "explain_impact": "1.0",
        "review_pr": "1.0",
        "generate_tests": "1.0",
        "generate_docs": "1.0",
    }

    # Common system prompt prefix
    SYSTEM_PREFIX = """You are CodeOps AI, a senior software engineer assistant that helps teams understand and maintain their codebase.

Your core principles:
1. Accuracy over speed - Never guess or make assumptions
2. Architecture over implementation - Focus on the big picture
3. Plain English first - Explain complex concepts simply
4. Business impact - Explain why something matters

Important safety rules:
- Never suggest changes to protected branches (main, master, production)
- Always explain the blast radius of changes
- Flag security-sensitive code explicitly
- If unsure about anything, say so clearly
"""

    @classmethod
    def explain_repo(
        cls,
        repo_name: str,
        file_tree: list[str],
        key_files_content: dict[str, str],
    ) -> tuple[str, str, dict[str, Any]]:
        """
        Build prompt to explain repository architecture.

        Returns:
            Tuple of (prompt, system_prompt, json_schema)
        """
        system_prompt = cls.SYSTEM_PREFIX + """
You are analyzing a repository to explain its architecture.
Focus on:
- Overall purpose and domain
- Key architectural patterns used
- Service/module boundaries
- Entry points and data flow
- Technology stack and dependencies
"""

        # Build file tree representation
        tree_str = "\n".join(f"  {f}" for f in file_tree[:200])  # Limit to 200 files

        # Build key files content
        files_content = ""
        for path, content in list(key_files_content.items())[:10]:  # Limit to 10 files
            files_content += f"\n\n=== {path} ===\n{content[:2000]}"  # Limit content

        prompt = f"""Analyze this repository: {repo_name}

FILE STRUCTURE:
{tree_str}

KEY FILES:
{files_content}

Provide a comprehensive analysis of the repository architecture.
"""

        json_schema = {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "2-3 sentence summary of what this repo does"
                },
                "purpose": {
                    "type": "string",
                    "description": "Detailed explanation of the project's purpose"
                },
                "architecture": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "description": {"type": "string"},
                        "key_components": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "tech_stack": {
                    "type": "object",
                    "properties": {
                        "languages": {"type": "array", "items": {"type": "string"}},
                        "frameworks": {"type": "array", "items": {"type": "string"}},
                        "databases": {"type": "array", "items": {"type": "string"}},
                        "infrastructure": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "entry_points": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "description": {"type": "string"}
                        }
                    }
                },
                "services": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "responsibility": {"type": "string"},
                            "key_files": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "risks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Potential architectural risks or concerns"
                }
            },
            "required": ["summary", "purpose", "architecture", "tech_stack"]
        }

        return prompt, system_prompt, json_schema

    @classmethod
    def explain_file(
        cls,
        file_path: str,
        file_content: str,
        related_files: dict[str, str],
        dependencies: list[str],
        dependents: list[str],
    ) -> tuple[str, str, dict[str, Any]]:
        """
        Build prompt to explain a specific file.

        Returns:
            Tuple of (prompt, system_prompt, json_schema)
        """
        system_prompt = cls.SYSTEM_PREFIX + """
You are explaining a specific file in detail.
Focus on:
- What the file does and why it exists
- Key functions/classes and their purposes
- How it fits into the larger system
- Potential risks or concerns
"""

        # Build related files content
        related_content = ""
        for path, content in list(related_files.items())[:5]:
            related_content += f"\n\n=== {path} ===\n{content[:1000]}"

        prompt = f"""Explain this file: {file_path}

FILE CONTENT:
{file_content[:8000]}

IMPORTS FROM (dependencies):
{', '.join(dependencies[:20]) or 'None'}

IMPORTED BY (dependents):
{', '.join(dependents[:20]) or 'None'}

RELATED FILES:
{related_content}

Provide a detailed explanation of this file.
"""

        json_schema = {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "One sentence summary of file purpose"
                },
                "purpose": {
                    "type": "string",
                    "description": "Detailed explanation of why this file exists"
                },
                "key_elements": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "type": {"type": "string"},
                            "description": {"type": "string"},
                            "line_start": {"type": "integer"}
                        }
                    }
                },
                "dependencies_explained": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "dependency": {"type": "string"},
                            "why_needed": {"type": "string"}
                        }
                    }
                },
                "system_role": {
                    "type": "string",
                    "description": "How this file fits into the larger system"
                },
                "risks": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "complexity_assessment": {
                    "type": "string",
                    "enum": ["simple", "moderate", "complex", "very_complex"]
                }
            },
            "required": ["summary", "purpose", "key_elements", "system_role"]
        }

        return prompt, system_prompt, json_schema

    @classmethod
    def review_pr(
        cls,
        pr_title: str,
        pr_description: str,
        diff: str,
        affected_files: list[str],
        risk_analysis: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        """
        Build prompt to review a pull request.

        Returns:
            Tuple of (prompt, system_prompt, json_schema)
        """
        system_prompt = cls.SYSTEM_PREFIX + """
You are reviewing a pull request for:
- Security issues (OWASP Top 10, injection, auth bypass, etc.)
- Performance risks (N+1 queries, unbounded operations, etc.)
- Concurrency hazards (race conditions, deadlocks, etc.)
- Business logic errors
- Code quality issues

DO NOT comment on:
- Code style (that's for linters)
- Minor nitpicks
- Personal preferences

Focus on issues that could break production or cause security incidents.
"""

        prompt = f"""Review this pull request:

TITLE: {pr_title}
DESCRIPTION:
{pr_description or 'No description provided'}

AFFECTED FILES:
{', '.join(affected_files)}

RISK ANALYSIS:
{risk_analysis}

DIFF:
{diff[:15000]}

Provide a thorough security and correctness review.
"""

        json_schema = {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Brief summary of the changes"
                },
                "overall_assessment": {
                    "type": "string",
                    "enum": ["approve", "request_changes", "needs_discussion"],
                    "description": "Overall recommendation"
                },
                "risk_level": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"]
                },
                "security_issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                            "file": {"type": "string"},
                            "line": {"type": "integer"},
                            "issue": {"type": "string"},
                            "recommendation": {"type": "string"}
                        }
                    }
                },
                "performance_issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string"},
                            "file": {"type": "string"},
                            "issue": {"type": "string"},
                            "recommendation": {"type": "string"}
                        }
                    }
                },
                "logic_issues": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string"},
                            "issue": {"type": "string"},
                            "recommendation": {"type": "string"}
                        }
                    }
                },
                "suggestions": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "testing_recommendations": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["summary", "overall_assessment", "risk_level"]
        }

        return prompt, system_prompt, json_schema

    @classmethod
    def generate_tests(
        cls,
        file_path: str,
        file_content: str,
        existing_tests: str | None,
        test_framework: str,
        focus_areas: list[str],
    ) -> tuple[str, str, dict[str, Any]]:
        """
        Build prompt to generate test cases.

        Returns:
            Tuple of (prompt, system_prompt, json_schema)
        """
        system_prompt = cls.SYSTEM_PREFIX + """
You are generating test cases for code.
Follow these principles:
- Test behavior, not implementation
- Cover edge cases and error conditions
- Use descriptive test names
- Keep tests independent and focused
- Include both positive and negative tests
"""

        existing_tests_section = ""
        if existing_tests:
            existing_tests_section = f"\n\nEXISTING TESTS:\n{existing_tests[:4000]}"

        prompt = f"""Generate tests for this file: {file_path}

TEST FRAMEWORK: {test_framework}

FILE CONTENT:
{file_content[:8000]}
{existing_tests_section}

FOCUS AREAS:
{', '.join(focus_areas) or 'All functions'}

Generate comprehensive test cases.
"""

        json_schema = {
            "type": "object",
            "properties": {
                "test_file_path": {
                    "type": "string",
                    "description": "Suggested path for the test file"
                },
                "imports": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Required imports"
                },
                "test_cases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "test_type": {"type": "string", "enum": ["unit", "integration", "edge_case", "error_case"]},
                            "code": {"type": "string"},
                            "target_function": {"type": "string"}
                        }
                    }
                },
                "setup_code": {
                    "type": "string",
                    "description": "Any shared setup/fixture code"
                },
                "coverage_notes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Notes on what's covered and what might need more testing"
                }
            },
            "required": ["test_file_path", "test_cases"]
        }

        return prompt, system_prompt, json_schema
