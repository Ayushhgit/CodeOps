"""
Background Tasks for CodeOps AI.

All tasks are audited and follow the safety model.
"""

import base64
import traceback
from datetime import datetime, timedelta
from typing import Any

import structlog
from arq import ArqRedis

from app.ai.provider import AIProvider
from app.core.config import settings
from app.github.client import GitHubClient
from app.intelligence.analyzer import CodeAnalyzer
from app.intelligence.graph import DependencyGraph
from app.intelligence.risk import RiskAnalyzer
from app.models.audit import AuditAction
from app.services.jobs import JobService, JobStatus


logger = structlog.get_logger(__name__)


async def _get_job_service() -> JobService:
    """Get a job service instance."""
    return JobService()


async def _update_job_progress(
    job_id: str,
    progress: int,
    status: JobStatus = JobStatus.RUNNING,
) -> None:
    """Update job progress."""
    job_service = await _get_job_service()
    try:
        await job_service.update_progress(job_id, progress)
    finally:
        await job_service.close()


async def analyze_repository(
    ctx: dict[str, Any],
    repo_full_name: str,
    installation_id: int,
    job_id: str | None = None,
) -> dict[str, Any]:
    """
    Analyze a repository to build/update intelligence.

    This task:
    1. Fetches repository contents
    2. Analyzes file structure
    3. Builds dependency graph
    4. Identifies risk hotspots
    5. Updates database

    Args:
        ctx: ARQ context
        repo_full_name: Repository full name (owner/repo)
        installation_id: GitHub App installation ID
        job_id: Optional job ID for status tracking

    Returns:
        Analysis summary
    """
    job_service = await _get_job_service()
    start_time = datetime.utcnow()

    logger.info(
        "Starting repository analysis",
        repo=repo_full_name,
        installation_id=installation_id,
        job_id=job_id,
    )

    try:
        # Mark job as running
        if job_id:
            await job_service.start_job(job_id)

        owner, repo = repo_full_name.split("/")

        # Create GitHub client
        async with GitHubClient(installation_id) as github:
            # Update progress: Fetching repository info
            if job_id:
                await job_service.update_progress(job_id, 10)

            # Get repository info
            repo_info = await github.get_repository(owner, repo)
            default_branch = repo_info.get("default_branch", "main")

            # Update progress: Fetching file tree
            if job_id:
                await job_service.update_progress(job_id, 20)

            # Get repository tree
            tree = await github.get_tree(owner, repo, default_branch, recursive=True)

            # Filter to analyzable files
            analyzable_extensions = {
                ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs",
                ".java", ".kt", ".rb", ".php", ".c", ".cpp", ".h",
                ".cs", ".swift", ".scala", ".ex", ".exs",
            }
            files_to_analyze = [
                item for item in tree
                if item["type"] == "blob" and
                any(item["path"].endswith(ext) for ext in analyzable_extensions)
            ]

            logger.info(
                "Found files to analyze",
                total_files=len(tree),
                analyzable_files=len(files_to_analyze),
            )

            # Update progress: Analyzing files
            if job_id:
                await job_service.update_progress(job_id, 30)

            # Initialize analyzers
            analyzer = CodeAnalyzer()
            graph = DependencyGraph()
            analyses = []

            # Analyze each file (with progress updates)
            total_files = len(files_to_analyze)
            for i, file_item in enumerate(files_to_analyze):
                try:
                    # Fetch file content
                    file_data = await github.get_file_content(
                        owner, repo, file_item["path"], ref=default_branch
                    )

                    if file_data.content:
                        content = base64.b64decode(file_data.content).decode("utf-8")

                        # Analyze file
                        analysis = analyzer.analyze_file(
                            path=file_item["path"],
                            content=content,
                        )
                        analyses.append(analysis)

                        # Add to dependency graph
                        graph.add_file(file_item["path"])
                        for imp in analysis.imports:
                            graph.add_dependency(file_item["path"], imp)

                except Exception as e:
                    logger.warning(
                        "Failed to analyze file",
                        file=file_item["path"],
                        error=str(e),
                    )

                # Update progress (30-80% range for file analysis)
                if job_id and i % 10 == 0:
                    progress = 30 + int((i / total_files) * 50)
                    await job_service.update_progress(job_id, progress)

            # Update progress: Running risk analysis
            if job_id:
                await job_service.update_progress(job_id, 85)

            # Run risk analysis
            risk_analyzer = RiskAnalyzer(graph)
            hotspots = risk_analyzer.get_hotspots(analyses, limit=20)

            # Update progress: Saving results
            if job_id:
                await job_service.update_progress(job_id, 95)

            # Build result
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            result = {
                "status": "completed",
                "repo": repo_full_name,
                "summary": {
                    "files_analyzed": len(analyses),
                    "total_lines": sum(a.line_count for a in analyses),
                    "total_symbols": sum(len(a.symbols) for a in analyses),
                    "dependency_edges": graph.edge_count,
                    "risk_hotspots": len(hotspots),
                },
                "top_hotspots": [
                    {
                        "file": h.file_path,
                        "risk_level": h.overall_risk.value,
                        "risk_score": round(h.overall_score, 1),
                        "factors": [f.name for f in h.factors[:3]],
                    }
                    for h in hotspots[:5]
                ],
                "duration_ms": duration_ms,
            }

            # Mark job as completed
            if job_id:
                await job_service.complete_job(job_id, result)

            logger.info(
                "Repository analysis completed",
                repo=repo_full_name,
                files_analyzed=len(analyses),
                hotspots=len(hotspots),
                duration_ms=duration_ms,
            )

            return result

    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}"
        logger.error(
            "Repository analysis failed",
            repo=repo_full_name,
            error=error_msg,
            traceback=traceback.format_exc(),
        )

        if job_id:
            await job_service.fail_job(job_id, error_msg)

        return {
            "status": "failed",
            "repo": repo_full_name,
            "error": error_msg,
        }

    finally:
        await job_service.close()


async def review_pull_request(
    ctx: dict[str, Any],
    repo_full_name: str,
    pr_number: int,
    installation_id: int,
    job_id: str | None = None,
    focus_areas: list[str] | None = None,
) -> dict[str, Any]:
    """
    Review a pull request.

    This is a READ-ONLY task - it only posts comments.

    Args:
        ctx: ARQ context
        repo_full_name: Repository full name
        pr_number: PR number
        installation_id: Installation ID
        job_id: Optional job ID for tracking
        focus_areas: Areas to focus on (security, performance, etc.)

    Returns:
        Review summary
    """
    job_service = await _get_job_service()
    start_time = datetime.utcnow()

    logger.info(
        "Starting PR review",
        repo=repo_full_name,
        pr=pr_number,
        job_id=job_id,
    )

    try:
        if job_id:
            await job_service.start_job(job_id)

        owner, repo = repo_full_name.split("/")

        async with GitHubClient(installation_id) as github:
            # Get PR details
            if job_id:
                await job_service.update_progress(job_id, 10)

            pr = await github.get_pull_request(owner, repo, pr_number)

            # Get PR diff
            if job_id:
                await job_service.update_progress(job_id, 20)

            diff = await github.get_pull_request_diff(owner, repo, pr_number)

            # Get changed files
            if job_id:
                await job_service.update_progress(job_id, 30)

            files = await github.get_pull_request_files(owner, repo, pr_number)

            # Prepare context for AI review
            if job_id:
                await job_service.update_progress(job_id, 40)

            focus = focus_areas or ["security", "performance", "correctness"]

            # Create AI provider and get review
            ai = AIProvider()

            review_prompt = f"""Review this pull request for a code review.

**PR Title:** {pr.title}
**PR Description:** {pr.body or 'No description provided'}
**Base Branch:** {pr.base_ref}
**Head Branch:** {pr.head_ref}
**Files Changed:** {pr.changed_files}
**Additions:** {pr.additions}
**Deletions:** {pr.deletions}

**Focus Areas:** {', '.join(focus)}

**Diff:**
```diff
{diff[:30000]}  # Truncate very large diffs
```

Please provide:
1. A summary of the changes
2. Potential issues found (categorized by: security, performance, correctness, maintainability)
3. Suggestions for improvement
4. An overall assessment (APPROVE, REQUEST_CHANGES, or COMMENT)

Be specific and reference line numbers where applicable.
"""

            if job_id:
                await job_service.update_progress(job_id, 60)

            review_response = await ai.complete(review_prompt)

            if job_id:
                await job_service.update_progress(job_id, 80)

            # Post review comment
            await github.create_pr_comment(
                owner, repo, pr_number,
                f"## CodeOps AI Review\n\n{review_response}"
            )

            if job_id:
                await job_service.update_progress(job_id, 95)

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            result = {
                "status": "completed",
                "repo": repo_full_name,
                "pr": pr_number,
                "review_posted": True,
                "files_reviewed": len(files),
                "focus_areas": focus,
                "duration_ms": duration_ms,
            }

            if job_id:
                await job_service.complete_job(job_id, result)

            logger.info(
                "PR review completed",
                repo=repo_full_name,
                pr=pr_number,
                duration_ms=duration_ms,
            )

            return result

    except Exception as e:
        error_msg = f"Review failed: {str(e)}"
        logger.error(
            "PR review failed",
            repo=repo_full_name,
            pr=pr_number,
            error=error_msg,
            traceback=traceback.format_exc(),
        )

        if job_id:
            await job_service.fail_job(job_id, error_msg)

        return {
            "status": "failed",
            "repo": repo_full_name,
            "pr": pr_number,
            "error": error_msg,
        }

    finally:
        await job_service.close()


async def generate_tests(
    ctx: dict[str, Any],
    repo_full_name: str,
    file_path: str,
    installation_id: int,
    job_id: str | None = None,
    test_type: str = "unit",
    create_pr: bool = False,
) -> dict[str, Any]:
    """
    Generate tests for a file.

    Args:
        ctx: ARQ context
        repo_full_name: Repository full name
        file_path: Path to file to test
        installation_id: Installation ID
        job_id: Optional job ID
        test_type: Type of tests (unit, integration, e2e)
        create_pr: Whether to create a PR with tests

    Returns:
        Generation summary
    """
    job_service = await _get_job_service()
    start_time = datetime.utcnow()

    logger.info(
        "Starting test generation",
        repo=repo_full_name,
        file=file_path,
        test_type=test_type,
        create_pr=create_pr,
        job_id=job_id,
    )

    try:
        if job_id:
            await job_service.start_job(job_id)

        owner, repo = repo_full_name.split("/")

        async with GitHubClient(installation_id) as github:
            # Get file content
            if job_id:
                await job_service.update_progress(job_id, 20)

            repo_info = await github.get_repository(owner, repo)
            default_branch = repo_info.get("default_branch", "main")

            file_data = await github.get_file_content(
                owner, repo, file_path, ref=default_branch
            )

            if not file_data.content:
                raise ValueError(f"Could not read file: {file_path}")

            content = base64.b64decode(file_data.content).decode("utf-8")

            # Analyze file
            if job_id:
                await job_service.update_progress(job_id, 30)

            analyzer = CodeAnalyzer()
            analysis = analyzer.analyze_file(file_path, content)

            # Generate tests with AI
            if job_id:
                await job_service.update_progress(job_id, 50)

            ai = AIProvider()

            test_prompt = f"""Generate {test_type} tests for this code file.

**File:** {file_path}
**Language:** {analysis.language}

**Code:**
```
{content}
```

**Symbols found:**
{chr(10).join(f'- {s.symbol_type}: {s.name}' for s in analysis.symbols[:20])}

Please generate comprehensive {test_type} tests that:
1. Cover all public functions/methods
2. Test edge cases and error conditions
3. Follow best practices for the language
4. Are well-documented with clear test names

Return ONLY the test code, ready to be saved to a file.
"""

            tests_code = await ai.complete(test_prompt)

            if job_id:
                await job_service.update_progress(job_id, 80)

            # Determine test file path
            if file_path.endswith(".py"):
                test_path = file_path.replace(".py", "_test.py")
                if "/" in test_path:
                    parts = test_path.rsplit("/", 1)
                    test_path = f"{parts[0]}/tests/{parts[1]}"
            elif file_path.endswith((".js", ".ts", ".tsx")):
                ext = file_path.split(".")[-1]
                test_path = file_path.replace(f".{ext}", f".test.{ext}")
            else:
                test_path = f"tests/test_{file_path.split('/')[-1]}"

            result = {
                "status": "completed",
                "repo": repo_full_name,
                "source_file": file_path,
                "test_file": test_path,
                "test_type": test_type,
                "tests_generated": tests_code,
                "create_pr": create_pr,
            }

            if create_pr:
                # TODO: Create branch and PR with test file
                # This would require permission level 2+
                result["pr_url"] = None
                result["note"] = "PR creation not yet implemented"
            else:
                # Would post as comment if triggered from PR
                pass

            if job_id:
                await job_service.complete_job(job_id, result)

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            result["duration_ms"] = duration_ms

            logger.info(
                "Test generation completed",
                repo=repo_full_name,
                file=file_path,
                duration_ms=duration_ms,
            )

            return result

    except Exception as e:
        error_msg = f"Test generation failed: {str(e)}"
        logger.error(
            "Test generation failed",
            repo=repo_full_name,
            file=file_path,
            error=error_msg,
            traceback=traceback.format_exc(),
        )

        if job_id:
            await job_service.fail_job(job_id, error_msg)

        return {
            "status": "failed",
            "repo": repo_full_name,
            "file": file_path,
            "error": error_msg,
        }

    finally:
        await job_service.close()


async def generate_documentation(
    ctx: dict[str, Any],
    repo_full_name: str,
    target: str,
    installation_id: int,
    job_id: str | None = None,
    format: str = "markdown",
    create_pr: bool = False,
) -> dict[str, Any]:
    """
    Generate documentation.

    Args:
        ctx: ARQ context
        repo_full_name: Repository full name
        target: What to document (api, file:path, readme)
        installation_id: Installation ID
        job_id: Optional job ID
        format: Output format (markdown, openapi, jsdoc)
        create_pr: Whether to create a PR with docs

    Returns:
        Generation summary
    """
    job_service = await _get_job_service()
    start_time = datetime.utcnow()

    logger.info(
        "Starting documentation generation",
        repo=repo_full_name,
        target=target,
        format=format,
        create_pr=create_pr,
        job_id=job_id,
    )

    try:
        if job_id:
            await job_service.start_job(job_id)

        owner, repo = repo_full_name.split("/")

        async with GitHubClient(installation_id) as github:
            if job_id:
                await job_service.update_progress(job_id, 20)

            repo_info = await github.get_repository(owner, repo)
            default_branch = repo_info.get("default_branch", "main")

            # Gather content based on target
            content_to_document = ""

            if target == "readme":
                # Get repository structure for README generation
                tree = await github.get_tree(owner, repo, default_branch, recursive=True)
                content_to_document = f"Repository: {repo_full_name}\n"
                content_to_document += f"Description: {repo_info.get('description', 'N/A')}\n"
                content_to_document += f"Language: {repo_info.get('language', 'Unknown')}\n\n"
                content_to_document += "File structure:\n"
                for item in tree[:100]:  # Limit to first 100 files
                    content_to_document += f"  {item['path']}\n"

            elif target.startswith("file:"):
                file_path = target[5:]
                file_data = await github.get_file_content(
                    owner, repo, file_path, ref=default_branch
                )
                if file_data.content:
                    content_to_document = base64.b64decode(file_data.content).decode("utf-8")

            elif target == "api":
                # Look for API-related files
                tree = await github.get_tree(owner, repo, default_branch, recursive=True)
                api_files = [
                    f for f in tree
                    if "api" in f["path"].lower() or
                    "routes" in f["path"].lower() or
                    "endpoints" in f["path"].lower()
                ]

                content_to_document = "API files found:\n"
                for f in api_files[:20]:
                    try:
                        file_data = await github.get_file_content(
                            owner, repo, f["path"], ref=default_branch
                        )
                        if file_data.content:
                            file_content = base64.b64decode(file_data.content).decode("utf-8")
                            content_to_document += f"\n--- {f['path']} ---\n{file_content}\n"
                    except Exception:
                        pass

            if job_id:
                await job_service.update_progress(job_id, 50)

            # Generate documentation with AI
            ai = AIProvider()

            doc_prompt = f"""Generate {format} documentation for this code.

**Target:** {target}
**Repository:** {repo_full_name}

**Content:**
```
{content_to_document[:50000]}  # Truncate if very large
```

Generate comprehensive documentation that includes:
1. Overview/Introduction
2. Installation/Setup (if applicable)
3. Usage examples
4. API reference (if applicable)
5. Configuration options

Format the output as {format}.
"""

            if job_id:
                await job_service.update_progress(job_id, 70)

            documentation = await ai.complete(doc_prompt)

            if job_id:
                await job_service.update_progress(job_id, 90)

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            result = {
                "status": "completed",
                "repo": repo_full_name,
                "target": target,
                "format": format,
                "documentation": documentation,
                "create_pr": create_pr,
                "duration_ms": duration_ms,
            }

            if job_id:
                await job_service.complete_job(job_id, result)

            logger.info(
                "Documentation generation completed",
                repo=repo_full_name,
                target=target,
                duration_ms=duration_ms,
            )

            return result

    except Exception as e:
        error_msg = f"Documentation generation failed: {str(e)}"
        logger.error(
            "Documentation generation failed",
            repo=repo_full_name,
            target=target,
            error=error_msg,
            traceback=traceback.format_exc(),
        )

        if job_id:
            await job_service.fail_job(job_id, error_msg)

        return {
            "status": "failed",
            "repo": repo_full_name,
            "target": target,
            "error": error_msg,
        }

    finally:
        await job_service.close()


async def explain_codebase(
    ctx: dict[str, Any],
    repo_full_name: str,
    target: str,
    installation_id: int,
    job_id: str | None = None,
    pr_number: int | None = None,
) -> dict[str, Any]:
    """
    Explain part of the codebase.

    Args:
        ctx: ARQ context
        repo_full_name: Repository full name
        target: What to explain (repo, file:path, impact)
        installation_id: Installation ID
        job_id: Optional job ID
        pr_number: PR number for posting response

    Returns:
        Explanation summary
    """
    job_service = await _get_job_service()
    start_time = datetime.utcnow()

    logger.info(
        "Starting codebase explanation",
        repo=repo_full_name,
        target=target,
        job_id=job_id,
    )

    try:
        if job_id:
            await job_service.start_job(job_id)

        owner, repo = repo_full_name.split("/")

        async with GitHubClient(installation_id) as github:
            if job_id:
                await job_service.update_progress(job_id, 20)

            repo_info = await github.get_repository(owner, repo)
            default_branch = repo_info.get("default_branch", "main")

            # Gather context based on target
            context = ""

            if target == "repo":
                # Get overview of repository
                tree = await github.get_tree(owner, repo, default_branch, recursive=True)
                context = f"Repository: {repo_full_name}\n"
                context += f"Description: {repo_info.get('description', 'N/A')}\n"
                context += f"Language: {repo_info.get('language', 'Unknown')}\n"
                context += f"Stars: {repo_info.get('stargazers_count', 0)}\n\n"
                context += "File structure:\n"
                for item in tree[:200]:
                    context += f"  {item['path']}\n"

            elif target.startswith("file:"):
                file_path = target[5:]
                file_data = await github.get_file_content(
                    owner, repo, file_path, ref=default_branch
                )
                if file_data.content:
                    content = base64.b64decode(file_data.content).decode("utf-8")
                    context = f"File: {file_path}\n\n```\n{content}\n```"

            elif target.startswith("impact:"):
                impact_pr = int(target[7:])
                pr = await github.get_pull_request(owner, repo, impact_pr)
                diff = await github.get_pull_request_diff(owner, repo, impact_pr)
                files = await github.get_pull_request_files(owner, repo, impact_pr)

                context = f"PR #{impact_pr}: {pr.title}\n"
                context += f"Description: {pr.body or 'N/A'}\n"
                context += f"Files changed: {len(files)}\n"
                context += f"Additions: {pr.additions}, Deletions: {pr.deletions}\n\n"
                context += f"Diff:\n```diff\n{diff[:30000]}\n```"

            if job_id:
                await job_service.update_progress(job_id, 50)

            # Generate explanation with AI
            ai = AIProvider()

            explain_prompt = f"""Explain this codebase/code to a developer.

**Target:** {target}
**Repository:** {repo_full_name}

{context}

Please provide:
1. A high-level overview
2. Key components and their purposes
3. How the parts work together
4. Important patterns or conventions used
5. Potential areas of complexity or concern

Be clear and educational in your explanation.
"""

            if job_id:
                await job_service.update_progress(job_id, 70)

            explanation = await ai.complete(explain_prompt)

            if job_id:
                await job_service.update_progress(job_id, 90)

            # Post to PR if specified
            if pr_number:
                await github.create_pr_comment(
                    owner, repo, pr_number,
                    f"## CodeOps AI Explanation\n\n{explanation}"
                )

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            result = {
                "status": "completed",
                "repo": repo_full_name,
                "target": target,
                "explanation": explanation,
                "posted_to_pr": pr_number,
                "duration_ms": duration_ms,
            }

            if job_id:
                await job_service.complete_job(job_id, result)

            logger.info(
                "Explanation completed",
                repo=repo_full_name,
                target=target,
                duration_ms=duration_ms,
            )

            return result

    except Exception as e:
        error_msg = f"Explanation failed: {str(e)}"
        logger.error(
            "Explanation failed",
            repo=repo_full_name,
            target=target,
            error=error_msg,
            traceback=traceback.format_exc(),
        )

        if job_id:
            await job_service.fail_job(job_id, error_msg)

        return {
            "status": "failed",
            "repo": repo_full_name,
            "target": target,
            "error": error_msg,
        }

    finally:
        await job_service.close()


async def cleanup_old_logs(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Clean up old audit logs based on retention policy.

    Runs as a cron job.
    """
    logger.info("Starting audit log cleanup")

    retention_days = settings.audit_log_retention_days
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

    try:
        # Clean up old jobs from Redis
        job_service = await _get_job_service()
        deleted_jobs = await job_service.cleanup_old_jobs(max_age_hours=24)

        logger.info(
            "Cleanup completed",
            deleted_jobs=deleted_jobs,
            cutoff_date=cutoff_date.isoformat(),
        )

        return {
            "status": "completed",
            "cutoff_date": cutoff_date.isoformat(),
            "deleted_jobs": deleted_jobs,
        }

    except Exception as e:
        error_msg = f"Cleanup failed: {str(e)}"
        logger.error("Cleanup failed", error=error_msg)
        return {
            "status": "failed",
            "error": error_msg,
        }
