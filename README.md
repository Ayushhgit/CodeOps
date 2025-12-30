# CodeOps AI — GitHub-Native AI Engineering Copilot

A security-first, GitHub-native AI system with controlled write access to production repositories.

## Core Principles

1. **Trust** — Every action is auditable and explainable
2. **Safety** — Never push directly to main/master
3. **Auditability** — Immutable logs for all operations
4. **Business Risk Reduction** — Blast radius analysis before any write
5. **Speed** — Last priority, never at the expense of safety

## Permission Levels

| Level | Name | Capabilities |
|-------|------|--------------|
| 0 | Read Only | Repo parsing, PR reviews, explanations |
| 1 | Suggest Mode | Generate diffs, post patches in comments |
| 2 | PR Author Mode | Create branches, commit, open PRs |
| 3 | CI-Bound Write | Commits gated by tests + security checks |

## Features

- **AI Codebase Explainer** — `/explain repo`, `/explain file`, `/explain impact`
- **AI Code Reviewer** — Security, performance, concurrency analysis (read-only)
- **AI API Documentation Generator** — Generate docs, OpenAPI specs via PRs
- **AI Test Case Generator** — Create tests, edge cases, regression coverage
- **AI Internal Tool Generator** — Generate APIs, schemas, admin UIs

## Tech Stack

### Backend
- Python 3.11+ with FastAPI
- PostgreSQL (repo intelligence + audit logs)
- Redis (task queues)
- Background workers (Celery/ARQ)

### Frontend
- Next.js (minimal dashboard)
- Primary UX happens inside GitHub

### AI Layer
- Provider-agnostic (OpenAI, Anthropic, etc.)
- Structured JSON outputs only
- Deterministic prompts

## Project Structure

```
codeops/
├── backend/
│   ├── app/
│   │   ├── api/           # FastAPI routes
│   │   ├── core/          # Config, security, permissions
│   │   ├── github/        # GitHub App integration
│   │   ├── intelligence/  # Repo Intelligence Engine
│   │   ├── ai/            # AI provider abstraction
│   │   ├── features/      # Feature implementations
│   │   ├── models/        # SQLAlchemy models
│   │   ├── services/      # Business logic
│   │   └── workers/       # Background tasks
│   └── tests/
├── frontend/              # Next.js dashboard
├── docker/                # Docker configurations
└── docs/                  # Documentation
```

## Quick Start

```bash
# Clone and setup
git clone <repo>
cd codeops

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env with your credentials

# Run services
docker-compose up -d postgres redis
uvicorn app.main:app --reload

# Frontend setup
cd ../frontend
npm install
npm run dev
```

## Environment Variables

See `.env.example` for required configuration.

## Write Workflow

Every write action follows this mandatory flow:

1. Analyze repo state
2. Explain proposed changes
3. Generate diff
4. Create branch
5. Commit with descriptive message
6. Open PR
7. Tag risks + rollback notes
8. Wait for human review

**No exceptions.**

## License

MIT
