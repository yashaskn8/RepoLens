# RepoLens

RepoLens is an AI-powered code analysis and repository intelligence platform.

> **Phase 1A: Project Foundation**  
> Clean, typed monorepo containing a FastAPI backend, Next.js frontend, canonical domain schemas, SQLAlchemy models, and Alembic migrations.

---

## Architecture Overview

```
RepoLens/
├── backend/                  # FastAPI / Python backend
│   ├── app/
│   │   ├── api/             # API routes & routers
│   │   ├── core/            # Config (Pydantic Settings) & Database (SQLAlchemy)
│   │   ├── models/          # SQLAlchemy ORM models
│   │   └── schemas/         # Canonical domain schemas & enums
│   ├── alembic/             # Database migrations
│   └── tests/               # Pytest suite
└── frontend/                 # Next.js + TypeScript frontend
    └── src/
        ├── app/             # Next.js App Router & UI
        ├── lib/             # API client
        └── types/           # Domain TypeScript definitions mirroring schemas
```

---

## Local Development (No Docker Required)

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run database migrations:
   ```bash
   alembic upgrade head
   ```

5. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   The backend will be available at `http://localhost:8000`.  
   API Docs: `http://localhost:8000/docs`  
   Health Check: `http://localhost:8000/health`

6. Run backend tests:
   ```bash
   pytest tests/ -v
   ```

---

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   The frontend will be available at `http://localhost:3000`.

---

## Database Portability

By default, RepoLens uses SQLite for local zero-dependency development (`sqlite:///./repolens.db`). To switch to PostgreSQL, set the `DATABASE_URL` environment variable:
```bash
DATABASE_URL="postgresql://user:password@localhost:5432/repolens"
```
Alembic migrations and SQLAlchemy models are designed to be fully compatible with both SQLite and PostgreSQL.
