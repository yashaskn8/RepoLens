# RepoLens Demonstration Playbook

> **Target Audience**: Technical Recruiters, Engineering Managers, Judges, and Systems Evaluators  
> **Estimated Run Time**: 5 minutes (Abbreviated) or 10–15 minutes (Deep-Dive)  
> **Environment**: Clean Local Machine (Windows, macOS, or Linux)

---

## 1. Demonstration Goals

By completing this demonstration, you will see how RepoLens:
1. Concurrently parses and extracts structural AST evidence from real public repositories without executing untrusted code.
2. Cross-references backend routes, frontend client calls, and database models to identify cross-layer contract breakages.
3. Performs exact dual-revision pull request change analysis and computes deterministic dependency blast radius.
4. Enforces strict human approval boundaries before candidate remediation patches can be applied.
5. Employs a fail-closed role model (`USER` vs `OPERATOR`) where normal users operate credential-free and privileged GitHub write operations require authorization and drift verification.

---

## 2. Prerequisites

- **Python**: 3.11 or higher
- **Node.js**: 18 or higher (with `npm`)
- **Git**: Installed and available on system `PATH`
- **LLM API Key (Optional but Recommended)**: Set `GEMINI_API_KEY`, `GROQ_API_KEY`, `NVIDIA_API_KEY`, or `HUGGINGFACE_API_KEY` in `backend/.env`. (Note: Deterministic AST parsing and structural diffing operate even with no LLM keys configured).

---

## 3. Safe Environment Setup

Ensure write feature flags remain disabled for standard demonstration:

```bash
# In backend/.env:
GITHUB_DELIVERY_ENABLED=false
GITHUB_PR_REVIEW_WRITE_ENABLED=false
```

> **Safety Notice**: In standard demos, RepoLens operates in safe preview mode. It generates full patch diffs, blast radius graphs, and formatted PR review comments without performing live external writes to public repositories.

---

## 4. Start the Application

### Step A: Start the Backend (Terminal 1)

```bash
cd backend

# Create virtual environment if not already present
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies in editable mode
pip install -e ".[dev]"

# Apply database migrations (001 through 010)
alembic upgrade head

# Start the FastAPI server
uvicorn app.main:app --reload --port 8000
```

Verify backend health at `http://localhost:8000/health`.

### Step B: Start the Frontend (Terminal 2)

```bash
cd frontend

# Install clean reproducible dependencies
npm ci

# Launch Next.js development server
npm run dev
```

Open `http://localhost:3000` in your web browser.

---

## 5. Curated Public Demonstration Repositories

| Repository | Recommended Branch | Primary Language | Why Chosen |
|---|---|---|---|
| `https://github.com/pallets/markupsafe` | `main` | Python | Small, clean Python repository with fast clone, structured symbols, and standard package layout. |
| `https://github.com/expressjs/cookie-parser` | `master` | JavaScript / TS | Compact Node.js middleware library with clear route/middleware conventions. |

---

## 6. End-to-End Walkthrough

### Step 1: User Registration & Role Indicator
1. In the top-right corner of the application header, click **Sign In**.
2. Click the **Register** tab and create a new account:
   - Email: `evaluator@example.com`
   - Password: `Password123!@#` (min 12 characters)
3. Upon registration, you are automatically signed in.
4. **Inspect Role Badge**: The header displays your email accompanied by a clear, distinct **`USER`** badge.
5. *Point of Note*: Standard `USER` sessions have access to public scanning and PR analysis within daily quotas, but cannot trigger external GitHub write operations.

---

### Step 2: Repository Security & Quality Scan
1. Ensure the **Security Scan** mode is active (default landing view).
2. Enter the curated repository URL:
   - Repository URL: `https://github.com/pallets/markupsafe`
   - Branch: `main`
3. Click **Start Repository Scan**.
4. Observe the live status updates streamed via Server-Sent Events (SSE):
   - Ephemeral Git shallow clone
   - Tree-sitter AST parsing across source files
   - Construction of the `RepositoryGraph`
   - Execution of static analyzers
   - Deterministic verification of findings
5. **Inspect Verified Findings**:
   - Notice that each finding includes exact file paths, line ranges, and severity ratings.
   - Observe the **Verification Verdict** (`CONFIRMED` or `POSSIBLE`), indicating that machine facts were validated against AST evidence.

---

### Step 3: Candidate Patch Generation & Human Approval Boundary
1. On any confirmed finding, click **Generate Candidate Patch**.
2. RepoLens plans a scoped fix, generates a unified diff, and executes its 12-check sandbox verifier.
3. The patch pauses in the **`VERIFIED`** or **`NEEDS_REVIEW`** state.
4. **Explain Human-in-the-Loop Authority**: The system deliberately does not auto-apply or auto-commit fixes. A human operator must review the unified diff and click **Approve Patch**.
5. Once approved, notice that the **Deliver to GitHub** button remains safely disabled or guarded because the session is a `USER` (not `OPERATOR`) and `GITHUB_DELIVERY_ENABLED=false`.

---

### Step 4: Pull Request Change Intelligence & Blast Radius
1. In the top navigation switcher, click **🔍 Change Intelligence & PR Review**.
2. Choose **Analyze Public Pull Request** (or analyze an exact commit range).
3. Enter a public PR URL (or test commit range).
4. Click **Analyze Pull Request Changes**.
5. **Review the Results**:
   - **AST Structural Diff**: Exact symbol-level additions, modifications, and signature changes.
   - **Cross-Layer Contract Breaks**: Any route changes affecting frontend client endpoints.
   - **Graph-Aware Blast Radius**: Direct and transitive upstream callers affected by the modified functions, computed via NetworkX graph traversal.
   - **AI Review Findings**: Evidence-grounded review comments citing specific changed lines.
   - **Epistemic Disclosures**: Transparent statement acknowledging that dynamic tests were not executed.

---

### Step 5: (Optional) Operator Elevation & Safe GitHub Boundary
1. To demonstrate the `OPERATOR` role boundary, open a terminal in the backend directory:
   ```bash
   python -m app.cli.create_operator --email evaluator@example.com
   ```
2. Confirm the prompt to elevate the existing user to `OPERATOR`.
3. In the browser, sign out and sign back in as `evaluator@example.com`.
4. Observe the header role badge seamlessly transition to a prominent **`OPERATOR`** badge.
5. Even as an `OPERATOR`, external GitHub writes remain blocked until the explicit server environment flags (`GITHUB_DELIVERY_ENABLED` / `GITHUB_PR_REVIEW_WRITE_ENABLED`) and valid `GITHUB_TOKEN` are configured.

---

## 7. Quick 5-Minute Abbreviated Demo Script

For a high-impact 5-minute recruiter overview:
1. **Minute 1**: Register user $\to$ point out the **`USER`** badge and explain the authentication and quota model.
2. **Minute 2**: Scan `pallets/markupsafe` $\to$ explain passive AST parsing without executing untrusted code.
3. **Minute 3**: Open a finding $\to$ highlight deterministic line citations and evidence grounding.
4. **Minute 4**: Switch to **Change Intelligence** $\to$ demonstrate AST structural diff and dependency blast radius computation.
5. **Minute 5**: Explain the **Human Approval Gate** and the guarded `OPERATOR` write boundary.

---

## 8. Failure & Edge Case Handling Guide

| Scenario | Expected Safe Behavior | Demonstration Action |
|---|---|---|
| **No LLM API Key Configured** | Deterministic AST parsing, graph reconstruction, and diff engines run cleanly; AI reasoning step logs an informative fallback message. | Safe to demo in offline / key-free mode. |
| **Invalid or Private Repo URL** | Returns standard HTTP 404 / 422 with validation error; never hangs or leaks internal paths. | Enter an invalid URL to demonstrate input validation. |
| **User Quota Exceeded** | Returns HTTP 429 Too Many Requests with clear reset countdown; prevents server exhaustion. | Quotas reset daily or can be adjusted in `.env`. |
| **Session Expiration** | API returns HTTP 401 Unauthorized; frontend cleanly prompts for re-authentication without crash. | Click Sign Out $\to$ verify protected actions prompt for login. |
