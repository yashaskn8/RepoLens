# Development Toolchain Usage

## Rule
All coding agents working in this repository MUST follow these toolchain usage
rules. These rules govern how development tools are used, what operations are
permitted, and what safeguards are enforced.

## Tool Roles and Usage

### Serena MCP — Local Code Understanding
- **Use for**: Finding symbols, declarations, references, implementations,
  and performing targeted semantic edits.
- **MUST use before editing**: Always inspect the target code with Serena
  (`find_symbol`, `find_referencing_symbols`, `get_symbols_overview`) before
  making changes.
- **Preferred over**: grep/ripgrep for understanding code structure and
  relationships.

### Repomix — Broad Architecture Only
- **Use for**: Generating whole-repository context when you need to understand
  the overall architecture, module boundaries, or dependency graph.
- **Do NOT use for**: Finding a specific function, debugging a single file, or
  routine code navigation. Use Serena for those tasks.
- **Frequency**: At most once per task. Do not regenerate context repeatedly.

### Context7 MCP — Current External API Documentation
- **Use for**: Looking up current documentation for third-party libraries
  (FastAPI, Pydantic, React, Next.js, SQLAlchemy, etc.).
- **MUST use instead of**: Guessing at library APIs from model memory.
  Library APIs change between versions; always check current docs.
- **Workflow**: `resolve-library-id` → `query-docs` with specific topic.

### GitHub MCP — Read-Only Repository Metadata
- **Permitted operations**: `list_commits`, `list_issues`, `list_pull_requests`,
  `get_issue`, `get_pull_request`, `get_pull_request_comments`,
  `get_pull_request_files`, `get_pull_request_reviews`,
  `get_pull_request_status`, `get_file_contents`, `search_code`,
  `search_issues`, `search_repositories`, `search_users`.
- **PROHIBITED operations**: `create_issue`, `create_pull_request`,
  `create_branch`, `create_repository`, `create_or_update_file`,
  `push_files`, `fork_repository`, `merge_pull_request`,
  `update_issue`, `update_pull_request_branch`,
  `add_issue_comment`, `create_pull_request_review`.
- **Rationale**: Write operations are performed via local git commands after
  human review, not through the GitHub API.

### Sequential-Thinking MCP — Structured Planning
- **Use for**: Breaking down complex problems, planning multi-step
  implementations, debugging with hypothesis tracking.
- **When**: Any task that benefits from structured, revisable reasoning.

### Semgrep — Deterministic Security/Static Analysis
- **Use for**: Security scanning, finding code patterns, static analysis.
- **When**: Before claiming "no security issues," before merging security-
  sensitive changes, during code review of auth/crypto/input-handling code.

## Workflow Rules

### 1. Inspect Before Editing
Before changing ANY file:
- Read the file with Serena or view_file
- Identify callers and downstream dependencies
- Understand the current implementation

### 2. Minimal Coherent Changes
- Make the smallest change that fully addresses the requirement.
- Do not refactor unrelated code in the same commit.
- Do not add abstractions "for future use."

### 3. Targeted Tests During Implementation
- Write or update tests for every behavioral change.
- Run affected tests after each meaningful edit, not just at the end.
- A failing test is a blocker — fix before continuing.

### 4. Full Verification Before Completion
- Run the relevant test suite and cite the output.
- Run lint/typecheck if frontend code was changed.
- Verify no regressions in existing tests.

### 5. No Secret Leakage
- NEVER add API keys, tokens, passwords, or credentials to tracked files.
- NEVER print full secret values in logs or test output.
- Secrets belong in `.env` files (which are gitignored).
- Before committing, verify: `git diff --cached` contains no secrets.
