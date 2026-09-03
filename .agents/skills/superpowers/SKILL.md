---
name: superpowers
description: >-
  Enforces a disciplined software engineering methodology for AI coding agents.
  Activates for any non-trivial implementation task to ensure structured planning,
  test-driven development, systematic debugging, and verified completion.
  Use when starting new features, fixing bugs, refactoring, or any multi-step
  coding work. Skipped for investigatory questions, simple lookups, or one-line fixes.
---

# Superpowers — Disciplined Engineering Methodology

This skill enforces a structured, multi-phase engineering workflow that prevents
rushing into implementation without proper planning or verification.

## When to Activate

Activate this skill for ANY task that involves:
- Writing or modifying more than a trivial amount of code
- Adding new features or capabilities
- Fixing non-obvious bugs
- Refactoring existing architecture
- Multi-file changes

Do NOT activate for:
- Simple lookups or "where is X?" questions
- One-line fixes with obvious solutions
- Reading or explaining existing code

---

## Phase 1: Brainstorming (REQUIRED before coding)

Before writing any implementation code:

1. **Clarify requirements** — What exactly does the user want? What are the
   acceptance criteria? Ask clarifying questions if the intent is ambiguous.
2. **Inspect the existing codebase** — Use Serena (`find_symbol`,
   `find_referencing_symbols`, `get_symbols_overview`) to understand the current
   architecture around the change area. Never assume — look.
3. **Identify constraints** — What existing patterns, types, naming conventions,
   and abstractions must be respected? Check `agentrules.md` and `.agents/rules/`.
4. **Map the blast radius** — What files, tests, APIs, schemas, and downstream
   consumers will be affected by this change?

**Gate**: Do not proceed to Phase 2 until you can articulate:
- What will change
- What will NOT change
- What existing code you must integrate with
- What tests will need to pass

---

## Phase 2: Planning (REQUIRED before coding)

Create a concrete implementation plan:

1. **Break into small tasks** — Each task should be completable in 2–5 minutes
   and independently verifiable.
2. **Order by dependency** — Dependencies first, consumers last.
3. **Identify test points** — For each task, define how you will verify it works.
4. **Use Sequential-Thinking MCP** — For complex multi-step plans, use the
   `sequentialthinking` tool to structure your reasoning with branching and
   revision support.

**Gate**: Do not proceed to Phase 3 until you have a written plan with:
- Numbered task list
- Expected files to modify/create
- Test strategy for each task

---

## Phase 3: TDD Execution (Red → Green → Refactor)

For each task in the plan:

1. **Red** — Write a failing test that captures the expected behavior.
   If the change is not testable (e.g., config-only), document why.
2. **Green** — Write the minimum code to make the test pass.
3. **Refactor** — Clean up without changing behavior. Run the test again.
4. **Verify** — Run the specific test(s) and confirm they pass before moving to
   the next task.

**Rules during execution**:
- Make ONE change at a time. Do not batch unrelated changes.
- Run tests after each meaningful change, not just at the end.
- If a test fails unexpectedly, stop and debug before continuing.
- Use Serena for targeted code navigation instead of scanning entire files.
- Use Context7 for external library API questions instead of guessing.

---

## Phase 4: Verification (REQUIRED before claiming completion)

Before claiming any task is done:

1. **Run the full relevant test suite** — Not just the new tests.
   ```
   backend\.venv\Scripts\pytest backend/tests/ -v          # backend
   npm run lint && npm run type-check                       # frontend
   ```
2. **Check for regressions** — Any existing test that now fails is a blocker.
3. **Verify contract parity** — If you changed schemas, types, or APIs, confirm
   all consumers still work.
4. **Cite evidence** — Per the `no-unverified-completion` rule, include actual
   test output in your completion claim.

---

## Phase 5: Review (Self-Check)

After all tasks are complete:

1. **Re-read the original requirement** — Does the implementation actually
   satisfy what was asked?
2. **Check for leftover artifacts** — No TODO placeholders, no commented-out
   code, no debug prints.
3. **Check for secret leakage** — No API keys, tokens, or credentials in any
   tracked file.
4. **Verify git diff** — Only expected files were modified.

---

## Anti-Patterns (NEVER Do These)

- ❌ Jump straight to writing code without reading existing code first
- ❌ Write a large batch of changes and test only at the end
- ❌ Claim "all tests pass" without running them and citing output
- ❌ Add new abstractions without checking if equivalent ones already exist
- ❌ Guess at library APIs instead of checking Context7
- ❌ Make changes to files you haven't inspected with Serena
- ❌ Leave the codebase in a state where tests fail
