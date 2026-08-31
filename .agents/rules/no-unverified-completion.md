# No Unverified Completion

## Rule
No agent or engineer may claim a task is "complete," "fixed," "passing," or "done" without first running the relevant verification command and citing its output.

## Applies To
- Test suite results ("all tests pass")
- Build status ("builds successfully")
- Deployment state ("deployed to staging")
- Security scans ("no vulnerabilities found")
- Lint/format checks ("code is clean")
- Migration status ("migration applied successfully")
- Contract parity ("schemas match")

## Required Workflow
1. **Do the work** (write code, fix bug, apply migration).
2. **Run the verification command** (pytest, npm test, mypy, semgrep, etc.).
3. **Read the output** (don't assume success — read the actual numbers).
4. **Cite the output** in your completion claim (e.g., "533 passed, 0 failed in 36.20s").
5. **Only then** claim completion.

## Prohibited Patterns
- ❌ "I've fixed the issue" without showing the test that validates the fix passes.
- ❌ "All tests pass" without showing the test runner output.
- ❌ "The build is clean" without showing the build output.
- ❌ "No security issues" without showing the scanner output.
- ❌ Marking a task as `[x]` complete without evidence in the same message.

## Exception
Read-only audits (architecture reviews, code quality reviews) do not require test runs, but they DO require file/line citations for every finding.
