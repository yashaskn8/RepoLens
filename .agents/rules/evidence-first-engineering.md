# Evidence-First Engineering

## Rule
Every implementation claim, architectural assertion, and completion statement MUST be backed by deterministic machine evidence before it is accepted.

## What Counts as Evidence
1. **Test output**: Actual pytest/jest/vitest terminal output showing pass/fail counts.
2. **Type checker output**: mypy, pyright, tsc with zero errors.
3. **Linter output**: Semgrep, ESLint, Ruff with zero critical findings.
4. **Code citations**: Exact file path, line number, and symbol name from repository source.
5. **API responses**: Actual HTTP response bodies from running servers or test clients.
6. **Context7 documentation**: Current official library documentation fetched at query time.
7. **Serena symbol lookups**: Deterministic AST-level symbol resolution.
8. **Git state**: Actual `git log`, `git diff`, `git status` output.

## What Does NOT Count as Evidence
- ❌ "I'm confident this works"
- ❌ "Based on my knowledge of the codebase"
- ❌ "This should be correct"
- ❌ "As we discussed earlier"
- ❌ Any claim from model memory without current source verification
- ❌ Screenshots of code (use actual file citations instead)

## Enforcement
- Before claiming "all tests pass," run the test suite and cite the output.
- Before claiming "contract parity," show the producer and consumer field lists side by side.
- Before claiming "no security issues," show the scan output.
- Before claiming "backwards-compatible," show the migration diff and affected queries.

## Violations
If an agent or engineer makes an unsupported claim:
1. Flag it as UNVERIFIED.
2. Request the specific evidence needed.
3. Do not proceed until evidence is provided.
