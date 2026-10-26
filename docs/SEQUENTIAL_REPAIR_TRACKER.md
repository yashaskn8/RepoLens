# RepoLens sequential repair-pack acceptance tracker

Updated 2026-10-26. This tracks the user's numbered **Prompts 0–35 plus supplemental Prompt 0B** (37 acceptance items). **No item is certified complete at this HEAD.** “PARTIAL” means some relevant fixes/tests exist, **not** that the prompt's success criterion passed. “BLOCKED” means a required trust boundary is absent; “NOT TESTED” means final acceptance was not executed.

Repository: `yashaskn8/RepoLens`. Direct-`main` work only. Snapshot HEAD before this tracker: `4f4725278f55af4ad854701cb648af795a9d2e74`.

| Prompt | Acceptance scope | Status | Evidence gap / next validation |
| --- | --- | --- | --- |
| 0 | Development startup | **PARTIAL** | Historical CI imports/build/migrations; live localhost API + browser flow not executed. |
| 0B | Database, migrations, jobs | **PARTIAL** | Historical CI DB/integration tests; restart/restore under deployment not accepted. |
| 1 | Public GitHub scanning | **PARTIAL** | Mocked scan and status tests; real public clone-to-UI acceptance untested. |
| 2 | Immutable snapshots | **PARTIAL** | Targeted snapshot/path fixes; full rehydration acceptance unverified. |
| 3 | Hostile repository confinement | **PARTIAL** | Path/input tests; independently enforced production acquisition still blocked. |
| 4 | Semgrep, Trivy, OSV | **PARTIAL** | Mocked scanner tests; real isolated scanner execution unavailable in production. |
| 5 | Tree-sitter and graphs | **PARTIAL** | Parser/graph unit coverage; live multi-language acceptance unverified. |
| 6 | Evidence storage | **PARTIAL** | Evidence unit checks; end-to-end artifact retrieval unverified. |
| 7 | Finding display and navigation | **PARTIAL** | UI/evidence tests; full browser journey unverified. |
| 8 | Deterministic verification | **PARTIAL** | Verifier tests; complete scanner-to-report acceptance unverified. |
| 9 | Remediation plans | **PARTIAL** | Planning tests; interactive full journey unverified. |
| 10 | Patch generation | **PARTIAL** | Patch tests; full workflow unverified. |
| 11 | Twelve-check patch verification | **PARTIAL** | Verification unit tests; all release conditions not independently accepted. |
| 12 | Patch critic and revision | **PARTIAL** | Revision tests; complete history UI unverified. |
| 13 | Human approve/reject | **PARTIAL** | Auth/verdict regression tests; browser end-to-end unverified. |
| 14 | GitHub PR delivery | **PARTIAL** | Mock provider, identity and idempotency tests; authorized sacrificial remote write untested. |
| 15 | Structural diff | **PARTIAL** | Targeted diff/rename fixes; live PR comparison unverified. |
| 16 | Public PR URL resolution | **PARTIAL** | Resolver tests; live public PR end-to-end unverified. |
| 17 | Cross-layer contracts | **PARTIAL** | Route/diff tests; representative live app acceptance unverified. |
| 18 | AI review/report | **PARTIAL** | Evidence/report tests; real provider integration unverified. |
| 19 | PR comment publishing | **PARTIAL** | Policy/mock tests; authorized COMMENT-only remote write untested. |
| 20 | Registration/login/logout | **PARTIAL** | Automated auth tests; browser/session restoration acceptance unverified. |
| 21 | CSRF and cookies | **PARTIAL** | Automated CSRF tests; cross-host browser deployment unverified. |
| 22 | Tenant isolation | **PARTIAL** | Backend tests and frontend account-state fixes; complete cross-resource audit unverified. |
| 23 | Daily quotas | **PARTIAL** | Quota unit tests; host-level acquisition quota still blocked. |
| 24 | SSE and polling | **PARTIAL** | Stale-socket fix bf0c574; live reconnect/browser flow unverified. |
| 25 | Health/telemetry | **PARTIAL** | Historical CI health tests; production host readiness intentionally blocked. |
| 26 | Multi-provider LLM | **PARTIAL** | Mock routing tests; authorized real-provider calls unverified. |
| 27 | Read-only MCP | **PARTIAL** | Protocol tests; supported client acceptance unverified. |
| 28 | Frontend | **PARTIAL** | Account isolation, PR history, scan retry, risk presentation fixed; full current-HEAD build/browser tests not executed. |
| 29 | Optional embeddings | **PARTIAL** | Historical optional-dependency tests; explicit model environment unverified. |
| 30 | AI cache | **PARTIAL** | Historical cache tests; all evidence/tenant replay cases unverified. |
| 31 | AI single-flight | **PARTIAL** | Historical coalescing tests; integration load/cancel cases unverified. |
| 32 | Optional Ollama | **PARTIAL** | Mock tests; opted-in local provider not tested. |
| 33 | Findings/remediation lifecycle | **PARTIAL** | Race/verdict/account fixes; complete interactive journey unverified. |
| 34 | Production hard isolation | **BLOCKED** | Trusted quota broker, Git-only egress, independent scanner sandbox, and host probes missing. |
| 35 | Final release audit | **NOT TESTED** | Cannot certify until all prior acceptance gates and staging recovery pass. |

## Latest focused repairs (this run)

- `67df984030dc47ca921f7b4fcafa7586518ce3dd`: account-bound recent PR analyses, stale-response rejection, submission guard.
- `f94f1f30c12b4bcd1541753dcf3f55132f2e03c4`: correct test harness escaping for the preceding change.
- `b0dd6dfcd16b6945277a04e911400fcc2cb96870`: scan-detail findings retry and unknown-count disclosure.
- `4f4725278f55af4ad854701cb648af795a9d2e74`: neutral badge for `NONE`/unrecognized PR risk.

The original stale PR-history effect was reproduced: a previous account's pending response could populate the view after logout. After repair, **7 account-history/submission behavioral checks** passed against retrieved committed source. **5 scan-detail checks** and **9 PR-risk presentation checks** passed in isolated JavaScript execution against retrieved committed source. The corresponding repository regression tests were committed, **but the full Node test suite, TypeScript type-check, lint, Next.js build, backend pytest and live end-to-end workflow were not executed in this run**. These checks must be rerun on the final proposed release commit.

See [REPAIR_AUDIT_2026-10-26.md](REPAIR_AUDIT_2026-10-26.md) for historical CI evidence tied to earlier commits, not the current HEAD.

## Additional verified application repair (2026-10-26)

- `cd8f19a4732d2e5259c882752ff2715e502c1e85`: fixed the PR-analysis **exact revision** launcher. Previously its “Compare Branches / Commits” form defaulted to `main` and `feature/auth-contracts`, then submitted those branch names as `base_commit_sha` and `head_commit_sha`. The backend `ChangeAnalysisRequest` contract requires two distinct, exact 40-character hexadecimal SHAs, so the default UI request failed with HTTP 422. The interface now explicitly requests immutable commit IDs, starts with empty fields, validates and normalizes them before enqueue, and rejects equal revisions. PR URL mode remains unchanged.
- Regression coverage committed: `frontend/tests/change-analysis-exact-commits.test.mjs` (7 tests). The original mismatch was reproduced from the actual frontend and backend schemas before editing. **17 focused behavioral assertions were executed and passed** against the retrieved committed helper and submit-handler source, with TypeScript-only annotations stripped for isolated JavaScript execution. The repository Node test file itself, full frontend suite, type-check, build, backend pytest, and live browser acceptance **were not executed**. Prompt 16/17/28 acceptance remains **PARTIAL**; this is a contract/UI correctness fix, not a claim of branch-ref resolution support.

## Non-bypassable next gates

1. Run full current-HEAD frontend/backend tests and a local API/browser startup; correct any failures.
2. Complete real public scan, evidence/report, remediation/approval and public PR analysis journeys.
3. Verify tenant ownership, quota concurrency, durable recovery and rollback in deployment-equivalent integration tests.
4. Integrate **independently enforced** acquisition filesystem/resource budgets and Git-only egress, plus externally isolated scanner workers, on an identified host. Until then keep production readiness fail-closed.
5. Validate sacrificial GitHub writes only with explicit authorization and an appropriately scoped integration environment. Never substitute mocks for release certification.


## Active PR-detail artifact recovery (2026-10-26)

- `080537fbc74329457ca5fc7abf963c44793e14ec`: fixed the **active** `/changes/[id]` workspace. Completed analysis artifact failures were silently ignored after terminal polling stopped; users could see an unavailable diff/review without a retry path. The workspace now identifies missing required diff, impact and review evidence, distinguishes optional publication lookup, and provides a guarded retry that retains successfully loaded evidence. Failed analyses do not attempt completed-artifact fetches. The earlier `ChangeAnalysisWorkspace` retry is separate and does not cover this active route.
- `ce17a28888f0fe83beb6b8f73a596b24eb0f0b6c`: added four regression tests in `frontend/tests/change-detail-artifact-recovery.test.mjs`.
- Reproduced the original silent failure by executing the actual pre-fix effect with a rejected structural-diff request and completed analysis. **Four focused behavioral scenarios passed** when executed against the retrieved committed effect and retry handler in an isolated JavaScript harness (required/optional failures, successful retry, failed analysis, duplicate retry). The committed Node test file, full frontend test suite, TypeScript type-check/build, backend pytest and browser acceptance **were not executed**. Prompts 17, 18, 19 and 28 remain **PARTIAL**.
