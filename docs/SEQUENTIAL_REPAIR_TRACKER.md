# RepoLens sequential repair-pack acceptance tracker

Updated 2026-10-27. This tracks the user's numbered **Prompts 0–35 plus supplemental Prompt 0B** (37 acceptance items). **No item is certified complete at this HEAD.** “PARTIAL” means some relevant fixes/tests exist, **not** that the prompt's success criterion passed. “BLOCKED” means a required trust boundary is absent; “NOT TESTED” means final acceptance was not executed.

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

## Change-analysis workspace submission repair (2026-10-27)

- `4d94437c84bf64fbc5a70d077bddbdf326d0d4fa`: the legacy change-analysis workspace previously accepted nonempty branch names as `base_commit_sha` / `head_commit_sha` and lacked a synchronous submission guard. It now uses the shared exact-SHA parser before initiating work, normalizes hashes, rejects identical revisions and prevents duplicate in-flight requests. This is distinct from the previously repaired `/change-analysis` route.
- `dd74184a17b506c3df8363a81401e2dbc9227e50`, `965a81cf046c50e54bc396cd7f3d53404a8467c1`: regression tests added and the isolated TypeScript parser harness corrected. `20073bbc455ecc9ef16fcb8b647aa478082fe5d1`, `a67855262f7dc9739b18bb98e1a9b04ef1d0f741`, `2f8d12c91f768c333a7e3bc9e769b59a748724a7`: disable input-mode switching during submission and cover the guard.
- Reproduction: direct source inspection confirmed the unvalidated exact-SHA payload and absent ref guard; an isolated reproduction modeled the old handler and observed invalid branch-name submission and overlapping starts. **Five isolated behavioral scenarios were executed and passed** with a copied, TypeScript-transpiled version of the repaired submission handler and shared parser (invalid SHA, identical SHA, normalized SHA, duplicate submission, retry after error). The initial harness execution failed due to module-export transpilation and was corrected before the five passes. **The committed six-test repository file, full frontend type-check/build, backend suite and browser acceptance were not executed** because a complete local checkout was unavailable. Prompt 17/28 acceptance remains **PARTIAL**.


## Additional findings-history pagination repair (2026-10-27)

- `92ac3ec3d5e718635acee0ef325e3d01d3294f23`: fixed a same-render duplicate-click race in the authenticated findings explorer. Before the fix, two `Load older scan findings` calls at offset 25 both fetched the same page, but each advanced `loadedScanCount` by 25. The resulting offset 75 skipped scans 50–74. Reproduced from the original callback in an isolated JavaScript execution: two requests at offset 25, final count 75 instead of 50.
- `b5a774a7dc6663ddd20d05e555baf68e66446647`: added four Node regression tests exercising the actual callback, concurrent clicks, retry after failure, generation-scoped lock release, and account-refresh invalidation.
- After the change, **seven isolated behavioral assertions executed and passed** against the fetched committed component callback. The four committed regression tests were also executed and passed in a V8 harness with Node assertion shims against the fetched current-main source. The repository Node test runner itself, full frontend type-check/build, backend pytest, and browser end-to-end acceptance **were not executed**. Prompts 22/28 remain **PARTIAL**, and production release acceptance is still blocked.

## Legacy scan-workspace duplicate-submission repair (2026-10-27)

- `790fcb211ce213aa669fe446d5aa68f153bb6648`: introduced a synchronous ref guard for the legacy `RepositoryScanWorkspace` scan launcher. The original callback relied on asynchronous React state and permitted two rapid submissions, initiating two scans and advancing the generation twice. The defect was reproduced by executing the pre-fix callback with two same-render invocations: **2 requests instead of 1**.
- `80769dd7587ca1df568d4d4a87b7999e321b01ce`: added regression tests exercising the real callback, duplicate submission, error recovery, running-scan protection, invalid input, and branch fallback.
- `f86f509e75892e12baf3d1488ba1699c4ae08d96`: fixed an additional post-resolution race reproduced against the initial guard: the lock was released immediately after the server returned a `PENDING` scan, before React could render the running state. The guard now remains locked through a running scan and releases on terminal status or failed initiation.
- `03c3b03e9499a3f7ed7ff0c85b34c296c554cd5c`: extended coverage to seven scenarios, including post-resolution duplicate submission and terminal-state unlock. **All seven committed regression test bodies executed and passed** against fetched current-main source in a V8 JavaScript harness with assertion shims. The repository's Node test runner, full frontend build/type-check, backend pytest, browser tests and production acceptance **were not executed**. Prompt 1/23/28 remain **PARTIAL**; no quota or hard-isolation acceptance is inferred.

## Active scan-route submission and account-isolation repairs (2026-10-27)

- `1f469948a9170412aa9994841c5c7002ced496fc`: fixed the active `/scan` launcher (distinct from the legacy workspace) where two same-render submits could start two scans. Reproduced against the pre-fix callback: **2 API calls before either settled**. The new synchronous guard prevents duplicates, remains locked while a returned scan is pending/running, releases on failure/terminal state, and uses request-generation checks to avoid stale account responses clearing newer locks. `60fce7d1de2529daf47f833fd82195d61e654509` added seven regression scenarios. **All seven committed test bodies passed** in an isolated V8 harness against fetched committed source, including an account-change generation race.
- `3eec20095bca4d889563e85661f504af494035ed`: fixed private scan-history state surviving one render across account changes. Previously `ScanWorkspaceContent` held `recentScans` and `activeScan` until an effect reset them; the render immediately following logout/account switch could expose the old account's history. The route now remounts its stateful workspace under an account/session-loading key. `634f62d7183e780d7628325c21c989b3eb43bcb4` added four regression scenarios, **all four executed and passed** in the isolated V8 harness against committed source. This is client-state isolation; backend authorization remains mandatory.
- Across both active-route repairs, **11 focused committed regression test bodies passed** in V8 with Node assertion shims. The repository's Node test runner, frontend type-check/build, backend pytest, live browser session transitions and production hard-isolation acceptance **were not executed**. Prompts 20/22/23/28 remain **PARTIAL**, and no release-readiness claim is made.

## Failed findings evidence recovery (2026-10-27)

- `d40dbde195181c79434f90f29f239860c7afd85b`: `loadScanFindingsPage` now returns the identities of scans whose findings retrieval failed, not just a failure count. Previously the findings explorer advanced the scan offset after partial failure but forgot which scans had failed, making their verified findings inaccessible through older-page navigation until a manual full refresh.
- `bdfe05ade93015201c92e24000c9d4a83061de7a`: the active findings explorer retains missing scan IDs across pages and exposes a targeted retry. Successful retries merge evidence without duplicate finding IDs; failed IDs remain retryable. The retry is guarded against duplicate clicks, simultaneous older-page loads and stale account generations.
- `c8bbad527a75c57fe9b23880a8e1f73de7d4eb08`, `ef34424c13069e4636e76f41eda9fee84991e080`, `e0a5674d682f4dd06a5c640a81ff2d6032e0eb31`: added six behavioral regression tests and corrected the newline/cross-realm harness details.
- `27d0ca5bff21498c2d6570d846ff6cea2b3c3a14`: corrected a JSX closing delimiter found during source review, scoped prior error messages to the loaded account, and prevented an incomplete evidence set from being described as having no findings.
- `d220c0bb129b69178a39586b36a0b61cb1af059f`: added a seventh regression checking full-page TSX parsing, tenant-scoped errors and incomplete-evidence presentation.
- **Executed:** six Node test cases passed using `node --test` against an isolated, manually copied copy of the committed helper and retry callback, with the test file run as the unprivileged `nobody` user. The first run exposed a cross-VM-realm array assertion error (five passed, one failed); after correcting the assertion, all six passed. The seventh test, which parses the entire TSX page, was **written but not executed** because a full checkout was unavailable. These are isolated behavioral checks, **not** a full-repository Node suite, TypeScript type-check, browser test, or backend pytest run.
- **Remaining:** execute all seven tests and the full frontend build against a complete checkout, verify account changes and recovery in a browser, and retain production hard-isolation gates. Prompts 6, 7, 22, 28 and 35 remain **PARTIAL** or **NOT TESTED**; no prompt has been certified complete.

## PR-detail missing-evidence truthfulness (2026-10-27)

- `fe62d6fee0ccf9dfc14bf99fbca89b402088000f`: fixed the active `/changes/[id]` view, which previously rendered **“Zero breaking changes detected”** when the structural-diff request failed, and **“No downstream callers affected”** when impact retrieval failed. Those were incorrect clean conclusions from absent evidence. The page now tracks successful impact retrieval separately from an empty impact list, distinguishes unavailable diff/impact evidence from verified empty results, labels unavailable summary counts explicitly, and requires impact evidence before offering the “No blockers detected” assessment.
- `b3e36648ff0226d86e84690c096a3909d723e87f`: treats `NONE` risk as unassessed, displays missing review count as unavailable, and removes unsupported absolute compatibility/propagation guarantees from empty-state copy.
- `d96c8749dfea93fb0853a667b778b11feab898e9`: added five regression tests covering TSX parsing, evidence-state branch ordering, successful impact retrieval, risk gating, and unknown counts. **The committed Node tests were written but not executed**; the complete repository is unavailable locally.
- **Executed:** 11 static source assertions against the retrieved committed `main` TSX passed, checking the guarded empty-state branches, availability transitions, risk gating, unavailable counts, and removal of unsupported guarantees. These checks are **not** runtime/browser tests or the committed test suite. The `Tabs` component contract was also inspected: its count prop permits `undefined`.
- **Acceptance remains PARTIAL:** Prompts 15, 17, 18, 22, 28 and 35 need end-to-end and current-HEAD test/build verification. Production hard-isolation Prompt 34 remains **BLOCKED**; no security gate or approval rule was weakened.

## Report-generation external idempotency scope (2026-10-27)

- `47c6b090f7be78365fd0bad07a2be93f2b8150cc`: fixed a same-tenant, cross-scan replay defect in `POST /api/v1/scans/{scan_id}/reports`. The external idempotency lookup is keyed by tenant and work kind, but the original replay branch loaded the existing report and resubmitted **that existing report's** payload without checking that the requested scan matched. Reusing the same key for completed scan B after scan A could therefore return scan A's report as the result of scan B's request. The replay branch now rejects that mismatch with HTTP 409 `IDEMPOTENCY_CONFLICT`, before durable submission or artifact mutation. Legitimate replay for the same scan remains allowed.
- `175f938f9ea6ff4c876dff0ffd9c83385176cdbb`: added an API-level regression test with two completed scans owned by the **same tenant**. It checks first creation, same-scan replay, rejection and no new report on cross-scan key reuse, and independent creation with a fresh key.
- **Executed:** 10 source-level checks passed against the retrieved committed route and regression test. The exact committed regression test was copied into an unprivileged local sandbox, its Git blob hash matched `43c78d2c99b3a898f4b73580f24c295df67669e5`, and Python AST parsing passed as user `nobody`. **Not executed:** the new pytest integration test itself, full backend pytest, frontend suite, browser journeys, or deployment tests; a complete repository checkout was unavailable. This is code-level reproduction/substantiation and syntax verification, not integration acceptance.
- Prompts **0B, 6, 22, 23, 28, 35** remain **PARTIAL** or **NOT TESTED** as applicable. Prompt 34 remains **BLOCKED** on independent acquisition quotas, controlled egress, and scanner isolation. No acceptance item is certified complete by this change.


## PR review publication generation and duplicate-action recovery (2026-10-27)

- **Substantiated/reproduced:** The legacy `ChangeAnalysisWorkspace` preview handler guarded only successful publication state. Its error and loading-finally paths were unguarded; approval and publication handlers had no generation guard at all. In an isolated execution of the original approval handler, a response for analysis A resolved after switching to analysis B and called `setPublication` with A's approval. Repeated clicks could also start overlapping preview/approval/publish actions before React re-rendered.
- `a32501117acadfcc7e10762f273f1e0d74b3b68d`: the three handlers now capture their originating analysis ID and generation, discard stale UI results/errors/finally resets, and share a synchronous publication-action lock. Starting another analysis clears the previous publication state, confirmation, loading flags and lock; an old action's finally block cannot release the new generation's lock. No backend authorization, approval, digest, or publication policy was altered. An already-sent request cannot be cancelled by this UI protection.
- `3147899ee59f6c0f284ac60f195db5342bd26e4f`: added six frontend Node regression cases that execute the checked-in handler bodies with inert API fakes, covering stale preview success, stale approval failure, stale publication refresh, cross-action duplicate prevention, retry after failure, and new-analysis reset.
- **Actually executed:** six focused behavioral/reset scenarios passed against the fetched committed `main` workspace source in an isolated JavaScript V8 harness. **Not executed:** the committed Node test file via the repository runner, TypeScript type-check, frontend build, browser flows, backend pytest, or production acceptance. Prompt 19 (operator publication), 22 (account/resource isolation), 28 (frontend), and 35 (final audit) remain **PARTIAL**/**NOT TESTED**; no prompt has been independently certified complete. Prompt 34 remains **BLOCKED** on independently enforced acquisition quotas, controlled Git-only egress, scanner isolation and deployment evidence.


## Published PR review digest binding (2026-10-27)

- **Substantiated from committed control flow:** `ReviewPublicationService.approve_preview`, `ReviewPublicationService.publish_review`, and the `/review-publication/publish` API returned a previously published review **before** validating the caller's `expected_preview_digest`. Thus an incorrect digest could receive a successful replay response, contradicting the exact-preview authorization contract. The PUBLISHING service path could also reconcile before rejecting a wrong digest.
- `a5d6f44074d0d8215dbeccae1509104ce149dc5a` and `cbc6b39f909972729ac8a84363c6acfadac12b4a`: validate the supplied digest before published-state idempotent returns and before uncertain-write reconciliation, at both the service and API boundaries. Correct-digest idempotent replay remains allowed; no GitHub writes, authorization, CSRF, or approval gates were relaxed.
- `44472fd732dfac1b89a87c5df3749e228f02c22f` and `d17bafba367cbdbd90cbd610aa4e3de78f470dbc`: added two service regression tests (PUBLISHED mismatch and PUBLISHING mismatch without reconciliation) and one API regression test (approve/publish mismatch, exact replay success).
- **Actually executed:** seven source-level assertions against fetched committed service, route and test files passed, including digest-check ordering before both early returns and the reconciliation branch. **Not executed:** the three new pytest tests, complete backend suite, database integration, external GitHub write, frontend build, or browser journey. Prompts 13/19/22/35 remain **PARTIAL**/**NOT TESTED**; no item certified complete. Production hard isolation (34) remains **BLOCKED**.


## Exact-revision structural diff provenance in PR reports (2026-10-27)

- **Substantiated from current `main` source:** `GET /change-analyses/{id}/diff` previously returned any nonempty persisted `diff_result`, even when its base/head commit IDs belonged to a different analysis. `generate_change_analysis_report` treated any dictionary with string SHA fields as recorded AST evidence and rendered its contract deltas under the requested analysis's revisions. Thus mismatched persisted evidence could be attributed to the wrong exact commit pair. A missing diff could also appear as four zero contract-delta counts in the Markdown report.
- `12a705502ea1504473878bebd6337e44d7a94b64`: the report generator now accepts structural diff evidence only when both recorded commit IDs match the analysis's immutable base/head revisions. Unbound or absent diff data contributes no route/schema/dependency/config deltas; the Markdown table explicitly says **Unavailable**, and the structured report discloses incomplete contract-delta coverage.
- `8fe4af28d3ceeea25ec74cff5a12c4929472e8d2`: the diff API rejects mismatched or absent revision evidence with its existing HTTP 409 `CHANGE_DIFF_UNAVAILABLE` response. Ownership checks remain before evidence access.
- `42276ed1dcf84881325b1a2deab3c5c3b9e7d22c`: added a parameterized API regression for wrong base SHA, wrong head SHA, and absent diff. It verifies diff rejection, safe JSON report fallback, and Markdown unknown-count disclosure.
- `f5dec92a2a321169fe94cbf452099ad785c9d949`: added explicit Markdown limitations for missing or mismatched structural evidence.
- **Actually executed:** seven source-level checks against the fetched committed `main` route, report generator and regression test passed; a local Python AST parse and two isolated Markdown count-formatting assertions passed for the changed expression. **Not executed:** the three new pytest parameter cases, complete backend suite, full frontend type-check/build, browser journeys, or deployment acceptance. Local `git ls-remote` could not resolve `github.com`; connector-backed commits and source reads worked. This is code-level substantiation and syntax/formatting verification, not end-to-end acceptance.
- Prompts 15/17/18/22/28/35 remain **PARTIAL** or **NOT TESTED**; no acceptance item is independently certified complete. Production hard isolation (34) remains **BLOCKED** on trusted acquisition quotas, Git-only egress, external scanner isolation, and host verification. No auth/CSRF/tenant, human approval or production isolation policy was relaxed.


## Missing and malformed AI review evidence in change reports (2026-10-27)

- **Substantiated from current source:** A missing or non-dictionary `review_report` was normalized to an empty findings list, but the Markdown executive summary still rendered **0 Verified Review Findings**. A nonempty malformed value could also be treated as successful LLM review in the fallback status branch despite the authenticated `/review` API returning `CHANGE_REVIEW_UNAVAILABLE`.
- `98fdc15f3f4e896065f2d578738f13caee370269`: derives LLM success and capability flags from a validated review dictionary; shows **Unavailable** instead of zero when review evidence is absent or malformed (or when persisted finding records are malformed), and adds an explicit structured-report limitation.
- `39df36ff554d8dcbc67c818bb342983bc8ad84d2`: added two parameterized API regression cases for missing and malformed persisted review evidence. They cover review endpoint rejection, degraded JSON report, and Markdown disclosure.
- **Actually executed:** seven source-level assertions passed against fetched committed `main` source/test files. Python AST parsing and three isolated Markdown count-formatting scenarios passed for copied changed expressions. **Not executed:** the two new pytest parameter cases, complete backend suite, browser journey, or deployment tests; a full local checkout remains unavailable due to DNS resolution failure. These checks do not certify integration behavior.
- Prompts 18/22/28/35 remain **PARTIAL** or **NOT TESTED**. Prompt 34 remains **BLOCKED**; no acceptance item has been certified complete.
- `10d6ea54004265bb1d8353d902fb4c2f844d9f81`: refactored both contract and review count presentation through `_format_evidence_count` to avoid nested f-strings and keep zero distinct from unavailable. **Actually executed:** four isolated Python helper assertions and AST parsing on a copied helper body passed. The committed pytest cases and complete repository checks remain **not executed**.

## Artifact retry ordering regression (2026-10-27)

- Existing completed-analysis retry UI and tests: `frontend/tests/change-analysis-artifact-retry.test.mjs`. The previous run's pending write is now visible on main; it must not be treated as proof that a full frontend suite passed.
- `0d89a28d3dc6fe129ef55f2f355c1206b456b2de`: prevent a superseded artifact request from overwriting a newer report, impacts, diff, telemetry, or availability/error state. Reproduced against the previous main source: two loads were started, the newer completed first, then the older completed and incorrectly replaced `new` with `old`.
- `4e9920adb42d9dbd7a891c48f5e30ffa443063d0`: add `frontend/tests/change-analysis-artifact-ordering.test.mjs`, including overlapping-response ordering and invalidated-analysis generation tests.
- **Actually executed**: two isolated behavioral assertions against the updated committed artifact loader (out-of-order response and stale generation) passed in a JavaScript harness. **Written but not executed**: the two committed Node tests. Full frontend Node suite, TypeScript type-check, Next.js build, backend pytest, and browser acceptance were not run in this environment. Prompts 18, 24, and 28 remain **PARTIAL**.


## Stale report download isolation (2026-10-27)

- `aa22ac8a80e65869d08b60128fd6e86b7ac2bc36`: guard asynchronous Markdown report downloads against analysis generation changes and invalidate pending async callbacks when the workspace unmounts. The prior implementation could start a download for analysis A, navigate to B, then still download A's report when its request completed.
- `99b8f0e0b067bb4b76d1f1ed9852504f00fa4fcd`: add `frontend/tests/change-analysis-report-download-isolation.test.mjs` (two behavioral tests and one unmount guard check).
- **Reproduced before fix** using the retrieved original handler: an obsolete response triggered one browser download. **Actually executed after fix**: two isolated handler cases passed (obsolete report produces no download; current report downloads once), and unmount guard source was inspected. The committed Node tests, full frontend suite, TypeScript check, build, backend tests, and browser end-to-end tests remain **unexecuted**. Prompt 22/28 acceptance remains **PARTIAL**.



## Publication artifact recovery versus operator actions (2026-10-27)

- **Substantiated:** the completed-analysis artifact loader independently fetches optional persisted review-publication state. If this request begins before an operator generates a new preview or approves/publishes a review, its delayed response could overwrite the newer local publication result. The existing analysis-generation and artifact-load-sequence guards did not distinguish operator actions within the same analysis. A simplified asynchronous reproduction demonstrated `old-preview` replacing `new-preview`.
- `ea69712ea2899c94e2f311da625383b36bf45454`: added a publication-action sequence and pending-action check. Preview generation, approval, and publication increment the sequence on start and completion; the artifact loader only applies a persisted publication when no newer operator action intervened. The analysis-generation, human-approval, and tenant boundaries remain intact.
- `0580758f867e6d4f74bda9e0dd396a52fb631d98`: added `frontend/tests/change-analysis-publication-artifact-race.test.mjs` with delayed stale-preview, pending-action, approval ordering, and normal persisted-load cases.
- **Actually executed:** in the isolated copied-source Node harness, removing the new publication guard made 3 of 5 regression cases fail (2 pass); restoring the guard made all 5 pass. The tests exercise the copied committed loader and representative action markers, not the complete repository checkout. Additionally, five focused Node test cases passed against a locally copied artifact-loader excerpt plus action markers; source-level checks against the fetched committed `main` confirmed all three action entry guards, finalizer increments, pending guard, and test presence. **Not executed:** the committed Node test against a complete repository checkout, full frontend test/type-check/build, backend suite, browser acceptance, or CI. The container could not resolve `github.com` for a full checkout. Prompt 19/24/28 remain **PARTIAL**; Prompt 35 remains **NOT TESTED**. No acceptance item is certified complete.



## Synchronous artifact-retry exclusion (2026-10-27)

- **Reproduced on retrieved pre-fix source:** two immediate invocations of `retryCompletedArtifacts` both entered `loadCompletedAnalysisData` before React could update `isRetryingArtifacts`; the isolated harness observed 2 requests when only 1 should start.
- `0b7903e49151b16276b3cc690f64286724acc149`: committed `frontend/tests/change-analysis-retry-concurrency.test.mjs` covering synchronous duplicate retries, nonterminal rejection, and stale completion after a new analysis starts.
- `454f81af844c21ba561425b225046bf2ec6edf08`: introduced `artifactRetryPendingRef` to exclude immediate re-entry; reset on a new analysis, and release only for the current generation. No backend auth, publication approval, or scanner isolation behavior changed.
- **Actually executed:** 7 focused JavaScript behavioral assertions against the fetched committed retry handler passed. **Written but not executed in the repository:** the new Node regression file. Full frontend tests, TypeScript, Next.js build, backend pytest, and browser acceptance were not run. Prompts 24 and 28 remain **PARTIAL**; production isolation and Prompt 35 remain blocked/unverified.


## Optional publication fetch must not stall mandatory analysis evidence (2026-10-27)

- **Reproduced on fetched pre-fix source:** when `fetchReviewPublication` remained unresolved, `loadCompletedAnalysisData` did not complete and did not set the already-ready required report. The isolated reproduction observed `required_report_loaded=false` while the optional request hung.
- `f8f71e0559b377716c5a12c2898fdf252a0fc2a1`: committed three Node regressions in `frontend/tests/change-analysis-optional-publication-recovery.test.mjs`.
- `ad08d9b1ffdc0195f5a3fd4b702430dc2ace8614`: moved optional publication retrieval off the mandatory five-artifact `Promise.allSettled` path; kept generation, load-sequence, pending-action, and operator-action-sequence guards. Optional 404/failure is not treated as missing required evidence.
- `ebf8534a872b6394a36bbebd55abec382c784155`: corrected the existing artifact-ordering test fixture to supply publication guard refs used by the loader.
- **Actually executed:** six isolated JavaScript checks against the fetched committed loader passed (mandatory report loads without publication, delayed optional success, stale generation, optional rejection, operator action invalidation). **Not executed:** the newly committed Node tests, complete frontend tests/type-check/build, backend suite, and browser acceptance. Prompts 18/19/24/28 remain **PARTIAL**. No release gate is certified.


## Independent required-artifact recovery and clipboard correctness (2026-10-27)

- **Reproduced on pre-fix source:** when completed-analysis telemetry remained unresolved, the existing five-request `Promise.allSettled` prevented an already-resolved Markdown report from appearing. The isolated harness observed a null report after the report fetch resolved.
- `0cdffdac4750e5a9f4e7427191d5499dea5821ed`: apply each successful required artifact as soon as it resolves, while preserving analysis-generation and artifact-load-sequence checks. Aggregate missing-artifact error reporting still runs once all required requests settle. A permanently hung request still needs timeout/retry policy; this fix ensures it does not conceal already-ready evidence.
- `953015ab9675fb9140da556fcb0a2dcd62ddcba8`: added `frontend/tests/change-analysis-partial-artifact-recovery.test.mjs` (3 Node regressions for stalled sibling, rejected telemetry, and obsolete generation).
- **Reproduced on pre-fix source:** the report copy handler immediately displayed “Copied!” before the browser clipboard promise resolved, including when permission could later be denied.
- `4f57e5f38ad04ccae481f3381d33f9481c00ac65`: await clipboard confirmation, handle rejection visibly, invalidate obsolete copy callbacks, and protect newer success indicators from older timers.
- `2d68edd1ed05d909e9c8342b129bb7c04355d679`: show clipboard failure adjacent to the report controls.
- `3ceee6e2990c2c27d9b9373fa84226ae39aa349d`: added `frontend/tests/change-analysis-report-clipboard.test.mjs` (4 Node regressions for pending/denied/stale copies and timer ordering).
- **Actually executed:** seven isolated JavaScript behavioral checks against the fetched committed artifact loader and clipboard handler passed (three artifact checks, four clipboard checks). Both original defects were reproduced against pre-fix source. **Written but not executed:** the two committed Node test files. Full frontend test suite, TypeScript check, Next.js build, backend pytest, live browser journey, and deployment gates were not executed; local Git checkout was blocked by DNS resolution. Prompts 18/24/28 remain **PARTIAL**; Prompt 34 remains **BLOCKED**, Prompt 35 **NOT TESTED**.
