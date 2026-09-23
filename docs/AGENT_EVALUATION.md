# Evidence Investigator evaluation

RepoLens has a deterministic, zero-key evaluation gate for the bounded Evidence
Investigator. The evaluator drives the production LangGraph investigator nodes
and canonical `AgentToolRegistry` against temporary, hostile-looking fixtures.
It does not import or modify the frozen repository ground-truth benchmark.

From `backend/`, run:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.agent `
  --mode scripted `
  --regression-gate evaluation_data/agent/v1/regression_gate.json `
  --output agent-eval-scripted.json
```

The versioned corpus is in `backend/evaluation_data/agent/v1/`. Its manifest
and committed baseline carry the dataset hash, while the baseline also pins the
evaluator-contract hash. Hidden case annotations and scripted decisions are
never included in model-facing state.
The scripted router is synthetic and is explicitly marked
`SCRIPTED_NOT_A_REAL_PROVIDER`; scripted metrics therefore measure trajectory,
policy, evidence binding, and durability behavior, not model capability.

`evidence_validity_all_cases` is the fraction of all cases with trusted
evidence. `required_evidence_success_rate` excludes intentionally abstaining
or negative-result cases that do not require positive evidence.

Reports also expose bounded safety and context telemetry: unsafe tool requests
versus executions, duplicate executions, checkpoint resumes/duplicates, context
budget terminations, context measurement count, and maximum packed context
bytes. No dollar cost is inferred from scripted trials.

Live trials are manual and opt-in only:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.agent `
  --mode live --allow-live --live-trials 3 `
  --output agent-eval-live.json
```

Each live trial gets a fresh fixture and checkpoint. Provider failures are
reported as failures or `NOT EXECUTED`; they are never converted into scripted
scores. The investigator remains read-only, bounded by the production step and
tool budgets, and cannot publish or mutate findings.

## System identity, paired comparison, and promotion checks

The opt-in system evaluator measures the actual production Evidence Investigator
LangGraph nodes and routing predicates against the same isolated fixture and
canonical `AgentToolRegistry` used by the existing evaluator. It intentionally
does **not** claim to run the full scan workflow: mapper, specialists, verifier,
revision, application/database orchestration, and external MCP transport are
outside this phase's measured scope. Findings still enter the investigator as
bounded `POSSIBLE` candidates; this evaluator does not accept or publish them.

Run deterministic system-harness checks without provider keys:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.system run `
  --mode scripted --suite ALL --trials 3 --max-cases 32 `
  --output system-eval-scripted.json
```

The scripted runner exercises the real investigator graph/tool/context code,
but uses committed deterministic decisions; it is not evidence of model
capability. Each trial gets a new fixture, graph checkpoint, thread ID, and
workflow budget. Evaluation annotations, expected actions, and hidden canaries
remain grader-only.

Live evaluation requires an explicit candidate, explicit permission, and that
provider's credentials. It routes through RepoLens's normal `LLMRouter`,
capability gateway, provider adapter, quota, workflow budget, and structured
output validation. The context-local evaluation override pins one exact
provider/model, disables reusable response caching, and disallows cross-model
fallback. A live success is rejected unless recorded execution metadata proves
that exact provider/model ran. Retries are constrained by the production
one-model-call decision budget; candidate/provider failures stay failures.

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.system run `
  --mode live --allow-live --provider gemini --model <registered-model-id> `
  --suite ALL --trials 5 --max-cases 32 --output candidate.json

# Run the baseline with the same suite, trial count, and case limit, then:
.\.venv\Scripts\python.exe -m app.evaluation.system compare baseline.json candidate.json
.\.venv\Scripts\python.exe -m app.evaluation.system promote-check baseline.json candidate.json
```

Reports identify the model, source components, prompts, state/schema versions,
tool contract manifest, context/retrieval/router policies, dataset, and effective
budgets. Reports expose per-case and per-trial outcomes, bounded trajectory
digests, evidence references, safety counts, provider/model metadata, context
bytes, latency, and token/cost metrics only when actually reported. Unavailable
usage is `NOT_MEASURED`, never treated as zero. Report hashes are deterministic
integrity digests, **not signatures**; artifacts must be obtained from a trusted
evaluation run.

Comparison rejects incomplete/incompatible reports. The exact investigator
prompt is recorded by version and digest and may be the explicit candidate
dimension; changing prompt content without incrementing its version makes the
comparison invalid. Decision schema, evaluator contract, tools, context packing,
retrieval, router, budgets, and feature policy remain compatibility gates. This
lets a baseline report produced by the same evaluator before a prompt edit be
compared with a candidate report after it, without treating changed evaluation
rules or tool authority as a prompt improvement. Its Wilson intervals use
fixture-level all-trials success (not correlated model turns) as the independent
unit. Promotion is a non-mutating human-review signal only: it requires the
complete `ALL` suite, five fresh trials per case, a fully passing security
subset, no regression failures, no hard safety violations, no provider/harness
failures, and a measured meaningful improvement. No model, prompt, deployment,
or production setting is changed automatically. Partial runs are useful for
development but cannot be compared/promoted as complete evidence.

The manual `production-validation.yml` workflow can run paired baseline and
candidate evaluations when explicitly enabled. It uploads the reports and
comparison artifacts; provider credentials are exposed only to the selected
provider's evaluation step, not dependency installation or report comparison.
Live evaluation remains absent from normal pull-request CI and does not require
Docker, PostgreSQL, Redis, or provider secrets unless that manual option is
selected.

Current measured scope is the investigator graph only. Full analysis-workflow
evaluation, authenticated report signing, and the future Agent Improvement Lab
(automatic prompt optimization or harness modification) are not implemented.
