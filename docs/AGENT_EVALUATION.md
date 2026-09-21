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
