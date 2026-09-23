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

## Full production analysis graph scope

The same CLI can now evaluate the production repository-analysis graph, while
keeping the original investigator-only scope as the default and preserving old
1.0 reports:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.system run `
  --scope full-analysis --mode scripted --suite ALL --trials 1 `
  --max-cases 64 --output full-analysis-scripted.json
```

The full-analysis harness executes RepoLens's actual mapper, parallel
specialists, verifier, configured MCP-enrichment/investigator path, bounded
revision, and finalization nodes through `run_analysis_workflow`. Each trial
uses a newly populated temporary repository, a new scan ID, checkpointer,
workflow state, repository runtime, and in-memory retrieval index. It passes
only `LeakageDetector.bifurcate_input(case)` to the analysis fixture; benchmark
annotations stay in the evaluator. Fixture contents are parsed and scanned as
untrusted data but are never imported or executed. The deterministic core
scanner runs locally; external scanner binaries, fixture tests, GitHub API
delivery, remote MCP transport, and the production database are not part of
this scope.

Only DEV `REPOSITORY_SCAN` ground-truth cases are eligible. Reports use the
separate `FULL_ANALYSIS_GRAPH` scope, include bounded content-free node events,
structural final-output metrics, and deterministic failure attribution. A
miss is attributed to a named stage only where node provenance and the
structural matcher prove the causal connection; otherwise it is
`UNKNOWN_ATTRIBUTION`. The evaluator has no caller-supplied case-root option;
it reads only the canonical public benchmark tree and does not load sealed
private holdout labels. Source text, labels, and private holdout artifacts are
not included in reports.

`scripted` mode is a zero-key graph/harness test, not model-capability evidence:
its controlled router returns empty specialist outputs and abstains if the
investigator is reached. It commonly grades issue cases as failures by design.
Live evaluation is opt-in, requires `--allow-live` and one exact provider/model,
uses RepoLens's canonical router and workflow budget, and runs serially. The
hard limit is 64 cases, five fresh trials per case, and 320 case-trial work
units. Partial reports are useful for diagnostics but cannot be compared or
promoted as complete evidence.

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.system run `
  --scope full-analysis --mode live --allow-live `
  --provider gemini --model <registered-model-id> `
  --suite ALL --trials 5 --max-cases 64 --output full-analysis-candidate.json
```

Comparison rejects scope mismatches and requires matching graph, dataset,
evaluation contract, tool, context, routing, and budget identities. The
non-mutating promotion check additionally requires the complete DEV dataset,
five trials, a passing security subset, no unsupported confirmations, and no
hard safety or harness/provider failure. `PROMOTION_ELIGIBLE` is only a signal
for human review; nothing is automatically promoted. Report SHA-256 digests
detect content changes but are not signatures or proof of trusted origin.

The existing manual `production-validation.yml` workflow exposes this scope as
an explicit input. It remains excluded from ordinary pull-request CI; only the
provider-specific execution steps receive credentials, while comparison and
promotion steps do not.

## Offline Prompt Improvement Lab

RepoLens includes a bounded, evaluation-only prompt Improvement Lab. It consumes
only integrity-validated, complete public DEV `FULL_ANALYSIS_GRAPH` reports,
uses deterministic failure attribution to select a registered prompt, and
reuses the canonical full-analysis evaluator, paired comparison, and promotion
gate. It can propose prompt candidates and produce a human-review signal; it
never changes production prompt files, runtime settings, routing, tools,
evaluation logic, datasets, labels, or promotion policy.

Only these current LLM prompt surfaces are registered: architecture, security,
bug, verifier, revision, and evidence-investigator. Integration has no current
LLM system prompt and mapper is deterministic. Failure attribution can select
verifier, revision, evidence-investigator, or a specialist only when
deterministic provenance proves one unique candidate opportunity. Specialist
targeting requires an exact registered candidate-kind/ground-truth-rule
mapping, an exact fixture snapshot match, source evidence locators actually
packed into the specialist context, a normal provider-backed model execution
with validated structured output, and no matching candidate output from that
model. Scripted harness identities, malformed or evidence-rejected output,
provider failures, admission/context omissions, ambiguous opportunities,
unsupported candidate kinds, and unknown causes are never specialist prompt
targets. The currently registered ground-truth mappings cover selected
security-flow and bug/correctness candidates; architecture currently has no
targetable mapping because the public evaluator has no corresponding
architecture candidate rule contract. Attribution alone is not enough to
generate candidates: the lab also requires repeated failures across distinct
public DEV cases and families. Unsupported, provider, budget, harness, and
unknown attributions are not optimized. A failure family with insufficient
distinct DEV examples stops without generating candidates.

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.improvement analyze baseline.json --output corpus.json
.\.venv\Scripts\python.exe -m app.evaluation.improvement optimize baseline.json `
  --allow-live-optimization --generator-provider gemini `
  --generator-model <exact-generator-model> --output improvement-run.json
```

The `optimize` command makes no provider calls without
`--allow-live-optimization`. A semantic optimization run requires a current,
complete, five-trial LIVE baseline from the exact production graph and current
public DEV corpus. Candidate evaluation uses the baseline's exact provider and
model; generator identity is recorded separately. Each run is capped at two
generations, four candidates per generation, at most eight candidate screen
workflows, three full-DEV candidate evaluations, bounded model requests, 640
case-trial work units, and a one-hour wall-clock budget. These limits are
policy-versioned. The optimizer reserves at most 160,000 tokens across its own
reflection/generation requests (12,000 input + 8,000 output per reservation,
ten calls maximum). That reservation is not a global ceiling for candidate
evaluation. Candidate screen/full-evaluation model calls, reported input/output
tokens, retries, fallbacks, and cost are aggregated from the existing
full-analysis reports without double-counting. Missing provider usage is
`NOT_MEASURED`, never zero; work-unit, per-workflow AI-budget, candidate, and
wall-clock ceilings remain the pre-execution controls. When retries or
fallbacks occurred but their failed-attempt token/cost usage is unavailable,
the corresponding total token/cost metric is also `NOT_MEASURED`; retry and
fallback counts remain separately reported.

Candidate text is installed through an async-context-local evaluation overlay;
production prompt constants are never mutated. Candidates must preserve
registered mandatory clauses and pass deterministic safety, size, URL, secret,
case-ID, and fixture-path checks. The sanitizer is one defense, not a semantic
security proof. Each experiment changes exactly one registered prompt
component. The Improvement Lab verifies the baseline/candidate prompt-component
maps and exact overlay identity, requiring the changed-component set to equal
the selected target; every other component's version and digest must match.
The generic compatibility digest intentionally allows candidate-capable prompt
surfaces to vary, so compatibility-digest equality alone does not establish
prompt-only causal isolation. Application tool authority, snapshots,
verification, resources, and the existing human boundary remain independent of
prompt text. Candidate comparison still uses the existing full-report
compatibility, paired comparison, and non-mutating human promotion gate.

The deterministic development screen records four explicit groups:
target-attributed failures, withheld validation cases, security cases, and
known-good preserve/regression cases when available. Selection is fixed by the
versioned policy, target component, public corpus digest, case ID, and case
family; any remaining capacity is separately labeled deterministic fallback.
If the target has no known-good preserve examples, the report records that
limitation rather than describing fallback cases as regression evidence. The
screen uses one trial per case and is only a low-confidence elimination stage:
it cannot establish promotion eligibility. A survivor must still pass the
existing full public DEV evaluation with five fresh trials per case and the
existing comparison/promotion gates. Precision and recall may not regress.
Scripted reports are accepted only for offline harness/corpus tests and can
never establish real prompt improvement.

The lab reads only the canonical public DEV repository-scan dataset. It accepts
no dataset-root or holdout-path override and does not call holdout loaders. The
full-analysis evaluator and lab share a code-owned fixed inventory of the 35
public DEV repository-scan case files; they do not recursively discover JSON
files. Report case IDs are checked against this inventory before trial details
are serialized. All inventory paths are checked for symlink/junction escapes
before any case is opened, and files outside that inventory are never loaded.
Corpus and per-example truncation are recorded. The CLI rejects known
private/holdout baseline paths, refuses to overwrite output, and
restricts in-repository artifacts to `backend/evaluation_artifacts/improvement_lab`.
Validation-family IDs are withheld from reflection and candidate generation;
they are selected deterministically and recorded, but their labels are only
observed by the evaluator. There is no automatic source patch, commit, push,
PR, deployment, or private-final holdout execution. A generated candidate is
not evidence of improvement; absent an actual compatible comparison,
`REAL PROMPT IMPROVEMENT NOT MEASURED`.
