# Live Model Evaluation Campaigns

RepoLens provides an explicitly staged campaign coordinator for comparing
registered provider/model pairs on the same fixed, public 35-case DEV
repository-scan corpus. It reuses the production `FULL_ANALYSIS_GRAPH`,
canonical full-analysis evaluator, exact model route, fresh repository fixture
and checkpoint per case/trial, disabled response caching, and no cross-model
fallback. It records exact system identities and requires every observed model
execution to match the planned provider/model pair.

This is a manual evaluation workflow, not an automated model selector or
promotion system. Campaign artifacts are local, immutable JSON evidence under
`backend/evaluation_artifacts/model_campaigns/`; they are ignored by Git. A
campaign plan is frozen to the current source revision, model registry, graph,
prompts, tools, context policy, evaluator contract, and fixed DEV inventory.
Execution requires a clean checkout of that exact source revision.

## Stages

1. `preflight` checks exact registry entries, adapter availability, configured
   credentials (as booleans only), context/output budgets, and declared
   capability gaps. It makes no provider call. Ollama reachability is not
   probed.
2. `plan` freezes two to four candidate arms, one baseline, exact identities,
   the source revision, and deterministic case selection. It makes no provider
   call.
3. `smoke` runs one correctness and one security case once per candidate.
   Eligible arms can proceed to pilot.
4. `pilot` runs four correctness and four security cases twice, in deterministic
   paired order. A human explicitly chooses which eligible arm(s) advance.
5. `full` runs all 35 public DEV cases five times for the baseline and exactly
   one explicitly selected finalist.
6. `security-gate` and `context-gate` are separate, manual supplemental
   evaluations. The former uses the canonical public adversarial security
   corpus with three trials per case. The latter reuses the existing
   context/tool experiment with five full-DEV trials and its scripted security
   boundary gate. Neither can be silently inferred from a full-analysis run.
7. `analyze` recomputes paired summaries and a Pareto set. Human-review
   eligibility requires both supplemental gates to pass. It never applies a
   model, changes production configuration, or performs a promotion.

Provider/model pairs may have declared capability gaps for full-graph roles.
Preflight reports those gaps honestly; planning never invents capabilities.
Because the campaign pins one model for every role, a missing required
capability may lead to a controlled provider/routing failure rather than a
substitute model. Use those results as an evaluated limitation, not as a
successful full-role comparison. Mutable model aliases are identified as such;
provider-returned revisions are retained when available, and `UNKNOWN` is not
treated as pinned.

## Commands

Run from `backend` with the repository virtual environment. Replace every
provider/model identifier with an exact current registry entry:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.campaign preflight `
  --arm baseline=gemini:<exact-model> `
  --arm alternate=groq:<exact-model>

.\.venv\Scripts\python.exe -m app.evaluation.campaign plan `
  --arm baseline=gemini:<exact-model> `
  --arm alternate=groq:<exact-model> `
  --baseline baseline --seed 7
```

The plan command prints the campaign ID and saves `plan.json` in the dedicated
campaign artifact directory. Smoke is explicitly live-authorized:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.campaign stage <campaign-id> smoke `
  --allow-live --allow-model-campaign
```

After reviewing smoke eligibility, choose pilot arms:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.campaign stage <campaign-id> pilot `
  --candidate-id alternate --allow-live --allow-model-campaign
```

After reviewing pilot results, choose exactly one eligible non-baseline
finalist. Full evaluation has an additional explicit authorization:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.campaign stage <campaign-id> full `
  --candidate-id alternate --allow-live --allow-model-campaign --allow-full-campaign
```

Supplemental validation requires distinct opt-ins:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation.campaign security-gate <campaign-id> `
  --allow-live --allow-model-campaign --allow-adversarial-security-eval

.\.venv\Scripts\python.exe -m app.evaluation.campaign context-gate <campaign-id> `
  --allow-live --allow-model-campaign --allow-context-tool-experiments

.\.venv\Scripts\python.exe -m app.evaluation.campaign analyze <campaign-id>
```

Live execution is not part of normal CI and no live campaign is run by tests.
There is no caller-provided corpus root and no private/final holdout access.
All tool use remains read-only and inside the existing production boundaries.

## Statistics and interpretation

Campaign comparisons are paired by case and trial; Wilson intervals are
reported for per-case all-trial success. Smoke and pilot are elimination and
selection evidence only. Full evaluation is five trials per case, but it still
does not prove generalization beyond the public DEV inventory. Multiple models
are compared descriptively across measured task success, precision, recall,
F1, evidence validity, hard safety, unsupported confirmations, tokens, cost,
latency, tool calls, retries, and fallbacks. A missing provider measurement is
`NOT_MEASURED`, never zero.

The security evaluation reports model-request compromise separately from
deterministic system compromise. Its gate is required, but live security
behavior is not implied by a scripted boundary test. The context/tool gate
reports full workflow results and is separate from first-tool micro-evaluation.
The final Pareto set is human-review-only. No single scalar score hides quality
or safety regressions, and no campaign can modify prompts, routing, budgets,
tools, source, or deployment state.

Tests can validate plan construction, deterministic schedules, artifact
integrity, opt-in boundaries, report analysis, and evaluator wiring without
provider keys. Such tests prove harness behavior only; they do not measure live
model capability. A live campaign should be reported as `NOT EXECUTED` unless
providers were actually called under the explicit opt-ins.
