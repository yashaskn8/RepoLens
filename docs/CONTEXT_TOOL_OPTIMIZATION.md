# Context and Tool Optimization Lab

RepoLens includes an evaluation-only harness for controlled, one-factor
experiments over context packing and Evidence Investigator tool presentation.
It does not alter production configuration, prompt text, graph topology,
retrieval algorithms, tool schemas, registry authority, implementations, or
authorization. Diagnostic reductions are observations **under the tested
workload**, not universal claims that evidence or a tool is unnecessary.

## Experiment path

```text
Fixed public DEV baseline
  → content-minimized actual-request manifests
  → deterministic one-factor overlay
  → one-trial diagnostic screen
  → repeated full public DEV evaluation (live only)
  → scripted agent-security gate
  → quality/safety comparison
  → interpretable Pareto set for human review
```

The screen records `TARGET_FAILURES`, `VALIDATION`, `SECURITY`, and
`PRESERVE_REGRESSION` groups. Group membership is deterministic, digest-bound,
and reportable; a group may be empty when the selected workload has no matching
case. Preserve cases come from successful baseline trials when available. A
screen uses one trial and is only a low-confidence elimination stage. It is
never promotion evidence. Live full-DEV evaluation defaults to five trials per
case; at least three repeated trials are required even to consider a human
review recommendation. The lab reuses the canonical full-workflow comparison's
fixture-level Wilson intervals over all-trials-consistent case outcomes. An
invalid comparison is an invalid experiment; overlapping intervals or
insufficient separation remain `INCONCLUSIVE`, even when an efficiency metric
improves. This conservative gate does not claim equivalence, and efficiency-only
savings may not qualify without measured task-success separation. A human-review
recommendation also requires complete public DEV coverage, unchanged system
identity, preserved quality and safety, and the scripted security gate. Live
security evaluation remains separate and is never started automatically.

## What may vary

V1 supports exactly one presentation dimension per candidate:

- reduce a context token budget, while deterministic anchor and required
  evidence checks remain in force;
- reduce the maximum retrieved chunk count, never below protected candidate
  anchor capacity;
- omit one optional context group (`chunks`, `graph_edges`, `contracts`, or
  `static_findings`) where the production packer supports that group;
- hide one tool from the investigator's model-visible catalog; or
- substitute bounded, reviewed purpose text for one existing read-only tool.

Tool presentation is not tool authority. `permitted_tool_names`, typed policy
checks, and `AgentToolRegistry` remain unchanged; hidden tools are not remapped
and candidate descriptions cannot alter schemas or implementations. The
prompt-improvement overlay and context/tool overlay cannot be active together.
Model/provider, graph, retrieval algorithm, dataset, evaluator, budgets,
security policy, snapshot binding, and every other system condition remain
fixed.

## Manifests and interpretation

Manifests are recorded at the actual LLM request boundary. They contain request
and context digests, the effective request/context token budget, packed bytes,
estimated input tokens, included/available and required/optional counts where
supplied by the production packer, deduplication counts/bytes when measured,
compacted-observation counts, evidence identifiers, truncation and truncated
candidate IDs, visible tool names, and tool definition/schema digests. Raw
prompt, source, and tool-result text is not serialized in the
experiment report. Token counts are estimates (not attention measurements).
Downstream evidence reference counts, where available, are only an observable
proxy: they do not show what the model attended to or “ignored.” Missing
provider usage remains `NOT_MEASURED`, never zero.

The first-decision micro-evaluation runs the production investigator prepare
and decision nodes, then stops before tool execution. It uses only curated
first-action annotations and separately grades tool choice, hidden/forbidden
requests, and argument validity. It is diagnostic only; the full production
graph remains the authority for candidate quality.

Quality and safety are evaluated before efficiency. Regressions in precision,
recall, F1, task/evidence success, false positives/negatives, unsupported
confirmations, unsafe tool requests/executions, or hard safety outcomes block a
recommendation. No weighted efficiency score is computed. Pareto analysis
returns a nondominated set across measured context tokens, tool calls, latency,
and cost; unknown values are not treated as zero.

Only candidates that have already passed full-DEV quality/safety comparison and
have a measured efficiency improvement plus a valid, meaningfully separated
task-success comparison enter the Pareto set. Candidate/full report digests and
the canonical comparison are revalidated when the experiment report is loaded.
Candidates with different measured-axis inventories remain incomparable rather
than being ranked using whichever subset happens to be available.

V1 reports aggregate full-workflow tool usage and per-probe tool choices; it
does not yet publish a per-tool progress/no-progress effectiveness matrix.

## Running

From `backend`, zero-key scripted validation is:

```powershell
python -m app.evaluation.context_tool --mode scripted --max-cases 4 --candidate-limit 1
```

Scripted output means `HARNESS_VALIDATION_ONLY`; it does not demonstrate
improved model behavior or context efficiency. Live runs require both explicit
`--allow-live` and `--allow-context-tool-experiments`, plus the exact provider
and model. Live runs are bounded by public DEV inventory, trial, work-unit,
candidate, and wall-clock policies. The CLI accepts no data-root override and
the lab never loads private holdout data. Optional report output is
content-minimized and refuses to overwrite an existing file.

The lab never applies candidates, writes production settings, edits source,
commits, pushes, opens a PR, deploys, or triggers live adversarial security
evaluation. A result can only be considered for human review. There is no
automatic description generator, combinatorial optimizer, retrieval-algorithm
optimization, attention instrumentation, production mutation, or private
holdout tuning in this version.
