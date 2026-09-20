# Evidence Investigator

RepoLens optionally augments a genuine verifier `POSSIBLE` result with bounded, model-directed evidence gathering. Enable it with `AGENT_INVESTIGATOR_ENABLED=true`. The default remains `false`, which preserves the existing deterministic MCP enrichment path.

## Control flow

```text
specialists -> verifier -> POSSIBLE
                         -> investigator_prepare
                         -> investigator_decide
                              | TOOL_CALL
                              v
                            investigator_tool -> investigator_compact --+
                              ^                                      |
                              +--------------------------------------+
                              | FINISH / ABSTAIN / local bound
                              v
                            investigator_complete -> revision -> verifier
```

Each decision, tool execution, compaction, and completion is a separate LangGraph node. Checkpoints therefore preserve completed work, the remaining budgets, the evidence ledger, and the next node without serializing live routers, registries, or repository runtime objects.

## Authority boundary

The model returns one closed `InvestigatorDecision` JSON object: `TOOL_CALL`, `FINISH`, or `ABSTAIN`. It chooses only the next evidence question. Application policy selects the category-appropriate read-only tools, validates the action and arguments, enforces budgets and loop detection, and invokes the canonical `AgentToolRegistry`. The investigator cannot publish, modify a repository, call a shell, execute repository code, use arbitrary network access, or approve a finding. The existing independent verifier remains the acceptance authority.

The implementation uses the canonical provider-neutral `LLMRouter`, task policies, prompt lineage (`evidence-investigator/1.0`), workflow AI budget, execution metadata, and structured output validation. Investigator decisions disable response caching because each decision depends on the active snapshot, finding, evidence ledger, and step state. If no configured model is available, the uncertain path fails closed; deterministic analysis remains available and the feature is disabled by default.

## Context engineering

Each model decision receives only immutable safety instructions, the active finding, the verifier's specific evidence gap, structured working memory, a bounded evidence ledger, at most two recent normalized observations, category-selected compact input schemas, and remaining budgets. Source and tool text is enclosed as untrusted repository data.

Raw tool envelopes are redacted, bounded, normalized, digested, and compacted deterministically. Older payloads leave the prompt while stable evidence IDs, symbol IDs, locations, negative results, coverage limitations, unresolved questions, and contradictions remain. Model explanations never become deterministic facts. Context packing uses a centralized conservative byte-to-token estimate and evicts older low-priority material before any authority, target, tool, or stop-condition section.

## Bounds and supported tools

V1 hard ceilings are four sequential targets per workflow, six decisions per target, five tool executions per target, one execution per model response, two detailed recent observations, and explicit model/tool timeouts. Duplicate requests and evidence-free short cycles terminate as `STUCK`.

Bug, architecture, and integration investigations may use `inspect_file`, `search_symbol`, `inspect_symbol`, `find_callers`, `find_callees`, and `read_source_slice`. Security investigations may additionally use `trace_dataflow` and `scan_security`. Change, write, shell, execution, network, and GitHub-delivery capabilities are not exposed.

`read_source_slice` reads only a manifest-authorized UTF-8 file from the exact captured snapshot. It rejects traversal, absolute/drive/UNC paths, symlink or junction escapes, binary/skipped files, snapshot drift, excessive line spans, and excessive output. Returned text is secret-redacted, byte-bounded, and content-digested; source is never executed or imported.

## Telemetry and state

Checkpointed trajectory entries record the finding and step through their containing state, action, tool name, argument/result digests, evidence references, provider/model metadata, prompt and tool versions, duration, status, remaining budgets, stop reason, and content-free context metrics. Full source is not written to general event logs. Live registry/router/database objects are transient runtime dependencies and are never part of `AnalysisState`.
