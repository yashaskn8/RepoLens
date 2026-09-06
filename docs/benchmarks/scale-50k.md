# RepoLens 50K Scale Benchmark

- Commit: `e72e34960a44181f30abd7b97806e31c79c577af`
- Environment: Windows, local SQLite, one benchmark process; no external model, Ollama, Docker, or submitted repository code execution.
- Configuration: 50,000 requested source files, one symbol per file, 20% vendor ratio, fan-out 256, SCC size 32, workspace depth 8.
- Inventory: 50,017 represented files, 40,017 eligible/indexed files, 10,000 vendor files, 17 workspace files, and zero generated-classified files.

## Results

| Measurement | Result |
|---|---:|
| Fixture generation | 1.741 s |
| Changed-object discovery | 0.261 s |
| Cold index | 780.521 s |
| Cold throughput | 51.27 eligible files/s |
| Unchanged warm index | 3.114 s |
| Tiny-change interruption + resume | 11.802 s |
| Impact-frontier traversal | 2.996 s |
| Snapshot reopen | 0.047 s |
| Peak Python allocation | 19,418,367 bytes (18.52 MiB) |
| Cold database usage | 682,229,760 bytes (650.62 MiB) |
| Tiny-change database growth | 32,768 bytes |
| Retrieval p50 / p95 | 446.497 ms / 1,009.893 ms |

Cold indexing parsed all 40,017 eligible files. The unchanged pass parsed zero and reused 40,017/40,017 projections. The tiny change read 40 source bytes, parsed one file, and reused 40,016/40,017 projections. The deliberately interrupted generation stopped with `inventory_file_budget`, did not claim completion, and resumed to completion without a false-complete state.

The bounded graph view loaded 20 nodes and 33 edges in two pages with an empty remaining frontier. Stress validation observed 64/64 sampled fan-out edges and 32/32 cycle edges. Candidate selection produced one unique bug candidate and no security candidate; neither selection query exhausted its budget.

## AI economy and coverage

AI admission remained one unresolved/admitted candidate with a one-call ceiling, 1,200 planned context tokens, and 880 planned output tokens. Model execution and verification were `NOT_EXECUTED`; therefore actual model calls, tokens, and verifier attempts are unknown/null rather than zero. Revision attempts, deterministic `SKIP_AI`/`VERIFY_ONLY` counts, and MCP calls are not fields in benchmark schema version 2.

The latest smaller recorded run used different stress and content parameters, so runtime scaling is not directly comparable. Its AI envelope was nevertheless identical: one candidate, one-call ceiling, 1,200/880 planned tokens, and no model or verifier execution. AI invariance therefore passes for the fixed-candidate experiment.

Coverage is truthfully **PARTIAL**: inventory and extraction completed, while the materialized manifest was bounded/truncated, the graph view was bounded/partial, and retention reported a partial bounded maintenance page. There was no cold stop reason and no candidate-query budget exhaustion.

Benchmark result: **PASS with bounded partial views**. The principal limitation is cold deterministic SQLite projection/fact persistence at 51.27 eligible files/s; model work did not scale with repository size.

## Reproduction

```powershell
.\.venv\Scripts\python.exe -m app.benchmarks.scale --files 50000 --symbols-per-file 1 --vendor-ratio 0.20 --fanout 256 --scc-size 32 --workspace-depth 8 --output artifacts/benchmarks/scale-report-50k.json
```

Machine-readable artifact: `backend/artifacts/benchmarks/scale-report-50k.json` (local ignored artifact; not committed).
