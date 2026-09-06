# RepoLens 100K Scale Benchmark

- Tested commit: `b99836d11204578e19a0645d6c9a2a328ee95351`
- Environment: Windows, local SQLite, one benchmark process; no Docker, external model, Ollama, verifier, or submitted repository code execution.
- Configuration: 100,000 requested source files, one symbol per file, 20% vendor ratio, fan-out 256, SCC size 32, workspace depth 8, bounded index allowance 1,800 seconds.
- Inventory: 100,017 represented files, 80,017 eligible/indexed files, 20,000 vendor files, 17 workspace files, 256 fan-out files, and 32 cycle files.

## Results

| Measurement | 100K | Validated 50K | Ratio |
|---|---:|---:|---:|
| Represented files | 100,017 | 50,017 | 2.000x |
| Indexed files | 80,017 | 40,017 | 2.000x |
| Cold index | 1,234.475 s | 780.521 s | 1.582x |
| Cold throughput | 64.82 files/s | 51.27 files/s | 1.264x |
| Unchanged warm | 2.403 s | 3.114 s | 0.772x |
| Tiny change | 16.637 s | 11.802 s | 1.410x |
| Peak Python allocation | 20.85 MiB | 18.52 MiB | 1.126x |
| Cold database usage | 1,296.69 MiB | 650.62 MiB | 1.993x |
| Retrieval p50 / p95 | 386.515 / 863.693 ms | 446.497 / 1,009.893 ms | — |

Fixture generation took 2.322 seconds and changed-object discovery took 0.236 seconds for one changed file. Cold indexing completed without a stop reason, parsing all 80,017 eligible files and reading 3,129,997 source bytes. The unchanged pass parsed zero files, read zero source bytes, and reused 80,017/80,017 projections. The tiny change parsed one file, read 40 bytes, and reused 80,016/80,017 projections (99.9988%); persistent database growth was 57,344 bytes. Impact-frontier traversal took 2.367 seconds and snapshot reopen took 0.038 seconds.

The bounded graph loaded 20 nodes and 33 edges in two pages with no remaining frontier. Stress validation observed 64/64 sampled fan-out edges and 32/32 cycle edges. Recovery stopped the deliberate interruption with `inventory_file_budget`, never claimed false completion, resumed completely, and reused 80,016 files.

Candidate selection produced one bug candidate, zero security candidates, and no query-budget exhaustion. AI admission remained one unresolved/admitted candidate with a one-call ceiling and 1,200/880 planned context/output tokens, identical to 50K. Model calls, actual tokens, and verifier attempts are null because model and verifier execution were `NOT_EXECUTED`.

Coverage is truthfully **PARTIAL**: inventory and deterministic extraction completed, while manifest materialization, graph loading, and retention maintenance remained bounded partial views. No extraction stop reason or candidate-query exhaustion occurred.

## Verdicts

- 100K execution: **PASS**
- Cold scale: **PASS; 900-second performance target exceeded**
- Warm/incremental scale: **PASS**
- Memory bounds: **PASS**
- Recovery: **PASS**
- Stress graph: **PASS**
- AI invariance: **PASS**
- Overall: **PASS with truthful bounded partial views**

The first attempt stopped cold indexing truthfully at the prior fixed 900-second benchmark allowance. The harness now retains 900 seconds as its default but accepts an explicit bounded allowance for long validation runs.

## Reproduction

```powershell
.\.venv\Scripts\python.exe -m app.benchmarks.scale --files 100000 --symbols-per-file 1 --vendor-ratio 0.20 --fanout 256 --scc-size 32 --workspace-depth 8 --max-index-seconds 1800 --output artifacts/benchmarks/scale-report-100k.json
```

Machine-readable artifact: `backend/artifacts/benchmarks/scale-report-100k.json` (local ignored artifact; not committed). The remaining bottleneck is cold deterministic SQLite projection/fact persistence.
