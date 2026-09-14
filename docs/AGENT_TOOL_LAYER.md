# RepoLens Agent Tool Layer

Phase A exposes RepoLens's deterministic production facts through a small, typed, read-only Python API. It does not implement an LLM, autonomous planning, MCP transport, code editing, shell execution, or a second analyzer. Phase B owns autonomous orchestration.

## Architecture

`RepositorySnapshot` binds an authorized repository root to an already-ingested `EvidenceStore`, manifest, repository graph, and optional semantic program. `AgentToolContext` reuses those components across calls and may hold precomputed structural diffs. `AgentToolRegistry` is a closed allow-list: it validates arguments, invokes one trusted adapter, validates the tool-specific output, and returns the common envelope.

Adapters only validate, scope, invoke, normalize, bound, and package output from these production components:

- repository manifest and Tree-sitter parser;
- repository graph;
- normalized semantic program and security-flow engine;
- normalized scanner `EvidenceStore`;
- structural diff engine;
- graph-aware impact engine.

The tool contract version is `1.1.0`. Tool inputs and outputs use closed Pydantic models and JSON-compatible values so a later MCP adapter can project the schemas without changing analyzer semantics. Snapshot artifacts are detached and integrity-digested at registration; caller-declared component versions are explicitly marked `DECLARED`, not cryptographically verified.

## Tool catalog

| Tool | Use | Do not use for |
| --- | --- | --- |
| `inspect_file` | Manifest/parser facts for one file | Full file contents or behavioral inference |
| `search_symbol` | Exact, prefix, or substring symbol discovery | Fuzzy or semantic guessing |
| `inspect_symbol` | One stable symbol identity and its available graph facts | Resolving an ambiguous name |
| `find_callers` | Direct incoming production `CALLS` edges | Proving absence from a partial graph |
| `find_callees` | Direct outgoing production `CALLS` edges | Guessing dynamic/external calls |
| `trace_dataflow` | Bounded production source-to-sink paths | Creating paths missing from semantic analysis |
| `scan_security` | Query findings emitted by registered scanners | Launching tools or turning candidates into findings |
| `analyze_change` | Structural diff facts between authorized snapshots | Treating every change as a defect |
| `analyze_impact` | Directional, bounded production blast radius | Inflating impact from text matches |
| `verify_finding` | Exact claim support against repository evidence | Ground-truth or benchmark matching |

Specialist candidate builders remain internal. They produce hypotheses rather than confirmed findings, so Phase A does not silently expose them through `scan_security`.

## Common contract

Every invocation returns `tool`, `tool_version`, `status`, `deterministic`, a validated `result`, structured `evidence`, `provenance`, bounded `warnings`, and bounded `errors`. Stable statuses are:

- `SUCCESS`
- `NOT_FOUND`
- `INSUFFICIENT_EVIDENCE`
- `INVALID_INPUT`
- `UNSUPPORTED`
- `RESOURCE_LIMIT`
- `INTERNAL_ERROR`

`NOT_FOUND` means an addressed identity or fact was not found. `INSUFFICIENT_EVIDENCE` means coverage cannot prove the requested conclusion. Empty complete scanner output is not fabricated evidence, and partial output is never represented as complete.

Evidence records identify their type, production component, repository-relative source location, symbol or graph endpoints, relationship, and a stable evidence ID. Provenance identifies the repository snapshot, production components, supplied component versions, and analysis stage. Agent-visible failures never include raw stack traces or host repository roots.

## Verification claims

`verify_finding` uses four closed, discriminated claim schemas: exact `SECURITY_FINDING`, `DATAFLOW`, `CALL_RELATIONSHIP`, and `STRUCTURAL_CHANGE`. Every claim requires evidence. A claim is `SUPPORTED` only when its coordinates match a production fact and every supplied evidence reference resolves to that exact fact in the authorized snapshot context. Foreign, stale, fake, or unrelated references cannot be silently ignored. Otherwise the verdict is `UNSUPPORTED`, `INSUFFICIENT_EVIDENCE`, or `INVALID_CLAIM`. It never reads benchmark annotations or ground truth.

## Security and limits

All tools are read-only. Repository content is untrusted data and is never imported, executed, interpreted as instructions, installed, sent to a network, or passed to a shell. The registry cannot dispatch arbitrary Python names. Paths pass through RepoLens path confinement, which rejects traversal, absolute paths, drive escapes, UNC paths, sibling-prefix attacks, and symlink escapes. Source payloads are not returned by file inspection, and agent-visible strings are secret-redacted and bounded.

Context and request limits bound manifest registration, file-size/file-count admission, file and symbol result materialization, graph result materialization, flow paths/nodes/depth/aliases, scanner results, structural facts, and impact traversal. A reached computation or result limit is signalled as `RESOURCE_LIMIT`; configured clamping is visible in coverage and is never silently reported as exhaustive. Registered scanner, graph, semantic, and diff artifacts must reference manifest-authorized paths.

## Example

```python
from app.agent_tools import AgentToolContext, RepositorySnapshot, create_agent_tool_registry

snapshot = RepositorySnapshot.create(
    snapshot_id=evidence_store.manifest.commit_sha,
    repository_root=authorized_workspace,
    evidence_store=evidence_store,
    graph=repository_graph,
    chunks=production_chunks,
)
registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))

matches = registry.invoke("search_symbol", {"query": "search_products", "match_mode": "EXACT"})
symbol_id = matches.result["matches"][0]["symbol_id"]
callers = registry.invoke("find_callers", {"symbol_id": symbol_id})
```

For change and impact analysis, register both authorized snapshots and a trusted precomputed `StructuralDiffResult` bound to their snapshot IDs. The Phase-A boundary deliberately does not rescan mutable workspaces or invoke Git/subprocesses, so identical snapshot IDs cannot silently acquire different live-file results. Missing or stale diff artifacts return explicit insufficient/integrity errors.
