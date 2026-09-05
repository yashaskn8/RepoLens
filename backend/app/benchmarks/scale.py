"""Deterministic large-repository benchmark harness; no repository code executes."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import tracemalloc
from typing import Iterable

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.analysis.diff_engine import ChangeDiffEngine
from app.analysis.impact_frontier import advance_frontier
from app.graph.persistent import PersistentRepositoryGraph
from app.indexing.facts import search_postings, select_candidates
from app.indexing.persistent import IndexLimits, PersistentIndex
from app.ingestion.change_objects import changed_objects, changed_workspaces
from app.ingestion.git_inventory import GitInventory


PRESETS = {"1k": 1_000, "10k": 10_000, "100k": 100_000}


def ai_work_envelope(candidate_ids: Iterable[str], *, repository_files: int = 1) -> dict:
    """Exercise canonical admission; inventory size may not affect its AI budget."""
    from app.llm.admission import AdmissionDecision, build_admission_plan
    unique = sorted(set(candidate_ids))[:64]
    state = {"source_evidence_available": True, "manifest_summary": {"total_files": repository_files},
             "deterministic_correctness_candidates": [{"candidate_id": value} for value in unique]}
    plan = build_admission_plan(state, "bug")
    admitted = min(3, len(unique))
    calls = int(plan.decision == AdmissionDecision.CLOUD_REQUIRED and admitted > 0)
    return {"unresolved_candidates": len(unique), "admitted_candidates": admitted,
            "decision": plan.decision.value, "planned_call_upper_bound": calls,
            "planned_output_token_upper_bound": plan.max_output_tokens,
            "planned_context_token_upper_bound": admitted * 1_200 if calls else 0}


def assert_inventory_independent_ai_work(repository_a_files: int, repository_b_files: int,
                                         candidate_ids: Iterable[str]) -> dict:
    if repository_a_files <= 0 or repository_b_files <= repository_a_files:
        raise ValueError("repository B must be larger than repository A")
    first = ai_work_envelope(candidate_ids, repository_files=repository_a_files)
    second = ai_work_envelope(candidate_ids, repository_files=repository_b_files)
    if first != second:
        raise AssertionError("AI work scaled with unrelated inventory")
    return {"repository_a_files": repository_a_files, "repository_b_files": repository_b_files,
            "same_candidate_set": True, "envelope": first}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    return result.stdout.strip()


def _write_fast_import(repo: Path, message: str, entries: Iterable[tuple[str, bytes]], *, parent: str | None = None) -> None:
    process = subprocess.Popen(["git", "-C", str(repo), "fast-import", "--quiet"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert process.stdin is not None
    header = [b"commit refs/heads/main\n", b"author RepoLens Benchmark <benchmark@invalid> 0 +0000\n",
              b"committer RepoLens Benchmark <benchmark@invalid> 0 +0000\n"]
    encoded_message = message.encode()
    header.append(f"data {len(encoded_message)}\n".encode() + encoded_message + b"\n")
    if parent:
        header.append(f"from {parent}\n".encode())
    for item in header:
        process.stdin.write(item)
    for path, content in entries:
        process.stdin.write(f"M 100644 inline {path}\ndata {len(content)}\n".encode())
        process.stdin.write(content)
        process.stdin.write(b"\n")
    process.stdin.write(b"done\n")
    process.stdin.close()
    error = process.stderr.read() if process.stderr else b""
    if process.wait(timeout=300) != 0:
        raise RuntimeError("git fast-import failed: " + error.decode(errors="replace")[:1000])


def generate_passive_repository(repo: Path, file_count: int, *, symbols_per_file: int = 1,
                                vendor_ratio: float = 0.0, fanout: int = 0,
                                scc_size: int = 0, workspace_depth: int = 0) -> tuple[str, str]:
    """Create controlled Git objects directly; no generated source is imported or run."""
    if file_count <= 0 or file_count > 2_000_000:
        raise ValueError("file_count must be between 1 and 2,000,000")
    if symbols_per_file <= 0 or symbols_per_file > 32:
        raise ValueError("symbols_per_file must be between 1 and 32")
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--bare", "--quiet", str(repo)], check=True, timeout=30)

    def entries():
        yield "src/p0000/hot.py", b"import time\nasync def unresolved_candidate(value):\n    time.sleep(1)\n    return value\n"
        yield "src/core.py", b"def shared(value):\n    return value\n"
        emitted = 2
        for index in range(max(0, file_count - emitted)):
            vendor = vendor_ratio > 0 and index < int(file_count * min(vendor_ratio, 0.9))
            prefix = "vendor" if vendor else "src"
            bucket = index // 1000 + 1
            path = f"{prefix}/p{bucket:04d}/module_{index:07d}.py"
            imports = "from src.core import shared\n" if index < fanout else ""
            if index < scc_size:
                target = (index + 1) % max(1, scc_size)
                imports += f"from src.p{target // 1000 + 1:04d}.module_{target:07d} import duplicate\n"
            body = imports + "\n".join(
                f"def {'duplicate' if symbol == 0 else f'symbol_{symbol}'}(value):\n    return value"
                for symbol in range(symbols_per_file)) + "\n"
            yield path, body.encode()
        if workspace_depth:
            root = ""
            patterns = []
            for depth in range(min(workspace_depth, 16)):
                root = f"{root}packages/level{depth}/"
                patterns.append(root.rstrip("/"))
                yield root + "package.json", json.dumps({"name": f"@bench/level{depth}",
                    "exports": {".": "./index.ts"}}).encode()
                yield root + "index.ts", f"export const level = {depth};\n".encode()
            yield "package.json", json.dumps({"private": True, "workspaces": patterns}).encode()

    _write_fast_import(repo, "base", entries())
    base = _git(repo, "rev-parse", "refs/heads/main")
    changed = b"import time\nasync def unresolved_candidate(value):\n    time.sleep(2)\n    return value\n"
    _write_fast_import(repo, "tiny change", [("src/p0000/hot.py", changed)], parent=base)
    return base, _git(repo, "rev-parse", "refs/heads/main")


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * percentile))]


@contextmanager
def _clock(metrics: dict, key: str):
    started = time.perf_counter()
    yield
    metrics[key] = round(time.perf_counter() - started, 6)


def run_scale_benchmark(*, file_count: int, symbols_per_file: int = 1,
                        vendor_ratio: float = 0.0, fanout: int = 0,
                        scc_size: int = 0, workspace_depth: int = 0,
                        keep_directory: str | None = None) -> dict:
    """Run local deterministic paths and report live-model work as not executed."""
    holder = tempfile.TemporaryDirectory(prefix="repolens-scale-") if keep_directory is None else None
    root = Path(holder.name if holder else keep_directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    repo, database = root / "fixture.git", root / "benchmark.db"
    metrics: dict = {"schema_version": 1, "requested_files": file_count,
        "profile": {"symbols_per_file": symbols_per_file, "vendor_ratio": vendor_ratio,
                    "fanout": fanout, "scc_size": scc_size, "workspace_depth": workspace_depth}}
    tracemalloc.start()
    try:
        with _clock(metrics, "fixture_generation_seconds"):
            base, head = generate_passive_repository(repo, file_count, symbols_per_file=symbols_per_file,
                vendor_ratio=vendor_ratio, fanout=fanout, scc_size=scc_size, workspace_depth=workspace_depth)
        inventory = GitInventory(str(repo))
        with _clock(metrics, "discovery_seconds"):
            changes, discovery = changed_objects(inventory, inventory, base, head,
                max_files=512, max_entries=max(20_000, min(file_count + 1024, 250_000)), seconds=120)
        metrics["discovery"] = {**discovery, "materialized_change_records": len(changes)}
        engine = create_engine("sqlite:///" + database.as_posix())
        from app.models import Base
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine)()
        limits = IndexLimits(max_files=file_count + workspace_depth * 2 + 32,
            max_source_bytes=max(52_428_800, file_count * symbols_per_file * 256),
            max_seconds=900, manifest_files=min(file_count + 32, 2048),
            max_database_bytes=max(2_147_483_648, file_count * symbols_per_file * 32_768))
        cold = PersistentIndex(session, tenant_id="benchmark", repository_url="benchmark://fixture",
                               repo_dir=str(repo), commit_sha=base, limits=limits)
        with _clock(metrics, "cold_index_seconds"):
            cold.build_manifest()
        metrics["cold_index"] = dict(cold.stats)
        before_size = database.stat().st_size
        warm = PersistentIndex(session, tenant_id="benchmark", repository_url="benchmark://fixture",
                               repo_dir=str(repo), commit_sha=head, limits=limits)
        with _clock(metrics, "warm_index_seconds"):
            warm.build_manifest()
        metrics["warm_index"] = dict(warm.stats)
        resumed = PersistentIndex(session, tenant_id="benchmark", repository_url="benchmark://fixture",
                                  repo_dir=str(repo), commit_sha=head, limits=limits)
        with _clock(metrics, "resume_time_seconds"):
            resumed.open_snapshot(warm.snapshot_id)
        metrics["resume_status"] = "EXECUTED"
        metrics["persistent_storage_growth_bytes"] = max(0, database.stat().st_size - before_size)
        latencies = []
        for query in ("unresolved candidate", "shared value", "duplicate") * 7:
            started = time.perf_counter()
            search_postings(warm, query, limit=8, examined_limit=128)
            latencies.append((time.perf_counter() - started) * 1000)
        metrics["retrieval_ms"] = {"p50": round(statistics.median(latencies), 4),
                                   "p95": round(_percentile(latencies, 0.95), 4), "samples": len(latencies)}
        with changed_workspaces(str(repo), str(repo), base, head, max_files=512,
                                max_file_bytes=1_048_576, max_bytes=8_388_608) as (left, right, coverage):
            diff = ChangeDiffEngine().compute_structural_diff(left, right, base, head, "benchmark://fixture")
            diff.discovery_coverage = coverage
        graph = PersistentRepositoryGraph(warm)
        frontier = None
        with _clock(metrics, "impact_frontier_seconds"):
            for _ in range(16):
                frontier = advance_frontier(graph, diff, frontier)
                if not frontier["queue"] or frontier["stopped"]:
                    break
        metrics["graph"] = {"edges_loaded": len(frontier["edges"]), "nodes_loaded": len(frontier["nodes"]),
                            "frontier_pages": frontier["pages"], "frontier_remaining": len(frontier["queue"]),
                            "partial": frontier["partial"]}
        bug = select_candidates(warm, "bug")
        bug_coverage = dict(warm.query_coverage)
        security = select_candidates(warm, "security")
        security_coverage = dict(warm.query_coverage)
        ids = [candidate.candidate_id for candidate in bug + security]
        metrics["candidate_counts"] = {"scope": "BOUNDED_SELECTED", "bug": len(bug),
            "security": len(security), "unique": len(set(ids)),
            "bug_coverage": bug_coverage, "security_coverage": security_coverage}
        metrics["ai"] = {"status": "NOT_EXECUTED", "model_calls": None, "tokens": None,
                         "verifier_attempts": None, **ai_work_envelope(ids)}
        metrics["scale_invariant"] = assert_inventory_independent_ai_work(100_000, max(100_001, file_count * 2), ids)
        _, peak = tracemalloc.get_traced_memory()
        metrics["peak_python_allocation_bytes"] = peak
        session.close()
        engine.dispose()
        return metrics
    finally:
        tracemalloc.stop()
        if holder is not None:
            holder.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="RepoLens passive extreme-scale benchmark")
    parser.add_argument("--preset", choices=sorted(PRESETS))
    parser.add_argument("--files", type=int)
    parser.add_argument("--symbols-per-file", type=int, default=1)
    parser.add_argument("--vendor-ratio", type=float, default=0.0)
    parser.add_argument("--fanout", type=int, default=0)
    parser.add_argument("--scc-size", type=int, default=0)
    parser.add_argument("--workspace-depth", type=int, default=0)
    parser.add_argument("--keep-directory")
    parser.add_argument("--output")
    args = parser.parse_args()
    count = args.files or PRESETS.get(args.preset or "1k", 1_000)
    result = run_scale_benchmark(file_count=count, symbols_per_file=args.symbols_per_file,
        vendor_ratio=args.vendor_ratio, fanout=args.fanout, scc_size=args.scc_size,
        workspace_depth=args.workspace_depth, keep_directory=args.keep_directory)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
