"""Production-integrated benchmark runner executing RepoLens deterministic pipelines."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4
from pydantic import BaseModel, Field

from app.analysis.core import analyze_core_repository
from app.analysis.diff_engine import ChangeDiffEngine
from app.analysis.impact_engine import ChangeImpactEngine
from app.evaluation.ground_truth.catalog import CapabilityCatalog, load_capability_catalog
from app.evaluation.ground_truth.leakage import (
    LeakageDetector,
    cleanup_sandbox,
    create_neutral_sandbox,
)
from app.evaluation.ground_truth.loader import (
    compute_canonical_benchmark_hash,
    filter_by_split,
    load_benchmark_dataset,
)
from app.evaluation.ground_truth.matcher import (
    CaseEvaluationResult,
    EvaluatedFinding,
    IndependentBenchmarkJudge,
)
from app.evaluation.ground_truth.metrics import (
    BenchmarkAggregateMetrics,
    aggregate_case_metrics,
)
from app.evaluation.ground_truth.schemas import (
    BenchmarkCase,
    BenchmarkSplit,
    EvaluationStage,
    ExecutionStatus,
    TargetPipeline,
)
from app.graph.builder import build_repository_graph
from app.indexing.chunker import chunk_manifest
from app.ingestion.manifest import build_manifest
from app.semantics.builder import build_semantic_program
from app.semantics.flow import analyze_security_flows
from app.specialist_candidates import (
    build_bug_candidates,
    build_security_flow_candidates,
)


def _get_git_commit_sha() -> str:
    """Retrieve the current local git commit SHA or UNKNOWN."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "UNKNOWN_COMMIT"


class BenchmarkRunReport(BaseModel):
    """Complete machine-readable artifact of a benchmark evaluation run."""

    benchmark_version: str = "1.0.0"
    dataset_version: str = "1.0.0"
    canonical_dataset_hash: str
    git_commit_sha: str
    python_version: str
    platform: str
    timestamp: str
    duration_seconds: float
    mode: str = "DETERMINISTIC_ONLY"
    live_model_provider: str = "MODEL_NOT_EXECUTED"

    # Execution status gating
    execution_status: ExecutionStatus
    total_cases: int
    eligible_cases: int
    executed_cases: int
    skipped_cases: int = 0
    failed_cases: int = 0
    completion_fraction: float

    # Metrics
    aggregate_metrics: BenchmarkAggregateMetrics
    per_case_results: List[CaseEvaluationResult]


class BenchmarkRunner:
    """Orchestrates sandboxed evaluation of RepoLens on benchmark cases."""

    def __init__(
        self,
        catalog: Optional[CapabilityCatalog] = None,
        judge: Optional[IndependentBenchmarkJudge] = None,
    ) -> None:
        self.catalog = catalog or load_capability_catalog()
        self.judge = judge or IndependentBenchmarkJudge(catalog=self.catalog)

    def _execute_repository_scan_case(
        self,
        case: BenchmarkCase,
    ) -> List[EvaluatedFinding]:
        """Execute real production repository ingestion and analysis in a neutral sandbox."""
        files = case.fixture.files
        if not files:
            return []

        sandbox_dir = create_neutral_sandbox(files)
        try:
            # 1. Manifest
            manifest = build_manifest(
                sandbox_dir,
                repository_url="local://benchmark",
                commit_hash="0000000000000000000000000000000000000000",
            )

            emitted: List[EvaluatedFinding] = []

            # 2. If stage is STATIC_FINDING, run core static analyzers
            if case.evaluation_stage == EvaluationStage.STATIC_FINDING:
                scan_res = analyze_core_repository(sandbox_dir, manifest)
                for f in scan_res.findings:
                    rule_id = "CLIENT_CONTROLLED_AUTH_HEADER" if "client-controlled" in f.rule_id else (
                        "HARDCODED_CREDENTIAL" if "hardcoded" in f.rule_id else f.rule_id
                    )
                    emitted.append(
                        EvaluatedFinding(
                            rule_id=rule_id,
                            file_path=f.evidence.file_path,
                            start_line=f.evidence.start_line,
                            end_line=f.evidence.end_line,
                            stage=EvaluationStage.STATIC_FINDING,
                            raw_title=f.title,
                            raw_details=f.raw_details or {},
                        )
                    )

            # 3. If stage is ANALYSIS_CANDIDATE, run semantic flow & bug candidate analyzers
            elif case.evaluation_stage == EvaluationStage.ANALYSIS_CANDIDATE:
                chunks = chunk_manifest(manifest, files)
                program = build_semantic_program(manifest, chunks)

                # Security interprocedural flows
                flows = analyze_security_flows(program)
                for flow in flows:
                    sink_kind = getattr(flow.sink, "kind", "")
                    if sink_kind == "INPUT_TO_DATABASE":
                        rule_id = "INTERPROCEDURAL_FLOW_SQLI"
                    elif sink_kind == "INPUT_TO_COMMAND":
                        rule_id = "INTERPROCEDURAL_FLOW_CMDI"
                    elif sink_kind == "INPUT_TO_FILESYSTEM":
                        rule_id = "INTERPROCEDURAL_FLOW_PATH_TRAVERSAL"
                    else:
                        rule_id = f"FLOW_{sink_kind}"

                    emitted.append(
                        EvaluatedFinding(
                            rule_id=rule_id,
                            file_path=flow.source.file_path or (flow.sink.file_path if flow.sink else ""),
                            symbol=getattr(flow.source, "symbol", None),
                            start_line=getattr(flow.source, "start_line", None) or getattr(flow.sink, "start_line", None),
                            end_line=getattr(flow.sink, "end_line", None),
                            stage=EvaluationStage.ANALYSIS_CANDIDATE,
                            structural_facts={
                                "sink_kind": sink_kind,
                                "flow_required": True,
                            },
                        )
                    )

                # Bug candidates
                bug_candidates = build_bug_candidates(chunks, manifest=manifest, semantic_program=program)
                for cand in bug_candidates:
                    if cand.candidate_kind == "BROAD_EXCEPTION_SWALLOW":
                        rule_id = "BROAD_EXCEPTION_SWALLOW"
                    elif cand.candidate_kind in ("BLOCKING_CALL_IN_ASYNC", "ASYNC_BLOCKING_CALL"):
                        rule_id = "BLOCKING_API_IN_ASYNC"
                    elif cand.candidate_kind == "UNAWAITED_ASYNC_CALL":
                        rule_id = "UNAWAITED_ASYNC_CALL"
                    else:
                        rule_id = cand.candidate_kind

                    # Resolve file from evidence refs
                    file_path = ""
                    start_line = None
                    if cand.metadata and "source_line" in cand.metadata:
                        start_line = cand.metadata["source_line"]
                    if cand.evidence_refs:
                        first_ref = cand.evidence_refs[0]
                        if first_ref.startswith("file:"):
                            file_path = first_ref.replace("file:", "")
                        elif first_ref.startswith("symbol:"):
                            parts = first_ref.split(":")
                            if len(parts) >= 2:
                                file_path = parts[1]
                            if len(parts) >= 5 and parts[4].isdigit() and start_line is None:
                                start_line = int(parts[4])
                        elif first_ref.startswith("chunk:"):
                            # Find chunk
                            c_id = first_ref.replace("chunk:", "")
                            for ch in chunks:
                                if ch.chunk_id == c_id:
                                    file_path = ch.file_path
                                    if start_line is None:
                                        start_line = ch.start_line
                                    break

                    emitted.append(
                        EvaluatedFinding(
                            rule_id=rule_id,
                            file_path=file_path,
                            symbol=cand.related_symbol,
                            start_line=start_line,
                            stage=EvaluationStage.ANALYSIS_CANDIDATE,
                            raw_details={"reason": cand.deterministic_reason},
                        )
                    )

            return emitted

        finally:
            cleanup_sandbox(sandbox_dir)

    def _execute_change_analysis_case(
        self,
        case: BenchmarkCase,
    ) -> List[EvaluatedFinding]:
        """Execute real production change analysis (diff and impact engines) in sandboxes."""
        base_files = case.fixture.base_files or {}
        head_files = case.fixture.head_files or {}

        base_sandbox = create_neutral_sandbox(base_files)
        head_sandbox = create_neutral_sandbox(head_files)
        try:
            diff_engine = ChangeDiffEngine()
            diff_result = diff_engine.compute_structural_diff(
                base_sandbox,
                head_sandbox,
                base_commit_sha="base000000000000000000000000000000000000",
                head_commit_sha="head000000000000000000000000000000000000",
                repository_url="local://benchmark",
            )

            emitted: List[EvaluatedFinding] = []

            # 1. If stage is CHANGE_FACT, inspect route and schema deltas
            if case.evaluation_stage == EvaluationStage.CHANGE_FACT:
                for r_delta in diff_result.route_deltas:
                    if r_delta.change_type == "METHOD_CHANGED":
                        r_id = "HTTP_METHOD_MISMATCH"
                    elif r_delta.change_type == "PATH_CHANGED":
                        r_id = "ROUTE_PATH_MISMATCH"
                    elif r_delta.change_type == "METHOD_AND_PATH_CHANGED":
                        r_id = "ROUTE_METHOD_AND_PATH_CHANGED"
                    else:
                        r_id = f"ROUTE_{r_delta.change_type}"

                    emitted.append(
                        EvaluatedFinding(
                            rule_id=r_id,
                            file_path=r_delta.file_path,
                            stage=EvaluationStage.CHANGE_FACT,
                            structural_facts={"change_type": r_delta.change_type},
                            raw_title=f"Route {r_delta.head_path or r_delta.base_path or r_delta.route_name} delta {r_delta.change_type}",
                        )
                    )

                for s_delta in diff_result.schema_deltas:
                    if s_delta.change_type == "ADDED_FIELD":
                        s_id = "SCHEMA_FIELD_ADDED"
                    elif s_delta.change_type == "MODIFIED_TYPE":
                        s_id = "SCHEMA_FIELD_TYPE_CHANGED"
                    else:
                        s_id = f"SCHEMA_{s_delta.change_type}"

                    emitted.append(
                        EvaluatedFinding(
                            rule_id=s_id,
                            file_path=s_delta.file_path,
                            symbol=s_delta.model_name,
                            stage=EvaluationStage.CHANGE_FACT,
                            structural_facts={"change_type": s_delta.change_type},
                            raw_title=f"Schema {s_delta.model_name} delta {s_delta.change_type}",
                        )
                    )

            # 2. If stage is IMPACT_FACT, compute blast radius
            elif case.evaluation_stage == EvaluationStage.IMPACT_FACT:
                base_manifest = build_manifest(
                    base_sandbox,
                    repository_url="local://benchmark",
                    commit_hash="base000000000000000000000000000000000000",
                )
                head_manifest = build_manifest(
                    head_sandbox,
                    repository_url="local://benchmark",
                    commit_hash="head000000000000000000000000000000000000",
                )
                base_graph = build_repository_graph(base_manifest)
                head_graph = build_repository_graph(head_manifest)

                impact_engine = ChangeImpactEngine()
                blast_radius = impact_engine.compute_blast_radius(
                    analysis_id=uuid4(),
                    diff_result=diff_result,
                    base_graph=base_graph,
                    head_graph=head_graph,
                )

                for impact in blast_radius.impacts:
                    impact_type_str = getattr(impact.impact_type, "value", str(impact.impact_type))
                    payload = impact.evidence_payload or {}
                    title_lower = (impact.title or "").lower()
                    if payload.get("change_type") == "DELETED" or "deleted symbol" in title_lower:
                        rule_id = "DELETED_SYMBOL_WITH_CALLERS"
                        semantic_type = "CALLER_BROKEN_BY_DELETION"
                    elif "signature_diff" in payload or "signature change" in title_lower:
                        rule_id = "SIGNATURE_BREAK_CALLERS"
                        semantic_type = "SIGNATURE_MISMATCH"
                    elif len(blast_radius.impacts) >= 2:
                        rule_id = "BLAST_RADIUS_MULTI_CONSUMER"
                        semantic_type = impact_type_str
                    elif len(blast_radius.impacts) == 1:
                        rule_id = "BLAST_RADIUS_DIRECT_CALLER"
                        semantic_type = impact_type_str
                    else:
                        rule_id = impact_type_str
                        semantic_type = impact_type_str

                    emitted.append(
                        EvaluatedFinding(
                            rule_id=rule_id,
                            file_path=impact.affected_file or impact.source_file or "",
                            symbol=impact.affected_symbol or impact.source_symbol,
                            stage=EvaluationStage.IMPACT_FACT,
                            structural_facts={"impact_type": semantic_type, "raw_impact_type": impact_type_str},
                            raw_title=f"Impact on {impact.affected_symbol} in {impact.affected_file}",
                        )
                    )

            return emitted

        finally:
            cleanup_sandbox(base_sandbox)
            cleanup_sandbox(head_sandbox)

    def execute_case(self, case: BenchmarkCase) -> CaseEvaluationResult:
        """Run production RepoLens analysis on a single benchmark case and evaluate results."""
        # Enforce pre-flight leakage check
        LeakageDetector.check_case(case)

        # Collect manifest files and line bounds for reference validity
        manifest_files: Set[str] = set()
        file_line_counts: Dict[str, int] = {}
        target_dict = case.fixture.files if case.fixture.files else (case.fixture.head_files or {})
        for path, content in target_dict.items():
            norm_p = path.replace("\\", "/").strip().lstrip("/").lower()
            manifest_files.add(norm_p)
            file_line_counts[norm_p] = len(content.splitlines())

        try:
            if case.target_pipeline == TargetPipeline.REPOSITORY_SCAN:
                emitted = self._execute_repository_scan_case(case)
            elif case.target_pipeline == TargetPipeline.CHANGE_ANALYSIS:
                emitted = self._execute_change_analysis_case(case)
            else:
                raise ValueError(f"Unknown target pipeline: {case.target_pipeline}")

            return self.judge.evaluate_case(
                case=case,
                emitted_findings=emitted,
                manifest_files=manifest_files,
                file_line_counts=file_line_counts,
                explicit_abstention=False,
            )

        except Exception as exc:
            return self.judge.evaluate_case(
                case=case,
                emitted_findings=[],
                manifest_files=manifest_files,
                file_line_counts=file_line_counts,
                pipeline_error=str(exc),
            )

    def run_benchmark(
        self,
        cases: Optional[List[BenchmarkCase]] = None,
        split: Optional[BenchmarkSplit] = None,
        cases_dir: Optional[str] = None,
    ) -> BenchmarkRunReport:
        """Execute complete benchmark suite and return full auditable report."""
        start_time = time.perf_counter()
        loaded_cases = cases or load_benchmark_dataset(cases_dir=cases_dir, catalog=self.catalog)

        eligible_cases = loaded_cases if split is None else filter_by_split(loaded_cases, split)
        dataset_hash = compute_canonical_benchmark_hash(loaded_cases)

        results: List[CaseEvaluationResult] = []
        failed_cases = 0

        for case in eligible_cases:
            res = self.execute_case(case)
            if any("Pipeline error:" in r for r in res.mismatch_reasons):
                failed_cases += 1
            results.append(res)

        elapsed = round(time.perf_counter() - start_time, 2)
        total_count = len(loaded_cases)
        eligible_count = len(eligible_cases)
        executed_count = len(results)

        completion_fraction = round(float(executed_count) / float(eligible_count), 4) if eligible_count > 0 else 0.0
        status = ExecutionStatus.COMPLETED if executed_count == eligible_count and failed_cases == 0 else (
            ExecutionStatus.FAILED if failed_cases > 0 else ExecutionStatus.PARTIAL_RUN
        )

        agg_metrics = aggregate_case_metrics(results, run_bootstrap=True)

        return BenchmarkRunReport(
            benchmark_version="1.0.0",
            dataset_version="1.0.0",
            canonical_dataset_hash=dataset_hash,
            git_commit_sha=_get_git_commit_sha(),
            python_version=platform.python_version(),
            platform=f"{platform.system()} {platform.release()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=elapsed,
            execution_status=status,
            total_cases=total_count,
            eligible_cases=eligible_count,
            executed_cases=executed_count,
            failed_cases=failed_cases,
            completion_fraction=completion_fraction,
            aggregate_metrics=agg_metrics,
            per_case_results=results,
        )
