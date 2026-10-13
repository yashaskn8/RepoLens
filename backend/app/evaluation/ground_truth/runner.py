"""Production-integrated benchmark runner executing RepoLens deterministic pipelines."""

from __future__ import annotations

import json
import hashlib
import os
import platform
import subprocess
import sys
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4
from pydantic import BaseModel, Field, model_validator

from app.analysis.core import analyze_core_repository
from app.analysis.diff_engine import ChangeDiffEngine
from app.analysis.impact_engine import ChangeImpactEngine
from app.evaluation.ground_truth.authority import (
    BENCHMARK_CASES_DIR,
    BENCHMARK_MANIFEST_PATH,
    REPO_ROOT,
    TRUSTED_BENCHMARK_BOOTSTRAP_ITERATIONS,
    TRUSTED_BENCHMARK_BOOTSTRAP_SEED,
    TRUSTED_BENCHMARK_CASE_COUNT,
    TRUSTED_BENCHMARK_CONTRACT_ID,
    TRUSTED_BENCHMARK_DATASET_VERSION,
    TRUSTED_BENCHMARK_DATASET_SHA256,
    TRUSTED_BENCHMARK_MATCHER_VERSION,
    TRUSTED_BENCHMARK_METRICS_VERSION,
    TRUSTED_BENCHMARK_VERSION,
    TRUSTED_OFFICIAL_CASE_INVENTORIES,
)
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
from app.evaluation.ground_truth.holdout_governance import HoldoutAuthorizationContract
from app.evaluation.ground_truth.schemas import (
    BenchmarkCase,
    BenchmarkContract,
    BenchmarkSplit,
    EvaluationStage,
    ExecutionScope,
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

# Neutral repository URL and commit hashes for sandbox analysis.
# These must not contain benchmark-specific markers to avoid environment leakage.
_NEUTRAL_REPO_URL = "https://github.com/workspace/repo"
_NEUTRAL_NULL_COMMIT = "0000000000000000000000000000000000000000"
_NEUTRAL_BASE_COMMIT = "base000000000000000000000000000000000000"
_NEUTRAL_HEAD_COMMIT = "head000000000000000000000000000000000000"

# An official report is an execution result, not a label that may be restored
# from caller-controlled JSON. Only the verified runner sets this process-local
# mint while constructing its report. It is deliberately not serialized.
_OFFICIAL_REPORT_MINT = object()
_official_report_mint: ContextVar[object | None] = ContextVar(
    "repolens_official_benchmark_report_mint",
    default=None,
)


def _get_git_commit_sha() -> str:
    """Retrieve the current local git commit SHA or UNKNOWN."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=_git_identity_environment(),
        )
        candidate = res.stdout.strip()
        if res.returncode == 0 and _is_commit_sha(candidate):
            return candidate
    except Exception:
        pass
    return "UNKNOWN_COMMIT"


def _git_identity_environment() -> dict[str, str]:
    """Avoid caller-injected Git directory/index/config overrides for identity checks."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _is_commit_sha(value: str) -> bool:
    return len(value) in {40, 64} and all(character in "0123456789abcdef" for character in value)


def _repository_tree_is_clean() -> bool:
    """Fail closed unless HEAD exactly describes the current tracked/untracked source tree."""
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=_git_identity_environment(),
        )
    except Exception:
        return False
    return result.returncode == 0 and not result.stdout.strip()


class BenchmarkRunReport(BaseModel):
    """Complete machine-readable artifact of a benchmark evaluation run."""

    benchmark_version: str = TRUSTED_BENCHMARK_VERSION
    dataset_version: str = TRUSTED_BENCHMARK_DATASET_VERSION
    canonical_dataset_hash: str
    git_commit_sha: str
    python_version: str
    platform: str
    timestamp: str
    duration_seconds: float
    mode: str = "DETERMINISTIC_ONLY"
    live_model_provider: str = "MODEL_NOT_EXECUTED"

    # Execution scope and contract
    execution_scope: ExecutionScope
    benchmark_contract: Optional[BenchmarkContract] = None

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

    @staticmethod
    def _case_inventory_digest(results: List[CaseEvaluationResult]) -> str:
        """Digest only public case identity/label metadata, never fixture contents."""
        inventory = sorted(
            [
                [
                    result.case_id,
                    result.case_family,
                    result.split,
                    result.category,
                    result.difficulty,
                    result.evaluation_stage.value,
                    result.expected_verdict.value,
                    result.evaluation_scope.value,
                ]
                for result in results
            ],
            key=lambda item: item[0],
        )
        payload = json.dumps(inventory, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @model_validator(mode="after")
    def validate_report_identity_and_accounting(self) -> "BenchmarkRunReport":
        contract = self.benchmark_contract
        if contract is None:
            raise ValueError("benchmark report must include its run identity contract")
        if contract.execution_scope != self.execution_scope:
            raise ValueError("report execution scope must match its benchmark contract")
        if contract.dataset_canonical_hash != self.canonical_dataset_hash:
            raise ValueError("report dataset digest must match its benchmark contract")
        if contract.git_commit_sha != self.git_commit_sha:
            raise ValueError("report commit SHA must match its benchmark contract")
        if contract.benchmark_version != self.benchmark_version:
            raise ValueError("report version must match its benchmark contract")
        if (
            self.execution_scope != ExecutionScope.CUSTOM
            and _official_report_mint.get() is not _OFFICIAL_REPORT_MINT
        ):
            raise ValueError(
                "official benchmark authority is minted only during verified in-process runner execution; "
                "serialized reports are unauthenticated"
            )
        case_ids = [result.case_id for result in self.per_case_results]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("per-case results cannot contain duplicate case IDs")
        if self.eligible_cases > self.total_cases:
            raise ValueError("eligible case count cannot exceed total case count")
        if self.executed_cases > self.eligible_cases:
            raise ValueError("executed case count cannot exceed eligible case count")
        if self.failed_cases > self.executed_cases:
            raise ValueError("failed case count cannot exceed executed case count")
        if len(self.per_case_results) != self.executed_cases:
            raise ValueError("per-case results must match the executed case count")
        if self.skipped_cases != self.eligible_cases - self.executed_cases:
            raise ValueError("skipped case count must match eligible minus executed cases")
        observed_failures = sum(
            any("Pipeline error:" in reason for reason in result.mismatch_reasons)
            for result in self.per_case_results
        )
        if self.failed_cases != observed_failures:
            raise ValueError("failed case count must match per-case pipeline failures")

        expected_completion = (
            round(self.executed_cases / self.eligible_cases, 4)
            if self.eligible_cases
            else 0.0
        )
        if self.completion_fraction != expected_completion:
            raise ValueError("completion fraction must match executed/eligible case counts")

        expected_status = (
            ExecutionStatus.FAILED
            if self.failed_cases > 0
            else ExecutionStatus.COMPLETED
            if self.executed_cases == self.eligible_cases
            else ExecutionStatus.PARTIAL_RUN
        )
        if self.execution_status != expected_status:
            raise ValueError("execution status must match case completion and failure counts")

        # Aggregate fields are derived claims. Recompute every metric, including
        # seeded confidence intervals, from the child results before trusting them.
        expected_metrics = aggregate_case_metrics(
            self.per_case_results,
            run_bootstrap=True,
            bootstrap_iterations=TRUSTED_BENCHMARK_BOOTSTRAP_ITERATIONS,
            bootstrap_seed=TRUSTED_BENCHMARK_BOOTSTRAP_SEED,
        )
        if (
            expected_metrics.model_dump(mode="json")
            != self.aggregate_metrics.model_dump(mode="json")
        ):
            raise ValueError("aggregate metrics must be recomputed from per-case results")

        if self.execution_scope != ExecutionScope.CUSTOM:
            pinned_inventory = TRUSTED_OFFICIAL_CASE_INVENTORIES.get(self.execution_scope.value)
            if pinned_inventory is None:
                raise ValueError("official report scope is not pinned")
            expected_count, expected_inventory_digest = pinned_inventory
            if self.benchmark_version != TRUSTED_BENCHMARK_VERSION:
                raise ValueError("official report requires the repository-pinned benchmark version")
            if self.dataset_version != TRUSTED_BENCHMARK_DATASET_VERSION:
                raise ValueError("official report requires the repository-pinned dataset version")
            if contract.matcher_version != TRUSTED_BENCHMARK_MATCHER_VERSION:
                raise ValueError("official report requires the repository-pinned matcher version")
            if contract.metrics_version != TRUSTED_BENCHMARK_METRICS_VERSION:
                raise ValueError("official report requires the repository-pinned metrics version")
            if self.total_cases != TRUSTED_BENCHMARK_CASE_COUNT:
                raise ValueError("official report total must match the pinned public corpus")
            if self.eligible_cases != expected_count or self.executed_cases != expected_count:
                raise ValueError("official report must execute the complete pinned case inventory")
            if self.execution_status == ExecutionStatus.PARTIAL_RUN:
                raise ValueError("official report cannot claim a partial case inventory")
            if self._case_inventory_digest(self.per_case_results) != expected_inventory_digest:
                raise ValueError("official report case inventory does not match the pinned scope")
        return self


class BenchmarkRunner:
    """Orchestrates sandboxed evaluation of RepoLens on benchmark cases."""

    def __init__(
        self,
        catalog: Optional[CapabilityCatalog] = None,
        judge: Optional[IndependentBenchmarkJudge] = None,
    ) -> None:
        self._canonical_dependencies = catalog is None and judge is None
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
                repository_url=_NEUTRAL_REPO_URL,
                commit_hash=_NEUTRAL_NULL_COMMIT,
            )

            emitted: List[EvaluatedFinding] = []

            # 2. If stage is STATIC_FINDING, run core static analyzers
            if case.evaluation_stage == EvaluationStage.STATIC_FINDING:
                scan_res = analyze_core_repository(sandbox_dir, manifest)
                for f in scan_res.findings:
                    rule_id = "CLIENT_CONTROLLED_AUTH_HEADER" if "client-controlled" in f.rule_id else (
                        "HARDCODED_CREDENTIAL" if "hardcoded" in f.rule_id else f.rule_id
                    )
                    sym = None
                    if manifest and f.evidence.file_path and f.evidence.start_line:
                        norm_ev_f = f.evidence.file_path.replace("\\", "/").strip().lstrip("/").lower()
                        for fe in manifest.files:
                            if fe.path.replace("\\", "/").strip().lstrip("/").lower() == norm_ev_f:
                                for s in fe.symbols:
                                    if s.start_line <= f.evidence.start_line <= s.end_line:
                                        kind_str = getattr(s.kind, "value", str(s.kind))
                                        if kind_str in ("FUNCTION", "METHOD"):
                                            sym = s.name
                                            break
                                        elif kind_str == "FASTAPI_ROUTE" and s.details.get("handler"):
                                            sym = s.details["handler"]
                                            break
                    emitted.append(
                        EvaluatedFinding(
                            rule_id=rule_id,
                            file_path=f.evidence.file_path,
                            symbol=sym,
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
                    if flow.sanitizers or any(t.startswith("OPAQUE_CALL:") for t in flow.transformations):
                        continue
                    sink_kind = getattr(flow.sink, "sink_kind", getattr(flow.sink, "kind", ""))
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
                base_commit_sha=_NEUTRAL_BASE_COMMIT,
                head_commit_sha=_NEUTRAL_HEAD_COMMIT,
                repository_url=_NEUTRAL_REPO_URL,
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

                    sym = None
                    if r_delta.details and r_delta.details.startswith("Changed "):
                        sym = r_delta.details.split("Changed ", 1)[1].split(":", 1)[0].strip()
                    if not sym:
                        sym = r_delta.route_name

                    emitted.append(
                        EvaluatedFinding(
                            rule_id=r_id,
                            file_path=r_delta.file_path,
                            symbol=sym,
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
                    repository_url=_NEUTRAL_REPO_URL,
                    commit_hash=_NEUTRAL_BASE_COMMIT,
                )
                head_manifest = build_manifest(
                    head_sandbox,
                    repository_url=_NEUTRAL_REPO_URL,
                    commit_hash=_NEUTRAL_HEAD_COMMIT,
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

                seen_multi_consumer: Set[str] = set()
                for impact in blast_radius.impacts:
                    impact_type_str = getattr(impact.impact_type, "value", str(impact.impact_type))
                    payload = impact.evidence_payload or {}
                    title_lower = (impact.title or "").lower()
                    if payload.get("change_type") == "DELETED" or "deleted symbol" in title_lower:
                        rule_id = "DELETED_SYMBOL_WITH_CALLERS"
                        semantic_type = "CALLER_BROKEN_BY_DELETION"
                    elif ("signature_diff" in payload or "signature change" in title_lower) and payload.get("is_breaking", True):
                        rule_id = "SIGNATURE_BREAK_CALLERS"
                        semantic_type = "SIGNATURE_MISMATCH"
                    elif len(blast_radius.impacts) >= 2:
                        rule_id = "BLAST_RADIUS_MULTI_CONSUMER"
                        semantic_type = impact_type_str
                        sym_key = impact.source_symbol or ""
                        if sym_key in seen_multi_consumer:
                            continue
                        seen_multi_consumer.add(sym_key)
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
        if cases is not None and cases_dir is not None:
            raise ValueError("provide either explicit cases or cases_dir, not both")

        has_explicit_dataset = cases is not None or cases_dir is not None
        if cases is not None:
            # An explicitly supplied empty list is a real empty custom dataset,
            # not a request to fall back to the repository benchmark.
            loaded_cases = cases
        else:
            loaded_cases = load_benchmark_dataset(cases_dir=cases_dir, catalog=self.catalog)

        eligible_cases = loaded_cases if split is None else filter_by_split(loaded_cases, split)
        dataset_hash = compute_canonical_benchmark_hash(loaded_cases)
        commit_sha = _get_git_commit_sha()

        # Official labels require implicit canonical inputs, default evaluator
        # dependencies, a supported split, and a successful repository-pinned
        # benchmark verification. Explicit caller data is always CUSTOM even if
        # it happens to have the same bytes as the public corpus.
        supported_official_split = split in {
            None,
            BenchmarkSplit.DEV,
            BenchmarkSplit.FROZEN_PUBLIC_EVAL,
        }
        benchmark_verified = False
        if (
            not has_explicit_dataset
            and self._canonical_dependencies
            and supported_official_split
            and _is_commit_sha(commit_sha)
            and _repository_tree_is_clean()
        ):
            try:
                validation = HoldoutAuthorizationContract.verify_benchmark_contract(
                    BENCHMARK_MANIFEST_PATH,
                    cases_dir=BENCHMARK_CASES_DIR,
                    root_dir=REPO_ROOT,
                )
                benchmark_verified = validation.valid
            except Exception:
                # Verification failures must never grant an official identity.
                benchmark_verified = False

        if not benchmark_verified or dataset_hash != TRUSTED_BENCHMARK_DATASET_SHA256:
            exec_scope = ExecutionScope.CUSTOM
        elif split == BenchmarkSplit.FROZEN_PUBLIC_EVAL:
            exec_scope = ExecutionScope.OFFICIAL_PUBLIC_EVAL
        elif split == BenchmarkSplit.DEV:
            exec_scope = ExecutionScope.OFFICIAL_DEV
        else:
            exec_scope = ExecutionScope.OFFICIAL_FULL_DIAGNOSTIC

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

        agg_metrics = aggregate_case_metrics(
            results,
            run_bootstrap=True,
            bootstrap_iterations=TRUSTED_BENCHMARK_BOOTSTRAP_ITERATIONS,
            bootstrap_seed=TRUSTED_BENCHMARK_BOOTSTRAP_SEED,
        )
        # Build cryptographic binding contract
        contract = BenchmarkContract(
            dataset_canonical_hash=dataset_hash,
            git_commit_sha=commit_sha,
            execution_scope=exec_scope,
            benchmark_contract_id=f"{exec_scope.value}:{dataset_hash}:{commit_sha}",
            benchmark_authority_id=(
                TRUSTED_BENCHMARK_CONTRACT_ID
                if exec_scope != ExecutionScope.CUSTOM
                else None
            ),
        )

        mint_token = (
            _official_report_mint.set(_OFFICIAL_REPORT_MINT)
            if exec_scope != ExecutionScope.CUSTOM
            else None
        )
        try:
            return BenchmarkRunReport(
                benchmark_version=TRUSTED_BENCHMARK_VERSION,
                dataset_version=TRUSTED_BENCHMARK_DATASET_VERSION,
                canonical_dataset_hash=dataset_hash,
                git_commit_sha=commit_sha,
                python_version=platform.python_version(),
                platform=f"{platform.system()} {platform.release()}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                duration_seconds=elapsed,
                execution_scope=exec_scope,
                benchmark_contract=contract,
                execution_status=status,
                total_cases=total_count,
                eligible_cases=eligible_count,
                executed_cases=executed_count,
                failed_cases=failed_cases,
                completion_fraction=completion_fraction,
                aggregate_metrics=agg_metrics,
                per_case_results=results,
            )
        finally:
            if mint_token is not None:
                _official_report_mint.reset(mint_token)
