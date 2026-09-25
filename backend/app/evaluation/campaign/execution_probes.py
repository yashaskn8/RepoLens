"""Separate, non-scoring fixtures for explicit live model-execution proof.

These two fixtures establish that the configured live models can be invoked by
the production full-analysis graph. They are not benchmark cases and carry no
expected findings, labels, grader outcomes, or quality metrics.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import time
from typing import Any, Literal
from uuid import uuid4

from pydantic import ConfigDict, Field, model_validator

from app.evaluation.campaign.contracts import CampaignModel, canonical_digest
from app.evaluation.campaign.path_qualification import (
    ModelPathQualificationReport,
    _qualify_analysis_input,
    qualify_public_dev_model_paths,
)
from app.evaluation.ground_truth.schemas import AnalysisInput, RepositoryFixture, TargetPipeline
from app.evaluation.system.full_analysis import _actual_model_pairs, _execute_trial
from app.evaluation.system.identity import build_agent_system_identity, full_analysis_graph_identity_digest
from app.evaluation.system.schemas import SystemEvalMode
from app.evaluation.system.full_analysis import FullAnalysisFixture
from app.evaluation.ground_truth.leakage import LeakageDetector
from app.llm.types import LLMProvider


LIVE_EXECUTION_PROBE_SET_VERSION = "live-execution-probes/1.0"
LIVE_EXECUTION_PROOF_SCHEMA_VERSION = "live-execution-proof/1.1"
_PROBE_SOURCE_DIRECTORIES = (
    "backend/app/agents",
    "backend/app/agent_runtime",
    "backend/app/agent_tools",
    "backend/app/context",
    "backend/app/llm",
    "backend/app/evaluation/system",
    "backend/app/evaluation/campaign",
)


class LiveExecutionProbe(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    expected_model_node: Literal["bug", "security"]
    analysis_input: AnalysisInput
    fixture_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_fixture(self) -> "LiveExecutionProbe":
        if self.analysis_input.case_id != self.probe_id:
            raise ValueError("execution probe ID must match its label-free analysis input")
        if self.analysis_input.target_pipeline != TargetPipeline.REPOSITORY_SCAN:
            raise ValueError("execution probes must use the production repository-scan pipeline")
        actual = canonical_digest(self.analysis_input.model_dump(mode="json"))
        if actual != self.fixture_digest:
            raise ValueError("execution probe fixture digest mismatch")
        LeakageDetector.check_fixture(self.analysis_input.fixture, case_id=self.probe_id)
        if self.category == "CORRECTNESS" and self.expected_model_node != "bug":
            raise ValueError("correctness execution probe must qualify the bug specialist path")
        if self.category == "SECURITY" and self.expected_model_node != "security":
            raise ValueError("security execution probe must qualify the security specialist path")
        return self


class LiveExecutionProbeSet(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["live-execution-probes/1.0"] = LIVE_EXECUTION_PROBE_SET_VERSION
    probes: tuple[LiveExecutionProbe, LiveExecutionProbe]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_set(self) -> "LiveExecutionProbeSet":
        if {item.category for item in self.probes} != {"CORRECTNESS", "SECURITY"}:
            raise ValueError("execution probe set must contain one correctness and one security fixture")
        if len({item.probe_id for item in self.probes}) != 2:
            raise ValueError("execution probe IDs must be unique")
        payload = self.model_dump(mode="json", exclude={"digest"})
        if canonical_digest(payload) != self.digest:
            raise ValueError("execution probe set digest mismatch")
        return self


def _build_probe_payload() -> dict[str, Any]:
    raw_inputs = (
        {
            "probe_id": "LIVE-EXEC-CORRECTNESS-01",
            "category": "CORRECTNESS",
            "expected_model_node": "bug",
            "analysis_input": AnalysisInput(
                case_id="LIVE-EXEC-CORRECTNESS-01",
                target_pipeline=TargetPipeline.REPOSITORY_SCAN,
                fixture=RepositoryFixture(files={
                    "worker.py": (
                        "import time\n\n"
                        "async def poll_remote_status():\n"
                        "    time.sleep(0.01)\n"
                    ),
                }),
            ),
        },
        {
            "probe_id": "LIVE-EXEC-SECURITY-01",
            "category": "SECURITY",
            "expected_model_node": "security",
            "analysis_input": AnalysisInput(
                case_id="LIVE-EXEC-SECURITY-01",
                target_pipeline=TargetPipeline.REPOSITORY_SCAN,
                fixture=RepositoryFixture(files={
                    "records.py": (
                        "from fastapi import FastAPI\n\n"
                        "app = FastAPI()\n\n"
                        "@app.get('/records/{owner}')\n"
                        "def load_record(owner: str):\n"
                        "    connection = get_connection()\n"
                        "    return connection.execute(\n"
                        "        f\"SELECT * FROM records WHERE owner = '{owner}'\"\n"
                        "    )\n"
                    ),
                }),
            ),
        },
    )
    probes = []
    for item in raw_inputs:
        analysis_input = item["analysis_input"].model_dump(mode="json")
        input_digest = canonical_digest(analysis_input)
        probes.append({**item, "analysis_input": analysis_input, "fixture_digest": input_digest})
    return {
        "version": LIVE_EXECUTION_PROBE_SET_VERSION,
        "probes": probes,
    }


def load_live_execution_probe_set() -> LiveExecutionProbeSet:
    """Return a fresh validated copy of exactly two public execution fixtures."""
    payload = _build_probe_payload()
    return LiveExecutionProbeSet(**payload, digest=canonical_digest(payload))


class ProbePathQualification(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    expected_model_node: Literal["bug", "security"]
    model_gateway_reached: bool
    observed_model_node: str | None = Field(default=None, max_length=64)
    failure_code: str | None = Field(default=None, max_length=64)


class LiveExecutionProbeQualification(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["live-execution-probe-qualification/1.0"] = "live-execution-probe-qualification/1.0"
    probe_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_calls: Literal[0] = 0
    probe_results: tuple[ProbePathQualification, ProbePathQualification]
    qualified: bool
    qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_qualification(self) -> "LiveExecutionProbeQualification":
        expected = all(
            item.model_gateway_reached and item.observed_model_node == item.expected_model_node
            and item.failure_code is None
            for item in self.probe_results
        )
        if self.qualified != expected:
            raise ValueError("probe qualification status does not match its child results")
        payload = self.model_dump(mode="json", exclude={"qualification_digest"})
        if canonical_digest(payload) != self.qualification_digest:
            raise ValueError("execution probe qualification digest mismatch")
        return self


class PinnedModelProbePath(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1, max_length=64)
    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    provider: LLMProvider
    model: str = Field(min_length=1, max_length=256)
    expected_model_node: Literal["bug", "security"]
    model_gateway_reached: bool
    observed_model_node: str | None = Field(default=None, max_length=64)
    failure_code: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def validate_route_path(self) -> "PinnedModelProbePath":
        if self.model_gateway_reached:
            if self.observed_model_node != self.expected_model_node or self.failure_code is not None:
                raise ValueError("pinned model path must reach its exact expected production node")
        elif self.observed_model_node is not None or self.failure_code is None:
            raise ValueError("unreachable pinned model paths require a bounded failure code")
        return self


class PinnedModelRouteQualification(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pinned-model-route-qualification/1.0"] = "pinned-model-route-qualification/1.0"
    probe_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    planned_model_pairs: tuple[str, str]
    provider_calls: Literal[0] = 0
    route_results: tuple[PinnedModelProbePath, PinnedModelProbePath, PinnedModelProbePath, PinnedModelProbePath]
    qualified: bool
    qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_route_matrix(self) -> "PinnedModelRouteQualification":
        expected_models = {
            "gemini:gemini-3.7-flash",
            "groq:openai/gpt-oss-120b",
        }
        if set(self.planned_model_pairs) != expected_models:
            raise ValueError("pinned route qualification must use the two exact planned models")
        keys = [(item.candidate_id, item.probe_id) for item in self.route_results]
        if len(set(keys)) != 4 or {item.probe_id for item in self.route_results} != {
            "LIVE-EXEC-CORRECTNESS-01", "LIVE-EXEC-SECURITY-01",
        }:
            raise ValueError("pinned route qualification must contain all four model/probe pairs")
        if {f"{item.provider.value}:{item.model}" for item in self.route_results} != expected_models:
            raise ValueError("pinned route results do not match the exact model identities")
        candidate_ids = {item.candidate_id for item in self.route_results}
        if len(candidate_ids) != 2 or any(
            sum(row.candidate_id == candidate_id for row in self.route_results) != 2
            for candidate_id in candidate_ids
        ):
            raise ValueError("each pinned model must have exactly two probe results")
        expected_qualified = all(
            row.model_gateway_reached and row.observed_model_node == row.expected_model_node
            and row.failure_code is None
            for row in self.route_results
        )
        if self.qualified != expected_qualified:
            raise ValueError("pinned route qualification status does not match the route matrix")
        payload = self.model_dump(mode="json", exclude={"qualification_digest"})
        if canonical_digest(payload) != self.qualification_digest:
            raise ValueError("pinned model route qualification digest mismatch")
        return self


async def qualify_live_execution_probe_set() -> LiveExecutionProbeQualification:
    """Prove both separate fixtures reach their intended nodes, without providers."""
    probes = load_live_execution_probe_set()
    results: list[ProbePathQualification] = []
    for probe in probes.probes:
        path = await _qualify_analysis_input(
            probe.analysis_input,
            case_id=probe.probe_id,
            category=probe.category,
        )
        results.append(ProbePathQualification(
            probe_id=probe.probe_id,
            category=probe.category,
            expected_model_node=probe.expected_model_node,
            model_gateway_reached=path.model_gateway_reached,
            observed_model_node=path.first_model_node,
            failure_code=None if path.model_gateway_reached else path.pre_model_terminal_reason,
        ))
    results.sort(key=lambda item: item.category)
    qualified = all(
        item.model_gateway_reached and item.observed_model_node == item.expected_model_node
        and item.failure_code is None
        for item in results
    )
    payload = {
        "schema_version": "live-execution-probe-qualification/1.0",
        "probe_set_digest": probes.digest,
        "graph_identity_digest": full_analysis_graph_identity_digest(),
        "provider_calls": 0,
        "probe_results": [item.model_dump(mode="json") for item in results],
        "qualified": qualified,
    }
    return LiveExecutionProbeQualification(
        **payload, qualification_digest=canonical_digest(payload),
    )


async def qualify_pinned_model_probe_paths(
    models: list[tuple[str, LLMProvider | str, str]],
) -> PinnedModelRouteQualification:
    """Run four exact-route graph probes with sentinel adapters and no provider I/O."""
    normalized = [(candidate_id, LLMProvider(provider), model) for candidate_id, provider, model in models]
    expected = {
        ("gemini", LLMProvider.GEMINI, "gemini-3.7-flash"),
        ("groq", LLMProvider.GROQ, "openai/gpt-oss-120b"),
    }
    if len(normalized) != 2 or set(normalized) != expected:
        raise ValueError("pinned route qualification only accepts the exact planned model candidates")
    probes = load_live_execution_probe_set()
    results: list[PinnedModelProbePath] = []
    for candidate_id, provider, model in sorted(normalized, key=lambda item: item[0]):
        for probe in sorted(probes.probes, key=lambda item: item.category):
            path = await _qualify_analysis_input(
                probe.analysis_input,
                case_id=probe.probe_id,
                category=probe.category,
                provider=provider,
                model=model,
            )
            results.append(PinnedModelProbePath(
                candidate_id=candidate_id,
                probe_id=probe.probe_id,
                category=probe.category,
                provider=provider,
                model=model,
                expected_model_node=probe.expected_model_node,
                model_gateway_reached=path.model_gateway_reached,
                observed_model_node=path.first_model_node,
                failure_code=None if path.model_gateway_reached else "PINNED_MODEL_ROUTE_NOT_REACHABLE",
            ))
    results.sort(key=lambda item: (item.candidate_id, item.category))
    pairs = tuple(sorted(f"{provider.value}:{model}" for _, provider, model in normalized))
    qualified = all(
        item.model_gateway_reached and item.observed_model_node == item.expected_model_node
        and item.failure_code is None
        for item in results
    )
    payload = {
        "schema_version": "pinned-model-route-qualification/1.0",
        "probe_set_digest": probes.digest,
        "graph_identity_digest": full_analysis_graph_identity_digest(),
        "planned_model_pairs": pairs,
        "provider_calls": 0,
        "route_results": [item.model_dump(mode="json") for item in results],
        "qualified": qualified,
    }
    return PinnedModelRouteQualification(
        **payload, qualification_digest=canonical_digest(payload),
    )


class LiveExecutionUnit(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1, max_length=64)
    probe_id: str = Field(min_length=1, max_length=96)
    category: Literal["CORRECTNESS", "SECURITY"]
    planned_provider: LLMProvider
    planned_model: str = Field(min_length=1, max_length=256)
    status: Literal[
        "EXECUTION_PROVEN", "PROVIDER_FAILURE", "BUDGET_FAILURE", "IDENTITY_MISMATCH",
        "MODEL_NOT_INVOKED", "HARNESS_FAILURE",
    ]
    model_calls: int = Field(ge=0, le=64)
    observed_model_pairs: tuple[str, ...] = Field(max_length=8)
    cross_provider_fallback: bool
    duration_ms: float = Field(ge=0.0, le=120_000.0)
    safe_failure_code: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def validate_execution_identity(self) -> "LiveExecutionUnit":
        planned = f"{self.planned_provider.value}:{self.planned_model}"
        if self.status == "EXECUTION_PROVEN" and (
            self.model_calls < 1 or self.observed_model_pairs != (planned,)
            or self.cross_provider_fallback or self.safe_failure_code is not None
        ):
            raise ValueError("proven execution requires an observed exact model call and no fallback")
        if self.status != "EXECUTION_PROVEN" and self.safe_failure_code is None:
            raise ValueError("failed execution units require a safe failure code")
        return self


class LiveExecutionProofReport(CampaignModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["live-execution-proof/1.1"] = LIVE_EXECUTION_PROOF_SCHEMA_VERSION
    proof_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    created_at: datetime
    source_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    source_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    dirty_worktree: bool
    probe_set_version: str = Field(min_length=1, max_length=64)
    probe_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_dataset_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    pinned_route_qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_dev_case_count: Literal[35] = 35
    public_dev_correctness_model_paths: int = Field(ge=1, le=12)
    public_dev_security_model_paths: Literal[0] = 0
    qualification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    graph_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_identity_digests: dict[str, str] = Field(min_length=2, max_length=2)
    planned_model_pairs: tuple[str, str]
    provider_preflight_statuses: dict[str, str] = Field(min_length=2, max_length=2)
    mode: Literal["LIVE_EXECUTION_PROOF_ONLY"] = "LIVE_EXECUTION_PROOF_ONLY"
    quality_metrics: Literal["NOT_APPLICABLE"] = "NOT_APPLICABLE"
    workflow_units: tuple[LiveExecutionUnit, LiveExecutionUnit, LiveExecutionUnit, LiveExecutionUnit]
    status: Literal["LIVE_EXECUTION_PROVEN", "LIVE_EXECUTION_NOT_PROVEN"]
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_proof(self) -> "LiveExecutionProofReport":
        expected_pairs = set(self.planned_model_pairs)
        if len(expected_pairs) != 2:
            raise ValueError("execution proof must bind exactly two distinct model identities")
        unit_keys = [(unit.candidate_id, unit.probe_id) for unit in self.workflow_units]
        if len(set(unit_keys)) != 4:
            raise ValueError("execution proof must contain one workflow for each model/probe pair")
        if {unit.probe_id for unit in self.workflow_units} != {
            "LIVE-EXEC-CORRECTNESS-01", "LIVE-EXEC-SECURITY-01",
        }:
            raise ValueError("execution proof contains an unknown probe fixture")
        if {f"{unit.planned_provider.value}:{unit.planned_model}" for unit in self.workflow_units} != expected_pairs:
            raise ValueError("execution proof workflow identities differ from planned identities")
        if expected_pairs != {
            "gemini:gemini-3.7-flash",
            "groq:openai/gpt-oss-120b",
        }:
            raise ValueError("execution proof must bind the two fixed requested model identities")
        candidate_ids = {unit.candidate_id for unit in self.workflow_units}
        if candidate_ids != set(self.system_identity_digests) or candidate_ids != set(self.provider_preflight_statuses):
            raise ValueError("execution proof candidate metadata must match all workflow units")
        proven = all(unit.status == "EXECUTION_PROVEN" for unit in self.workflow_units)
        if (self.status == "LIVE_EXECUTION_PROVEN") != proven:
            raise ValueError("proof status must be derived from all four workflow units")
        payload = self.model_dump(mode="json", exclude={"report_digest"})
        if canonical_digest(payload) != self.report_digest:
            raise ValueError("live execution proof digest mismatch")
        return self


def _validated_proof_report(raw: dict[str, Any]) -> LiveExecutionProofReport:
    """Normalize through the report's JSON contract before digesting it."""
    value = dict(raw)
    if isinstance(value.get("created_at"), str):
        value["created_at"] = datetime.fromisoformat(value["created_at"])
    value["planned_model_pairs"] = tuple(value["planned_model_pairs"])
    value["workflow_units"] = tuple(
        item if isinstance(item, LiveExecutionUnit) else LiveExecutionUnit.model_validate(item)
        for item in value["workflow_units"]
    )
    normalized = LiveExecutionProofReport.model_construct(
        **value, report_digest="0" * 64,
    ).model_dump(mode="json", exclude={"report_digest"})
    return LiveExecutionProofReport(
        **normalized,
        report_digest=canonical_digest(normalized),
    )


def _source_binding_digest() -> str:
    repository = Path(__file__).resolve().parents[4]
    digest = hashlib.sha256()
    root = repository.resolve(strict=True)
    paths: list[tuple[str, Path]] = []
    for relative_dir in _PROBE_SOURCE_DIRECTORIES:
        directory = repository / relative_dir
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("live execution proof source inventory is incomplete")
        for path in directory.rglob("*"):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                raise ValueError("live execution proof source inventory contains a symlink")
            if not path.is_file() or path.suffix != ".py":
                continue
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ValueError("live execution proof source inventory escaped the repository") from exc
            paths.append((path.relative_to(repository).as_posix(), resolved))
    for relative, path in sorted(paths):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _model_call_count(state: dict[str, Any]) -> int:
    trace = state.get("workflow_trace", [])
    if isinstance(trace, list):
        total = sum(
            int(item.get("model_execution_count", 0) or 0)
            for item in trace if isinstance(item, dict)
        )
        if total:
            return min(total, 64)
    executions = state.get("model_executions", [])
    return min(len(executions), 64) if isinstance(executions, list) else 0


def _cross_provider_fallback(state: dict[str, Any], expected: str) -> bool:
    if _actual_model_pairs(state) - {tuple(expected.split(":", 1))}:
        return True
    for item in state.get("model_executions", []) if isinstance(state.get("model_executions"), list) else []:
        extra = getattr(item, "extra_metadata", None)
        extra = extra if isinstance(extra, dict) else {}
        attempts = extra.get("fallbacks_attempted")
        if isinstance(attempts, list) and attempts:
            if any(
                not isinstance(attempt, dict)
                or str(attempt.get("provider", "")).lower() != expected.split(":", 1)[0]
                for attempt in attempts
            ):
                return True
        if extra.get("fallback_used") is True:
            return True
    return False


def _safe_failure_code(state: dict[str, Any], *, model_calls: int, identity_ok: bool) -> str | None:
    trace = state.get("workflow_trace", [])
    trace = trace if isinstance(trace, list) else []
    failure_codes = {
        str(code)
        for event in trace if isinstance(event, dict)
        for code in (
            event.get("failure_codes", [])
            if isinstance(event.get("failure_codes", []), list)
            else []
        )
    }
    if "BUDGET_EXHAUSTION" in failure_codes or bool((state.get("ai_cloud_budget") or {}).get("exhausted")):
        return "WORKFLOW_BUDGET_EXHAUSTED"
    if "MODEL_PROVIDER_FAILURE" in failure_codes or "MODEL_PROVIDER_TIMEOUT" in failure_codes:
        return "MODEL_PROVIDER_FAILURE"
    if model_calls == 0:
        return "MODEL_NOT_INVOKED"
    if not identity_ok:
        return "PINNED_MODEL_IDENTITY_MISMATCH"
    if state.get("status") == "FAILED":
        return "WORKFLOW_HARNESS_FAILURE"
    return None


def _persist_proof(report: LiveExecutionProofReport) -> Path:
    repository = Path(__file__).resolve().parents[4]
    directory = repository / "backend" / "output" / "live_execution_proofs"
    if directory.is_symlink():
        raise ValueError("execution proof artifact directory cannot be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{report.proof_id}.json"
    if path.exists() or path.is_symlink():
        raise ValueError("execution proof artifacts are immutable")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(report.model_dump_json(indent=2) + "\n")
    return path


async def run_live_execution_proof(
    models: list[tuple[str, LLMProvider | str, str]],
    *,
    allow_live: bool = False,
    allow_model_campaign: bool = False,
) -> tuple[LiveExecutionProofReport, Path]:
    """Make exactly four explicitly opted-in execution-only full-graph runs."""
    if not (allow_live and allow_model_campaign):
        raise ValueError("live execution proof requires --allow-live and --allow-model-campaign")
    if len(models) != 2 or len({str(item[0]) for item in models}) != 2:
        raise ValueError("execution proof requires exactly two distinct candidate IDs")
    expected_models = {
        ("gemini", "gemini-3.7-flash"),
        ("groq", "openai/gpt-oss-120b"),
    }
    normalized = [(cid, LLMProvider(provider), model) for cid, provider, model in models]
    if {(provider.value, model) for _, provider, model in normalized} != expected_models:
        raise ValueError("execution proof only accepts the two explicitly planned Gemini/Groq model identities")
    # Re-run both no-provider qualifications inside the proof command. A
    # caller-supplied, re-digested JSON artifact is not treated as evidence
    # that the current graph naturally reaches these boundaries.
    public_qualification: ModelPathQualificationReport = await qualify_public_dev_model_paths()
    public_security_paths = [
        item.case_id for item in public_qualification.cases
        if item.category == "SECURITY" and item.model_gateway_reached
    ]
    if public_security_paths:
        raise ValueError(
            "canonical public DEV security paths are now model-reachable; use the versioned benchmark smoke path instead"
        )
    if not any(
        item.category == "CORRECTNESS" and item.model_gateway_reached
        for item in public_qualification.cases
    ):
        raise ValueError("canonical public DEV correctness has no model-reaching path")
    probes_qualification = await qualify_live_execution_probe_set()
    probes = load_live_execution_probe_set()
    if not probes_qualification.qualified or probes_qualification.probe_set_digest != probes.digest:
        raise ValueError("both separate execution probes must pass offline path qualification before live calls")
    if probes_qualification.graph_identity_digest != full_analysis_graph_identity_digest():
        raise ValueError("offline probe qualification is stale for the current production graph")
    pinned_route_qualification = await qualify_pinned_model_probe_paths(normalized)
    if not pinned_route_qualification.qualified:
        blocked = [
            f"{item.candidate_id}/{item.category}"
            for item in pinned_route_qualification.route_results
            if not item.model_gateway_reached
        ]
        raise ValueError(
            "pinned candidate routes failed offline model-boundary qualification for: "
            + ", ".join(blocked)
            + "; no live provider workflows were started"
        )

    from app.evaluation.campaign.preflight import run_campaign_preflight

    preflight = run_campaign_preflight(normalized)
    accepted_statuses = {"READY", "READY_WITH_CAPABILITY_WARNINGS"}
    if any(item.status not in accepted_statuses or not item.credential_configured for item in preflight.candidate_readiness):
        raise ValueError("a pinned model is not technically ready; no live execution was attempted")

    system_digests: dict[str, str] = {}
    identity_fixture = FullAnalysisFixture(probes.probes[0].analysis_input)
    try:
        await identity_fixture.initialize_runtime()
        for candidate_id, provider, model in normalized:
            identity = build_agent_system_identity(
                provider=provider,
                model=model,
                registry=identity_fixture.registry,
                scope="FULL_ANALYSIS_GRAPH",
            )
            system_digests[candidate_id] = identity.system_digest
    finally:
        identity_fixture.close()

    from app.evaluation.campaign.plan import _git_head
    from app.evaluation.campaign.runner import _git_state

    source_revision, dirty = _git_state()
    if source_revision != _git_head():
        raise ValueError("source revision changed while freezing execution proof identity")
    source_digest = _source_binding_digest()
    units: list[LiveExecutionUnit] = []
    for candidate_id, provider, model in sorted(normalized, key=lambda item: item[0]):
        for probe in sorted(probes.probes, key=lambda item: item.category):
            started = time.perf_counter()
            try:
                state, _, _, _ = await asyncio.wait_for(
                    _execute_trial(
                        probe.analysis_input,
                        mode=SystemEvalMode.LIVE,
                        provider=provider,
                        model=model,
                        evaluation_case_id=probe.probe_id,
                        presentation_stage="LIVE_EXECUTION_PROOF_ONLY",
                    ),
                    timeout=120.0,
                )
                state = dict(state)
                model_calls = _model_call_count(state)
                expected_pair = f"{provider.value}:{model}"
                actual_pairs = sorted(f"{p}:{m}" for p, m in _actual_model_pairs(state))
                identity_ok = set(actual_pairs) == {expected_pair}
                fallback = _cross_provider_fallback(state, expected_pair)
                failure = _safe_failure_code(state, model_calls=model_calls, identity_ok=identity_ok)
                if fallback:
                    failure = "CROSS_PROVIDER_FALLBACK"
                status = "EXECUTION_PROVEN" if failure is None else (
                    "IDENTITY_MISMATCH" if failure in {"PINNED_MODEL_IDENTITY_MISMATCH", "CROSS_PROVIDER_FALLBACK"}
                    else "BUDGET_FAILURE" if failure == "WORKFLOW_BUDGET_EXHAUSTED"
                    else "PROVIDER_FAILURE" if failure == "MODEL_PROVIDER_FAILURE"
                    else "MODEL_NOT_INVOKED" if failure == "MODEL_NOT_INVOKED"
                    else "HARNESS_FAILURE"
                )
            except TimeoutError:
                model_calls = 0
                actual_pairs = []
                fallback = False
                failure = "WORKFLOW_TIMEOUT"
                status = "HARNESS_FAILURE"
            except Exception:
                # Deliberately omit arbitrary exception text from this public
                # identity proof; errors could contain provider details.
                model_calls = 0
                actual_pairs = []
                fallback = False
                failure = "WORKFLOW_HARNESS_FAILURE"
                status = "HARNESS_FAILURE"
            units.append(LiveExecutionUnit(
                candidate_id=candidate_id,
                probe_id=probe.probe_id,
                category=probe.category,
                planned_provider=provider,
                planned_model=model,
                status=status,
                model_calls=model_calls,
                observed_model_pairs=tuple(actual_pairs),
                cross_provider_fallback=fallback,
                duration_ms=min(120_000.0, max(0.0, (time.perf_counter() - started) * 1000.0)),
                safe_failure_code=failure,
            ))

    pairs = tuple(sorted(f"{provider.value}:{model}" for _, provider, model in normalized))
    results = tuple(units)
    proven = all(unit.status == "EXECUTION_PROVEN" for unit in results)
    raw = {
        "schema_version": LIVE_EXECUTION_PROOF_SCHEMA_VERSION,
        "proof_id": uuid4().hex,
        "created_at": datetime.now(timezone.utc),
        "source_revision": source_revision,
        "source_binding_digest": source_digest,
        "dirty_worktree": dirty,
        "probe_set_version": probes.version,
        "probe_set_digest": probes.digest,
        "public_dev_qualification_digest": public_qualification.report_digest,
        "public_dev_dataset_digest": public_qualification.dataset_digest,
        "pinned_route_qualification_digest": pinned_route_qualification.qualification_digest,
        "public_dev_case_count": public_qualification.public_dev_case_count,
        "public_dev_correctness_model_paths": sum(
            item.category == "CORRECTNESS" and item.model_gateway_reached
            for item in public_qualification.cases
        ),
        "public_dev_security_model_paths": 0,
        "qualification_digest": probes_qualification.qualification_digest,
        "graph_identity_digest": full_analysis_graph_identity_digest(),
        "system_identity_digests": dict(sorted(system_digests.items())),
        "planned_model_pairs": pairs,
        "provider_preflight_statuses": {
            item.candidate_id: item.status for item in sorted(preflight.candidate_readiness, key=lambda item: item.candidate_id)
        },
        "mode": "LIVE_EXECUTION_PROOF_ONLY",
        "quality_metrics": "NOT_APPLICABLE",
        "workflow_units": results,
        "status": "LIVE_EXECUTION_PROVEN" if proven else "LIVE_EXECUTION_NOT_PROVEN",
    }
    report = _validated_proof_report(raw)
    return report, _persist_proof(report)


__all__ = [
    "LIVE_EXECUTION_PROOF_SCHEMA_VERSION",
    "LIVE_EXECUTION_PROBE_SET_VERSION",
    "LiveExecutionProbe",
    "LiveExecutionProbeSet",
    "LiveExecutionProbeQualification",
    "PinnedModelProbePath",
    "PinnedModelRouteQualification",
    "LiveExecutionProofReport",
    "load_live_execution_probe_set",
    "qualify_live_execution_probe_set",
    "qualify_pinned_model_probe_paths",
    "run_live_execution_proof",
]
