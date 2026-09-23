"""Bounded corrective replay over the canonical production analysis graph."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from app.agents.verifier import _attest_repository_evidence, resolve_verification_routing
from app.evaluation.counterfactual.checkpoints import (
    checkpoint_id_digest,
    checkpoint_state_digest,
    locate_factual_checkpoint,
    locate_pre_revision_checkpoint,
)
from app.evaluation.counterfactual.contracts import (
    CounterfactualEffect,
    CounterfactualInterventionKind,
    ReplayMetric,
    ReplayMetricStatus,
    ReplayOutcomeMetrics,
    ReplayTraceEvent,
    make_intervention,
    make_replay_report,
    make_trial_result,
)
from app.evaluation.counterfactual.eligibility import ReplayEligibility, select_replay_intervention
from app.evaluation.counterfactual.policy import COUNTERFACTUAL_REPLAY_POLICY, CounterfactualReplayPolicy
from app.evaluation.ground_truth.matcher import IndependentBenchmarkJudge
from app.evaluation.ground_truth.schemas import BenchmarkCase, EvaluationStage, ExpectedVerdict
from app.evaluation.system.schemas import FailureAttribution, FailureClass, SystemEvalMode
from app.llm.economy import WorkflowCloudBudget, bind_workflow_cloud_budget, reset_workflow_cloud_budget
from app.schemas.enums import VerificationVerdict
from app.schemas.finding import Finding


_HARD_SAFETY_CODES = frozenset({
    "UNAUTHORIZED_TOOL_EXECUTED", "CROSS_SNAPSHOT_EVIDENCE", "SECRET_EXPOSURE",
    "WRITE_CAPABILITY_EXECUTED", "CANDIDATE_IDENTITY_MISMATCH", "UNSUPPORTED_CONFIRMED_FINDING",
})


class _ReplayGuardError(RuntimeError):
    """A local, content-free reason that invalidates a replay transition."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "value"):
        return _jsonable(value.value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(type(value).__name__)


def _get(value: Any, name: str, default: Any = None) -> Any:
    return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)


def _finding_id(value: Any) -> str:
    return str(_get(value, "id", "") or "")


def _recorded_model_pairs(state: Mapping[str, Any]) -> tuple[set[tuple[str, str]], bool]:
    executions = state.get("model_executions")
    if not isinstance(executions, list) or not executions:
        return set(), False
    pairs: set[tuple[str, str]] = set()
    for execution in executions:
        provider = _get(execution, "provider")
        model = _get(execution, "model_name") or _get(execution, "model")
        if not provider or not model:
            return pairs, False
        pairs.add((str(getattr(provider, "value", provider)).lower(), str(model)))
    return pairs, True


def _unmeasured(unit: str) -> ReplayMetric:
    return ReplayMetric(status=ReplayMetricStatus.NOT_MEASURED, value=None, unit=unit)


def _measured(value: float, unit: str) -> ReplayMetric:
    return ReplayMetric(status=ReplayMetricStatus.MEASURED, value=value, unit=unit)


def _outcome_for_state(
    case: BenchmarkCase,
    state: Mapping[str, Any],
    judge: IndependentBenchmarkJudge,
    *,
    intervened_node: str | None = None,
) -> ReplayOutcomeMetrics:
    # Import lazily to keep the evaluator module independent of graph runtime
    # construction and to use the exact same canonical output projection.
    from app.evaluation.system.full_analysis import (
        _evaluated_findings,
        _trial_failure_codes,
        _workflow_trace,
    )

    stage = EvaluationStage(case.evaluation_stage)
    predictions = _evaluated_findings(dict(state), stage)
    published_predictions = _evaluated_findings(dict(state), EvaluationStage.PUBLISHED_FINDING)
    files = set(case.fixture.files)
    lines = {path: len(content.splitlines()) for path, content in case.fixture.files.items()}
    explicit_abstention = (
        str((state.get("investigator") or {}).get("active", {}).get("stop_reason", ""))
        == "INSUFFICIENT_EVIDENCE"
    )
    judged = judge.evaluate_case(
        case, predictions, files, lines, explicit_abstention=explicit_abstention,
    )
    published = judge.evaluate_case(case, published_predictions, files, lines)
    if judged.expected_verdict == ExpectedVerdict.ISSUE:
        task_success = judged.fn == 0 and judged.fp == 0
    elif judged.expected_verdict == ExpectedVerdict.CLEAN:
        task_success = judged.clean_case_tn
    else:
        task_success = (
            judged.fp == 0 and judged.abstention_outcome is not None
            and judged.abstention_outcome.value in {
                "EXPLICIT_CORRECT_ABSTENTION", "NO_POSITIVE_PUBLICATION",
            }
        )
    # The factual event for the node whose output was substituted remains in
    # the branch's audit prefix. Its original failure codes describe the
    # factual output, however, and must not be attributed to this counterfactual
    # projection. All upstream and downstream events remain authoritative.
    trace_state = dict(state)
    if intervened_node is not None:
        raw_trace = trace_state.get("workflow_trace", [])
        if isinstance(raw_trace, list):
            replaced_index = next((
                index for index in range(len(raw_trace) - 1, -1, -1)
                if isinstance(raw_trace[index], Mapping)
                and raw_trace[index].get("node") == intervened_node
            ), None)
            if replaced_index is not None:
                trace_state["workflow_trace"] = [
                    event for index, event in enumerate(raw_trace) if index != replaced_index
                ]
    trace = _workflow_trace(trace_state)
    failure_codes = set(_trial_failure_codes(dict(state), trace))
    if published.fp > 0:
        failure_codes.add("UNSUPPORTED_CONFIRMED_FINDING")
    hard_safety = bool(failure_codes & _HARD_SAFETY_CODES)
    # Invalid references are never a rescue, even on rule-scoped clean cases.
    task_success = bool(
        task_success
        and judged.invalid_reference_count == 0
        and published.invalid_reference_count == 0
        and not hard_safety
        and state.get("status") != "FAILED"
        and not (failure_codes & {"BUDGET_EXHAUSTION", "MODEL_PROVIDER_FAILURE", "MODEL_PROVIDER_TIMEOUT"})
    )
    return ReplayOutcomeMetrics(
        success=task_success,
        tp=judged.tp,
        fp=judged.fp,
        fn=judged.fn,
        unsupported_claims=max(judged.unsupported_claim_count, published.unsupported_claim_count),
        invalid_references=judged.invalid_reference_count + published.invalid_reference_count,
        hard_safety_violation=hard_safety,
    )


def _classify_effect(factual: ReplayOutcomeMetrics, counterfactual: ReplayOutcomeMetrics) -> CounterfactualEffect:
    if not factual.success and counterfactual.success:
        return CounterfactualEffect.FULL_RESCUE
    regressed = (
        (factual.success and not counterfactual.success)
        or (counterfactual.hard_safety_violation and not factual.hard_safety_violation)
        or counterfactual.fp > factual.fp
        or counterfactual.fn > factual.fn
        or counterfactual.unsupported_claims > factual.unsupported_claims
        or counterfactual.invalid_references > factual.invalid_references
        or counterfactual.tp < factual.tp
    )
    if regressed:
        return CounterfactualEffect.REGRESSION
    improved = (
        (counterfactual.success and not factual.success)
        or counterfactual.hard_safety_violation < factual.hard_safety_violation
        or counterfactual.tp > factual.tp
        or counterfactual.fp < factual.fp
        or counterfactual.fn < factual.fn
        or counterfactual.unsupported_claims < factual.unsupported_claims
        or counterfactual.invalid_references < factual.invalid_references
    )
    return CounterfactualEffect.PARTIAL_RESCUE if improved else CounterfactualEffect.NO_EFFECT


def _safe_trace_events(events: list[Any]) -> tuple[ReplayTraceEvent, ...]:
    from app.evaluation.system.full_analysis import _workflow_trace

    safe = []
    for event in _workflow_trace({"workflow_trace": events})[-32:]:
        safe.append(ReplayTraceEvent(
            node=event.node,
            status=event.status,
            input_digest=event.input_digest,
            output_digest=event.output_digest,
            model_calls=event.model_execution_count or len(event.model_identities),
            tool_calls=event.tool_execution_count,
            failure_codes=tuple(event.failure_codes[:16]),
        ))
    return tuple(safe)


def _branch_tool_call_count(
    runtime_context: Any,
    checkpoint_values: Mapping[str, Any],
    trace_events: tuple[Any, ...] | list[Any] = (),
) -> int:
    """Count replay attempts without double-counting MCP events and traces."""
    executor = getattr(runtime_context, "mcp_executor", None)
    records = getattr(executor, "execution_records", []) if executor is not None else []
    checkpoint_count = checkpoint_values.get("mcp_call_count", 0)
    try:
        mcp_delta = max(0, len(records) - max(0, int(checkpoint_count or 0)))
    except (TypeError, ValueError):
        mcp_delta = 0
    trace_count = 0
    for event in trace_events:
        value = _get(event, "tool_execution_count", 0)
        try:
            trace_count += max(0, int(value or 0))
        except (TypeError, ValueError):
            continue
    return max(mcp_delta, trace_count)


def _all_attested_candidate_ids(values: Mapping[str, Any], runtime_context: Any) -> set[str]:
    attested: set[str] = set()
    repo_dir = runtime_context.scan_runtime.repo_dir
    commit_hash = str(values.get("commit_hash") or "")
    for candidate in values.get("candidate_findings", [])[:128]:
        candidate_id = _finding_id(candidate)
        evidences = _get(candidate, "evidences", []) or []
        evidence = evidences[0] if evidences else None
        if not candidate_id or evidence is None:
            continue
        attestation, _ = _attest_repository_evidence(
            repo_dir,
            str(_get(evidence, "file_path", "") or ""),
            _get(evidence, "start_line"),
            _get(evidence, "end_line"),
            commit_hash,
        )
        if attestation is not None:
            attested.add(candidate_id)
    return attested


def _route_projection(
    values: Mapping[str, Any],
    rejected: list[dict[str, Any]],
    runtime_context: Any,
) -> tuple[str, list[str]]:
    targets: set[str] = set()
    for item in rejected:
        finding_id = str(item.get("finding_id") or "")
        if item.get("verdict") == VerificationVerdict.POSSIBLE.value:
            targets.add(finding_id)
    attested = _all_attested_candidate_ids(values, runtime_context)
    targets &= attested
    missing_eval = any(
        item.get("verdict") == VerificationVerdict.POSSIBLE.value
        and "no valid evaluation" in str(item.get("reason", "")).lower()
        for item in rejected
    )
    infrastructure_failure = bool(values.get("errors"))
    return resolve_verification_routing(
        rejected,
        attested,
        has_infrastructure_failure=infrastructure_failure,
        has_missing_eval=missing_eval,
    )


def _state_patch(
    kind: CounterfactualInterventionKind,
    values: Mapping[str, Any],
    target_id: str,
    runtime_context: Any,
    pre_revision_values: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    if kind == CounterfactualInterventionKind.VERIFIER_ACCEPT_MATCHED_FINDING:
        candidates = [item for item in values.get("candidate_findings", []) if _finding_id(item) == target_id]
        rejected = [item for item in values.get("rejected_findings", []) if str(item.get("finding_id") or "") == target_id]
        if len(candidates) != 1 or len(rejected) != 1:
            return None, "TARGET_NOT_UNIQUE_IN_VERIFIER_STATE"
        verified = copy.deepcopy(list(values.get("verified_findings", [])))
        if any(_finding_id(item) == target_id for item in verified):
            return None, "TARGET_ALREADY_VERIFIED"
        candidate = copy.deepcopy(candidates[0])
        if isinstance(candidate, Mapping):
            candidate = Finding.model_validate(candidate)
        candidate.verification_verdict = VerificationVerdict.CONFIRMED
        candidate.verification_reason = "Evaluator-owned counterfactual substitution; not a production verifier decision."
        verified.append(candidate)
        remaining_rejected = [
            copy.deepcopy(item) for item in values.get("rejected_findings", [])
            if str(item.get("finding_id") or "") != target_id
        ]
        decision, targets = _route_projection(values, remaining_rejected, runtime_context)
        return {
            "verified_findings": verified,
            "rejected_findings": remaining_rejected,
            "verification_decision": decision,
            "revision_target_ids": targets,
        }, "BUILT"

    if kind == CounterfactualInterventionKind.VERIFIER_REJECT_UNSUPPORTED_FINDING:
        verified = [
            copy.deepcopy(item) for item in values.get("verified_findings", [])
            if _finding_id(item) != target_id
        ]
        if len(values.get("verified_findings", [])) - len(verified) != 1:
            return None, "TARGET_NOT_UNIQUE_IN_VERIFIED_STATE"
        rejected = [copy.deepcopy(item) for item in values.get("rejected_findings", [])]
        if any(str(item.get("finding_id") or "") == target_id for item in rejected):
            return None, "TARGET_ALREADY_REJECTED"
        rejected.append({
            "finding_id": target_id,
            "verdict": VerificationVerdict.REJECTED.value,
            "reason": "Evaluator-owned counterfactual rejection; no benchmark answer was copied into graph state.",
        })
        decision, targets = _route_projection(values, rejected, runtime_context)
        return {
            "verified_findings": verified,
            "rejected_findings": rejected,
            "verification_decision": decision,
            "revision_target_ids": targets,
        }, "BUILT"

    if kind == CounterfactualInterventionKind.REVISION_RESTORE_VALID_CANDIDATE:
        if not isinstance(pre_revision_values, Mapping):
            return None, "PRE_REVISION_CHECKPOINT_REQUIRED"
        originals = [
            item for item in pre_revision_values.get("candidate_findings", [])
            if _finding_id(item) == target_id
        ]
        if len(originals) != 1:
            return None, "PRE_REVISION_CANDIDATE_NOT_UNIQUE"
        current_outputs = [
            item for item in values.get("revision_candidates", [])
            if _finding_id(item) == target_id
        ]
        if len(current_outputs) != 1:
            return None, "REVISION_OUTPUT_NOT_UNIQUE"
        from app.evaluation.counterfactual.contracts import canonical_digest

        if canonical_digest(_jsonable(current_outputs[0])) == canonical_digest(_jsonable(originals[0])):
            return None, "REVISION_OUTPUT_UNCHANGED"
        revision_outputs = [
            copy.deepcopy(item) for item in values.get("revision_candidates", [])
            if _finding_id(item) != target_id
        ]
        restored = copy.deepcopy(originals[0])
        if isinstance(restored, Mapping):
            restored = Finding.model_validate(restored)
        revision_outputs.append(restored)
        return {"revision_candidates": revision_outputs}, "BUILT"

    return None, "POLICY_BLOCKED"


def _metric_sum(results: list[Any], field: str, unit: str) -> ReplayMetric:
    attempted = [item for item in results if item.replay_index is not None]
    metrics = [getattr(item, field) for item in attempted]
    if not metrics or any(item.status != ReplayMetricStatus.MEASURED for item in metrics):
        return _unmeasured(unit)
    return _measured(sum(float(item.value or 0.0) for item in metrics), unit)


class CounterfactualReplayCoordinator:
    """One-run hard cap owner; no report or graph state is retained globally."""

    def __init__(
        self,
        *,
        mode: SystemEvalMode,
        expected_provider: Any,
        expected_model: str,
        allowed_case_digests: Mapping[str, str],
        policy: CounterfactualReplayPolicy = COUNTERFACTUAL_REPLAY_POLICY,
    ) -> None:
        self.mode = SystemEvalMode(mode)
        self.expected_provider = expected_provider
        self.expected_model = expected_model
        self.allowed_case_digests = dict(allowed_case_digests)
        self.policy = policy
        self.started = time.monotonic()
        self.results: list[Any] = []
        self.trials_attempted: set[tuple[str, int]] = set()
        self.total_branches = 0
        self.total_model_calls = 0

    def _remaining_seconds(self) -> float:
        return max(0.0, self.policy.max_wall_clock_seconds - (time.monotonic() - self.started))

    def _result(
        self,
        *,
        case: BenchmarkCase,
        trial_number: int,
        failure_class: str | None,
        status: str,
        effect: CounterfactualEffect,
        reason_code: str,
        intervention: Any = None,
        factual: ReplayOutcomeMetrics | None = None,
        counterfactual: ReplayOutcomeMetrics | None = None,
        replay_index: int | None = None,
        target_digest: str | None = None,
        trace: tuple[ReplayTraceEvent, ...] = (),
        model_calls: int = 0,
        tool_calls: int = 0,
        input_tokens: ReplayMetric | None = None,
        output_tokens: ReplayMetric | None = None,
        cost_usd: ReplayMetric | None = None,
        duration_ms: float = 0.0,
    ) -> Any:
        result = make_trial_result(
            case_id=case.case_id,
            trial_number=trial_number,
            failure_class=failure_class,
            execution_status=status,
            effect=effect,
            reason_code=reason_code,
            intervention=intervention,
            factual=factual,
            counterfactual=counterfactual,
            replay_index=replay_index,
            target_finding_digest=target_digest,
            downstream_nodes=tuple(item.node for item in trace),
            trace=trace,
            model_calls=model_calls,
            tool_calls=tool_calls,
            input_tokens=input_tokens or _unmeasured("tokens"),
            output_tokens=output_tokens or _unmeasured("tokens"),
            cost_usd=cost_usd or _unmeasured("USD"),
            duration_ms=duration_ms,
        )
        self.results.append(result)
        return result

    def record_unexpected_failure(
        self,
        *,
        case: BenchmarkCase,
        trial_number: int,
        factual_state: Mapping[str, Any],
        judge: IndependentBenchmarkJudge,
    ) -> Any:
        """Retain a bounded diagnostic when evaluator orchestration itself fails."""
        return self._result(
            case=case,
            trial_number=trial_number,
            failure_class=None,
            status="INCONCLUSIVE",
            effect=CounterfactualEffect.INCONCLUSIVE,
            reason_code="REPLAY_CALLBACK_FAILURE",
            factual=_outcome_for_state(case, factual_state, judge),
        )

    def build_report(
        self,
        *,
        factual_report_digest: str,
        system_identity: Any,
    ) -> Any:
        completed = [item for item in self.results if item.execution_status == "COMPLETED"]
        rescue_rate = (
            _measured(
                sum(item.effect == CounterfactualEffect.FULL_RESCUE for item in completed) / len(completed),
                "proportion",
            )
            if completed else _unmeasured("proportion")
        )
        return make_replay_report(
            factual_report_digest=factual_report_digest,
            system_identity_digest=system_identity.system_digest,
            graph_identity_digest=system_identity.graph_identity_digest,
            evaluation_contract_hash=system_identity.evaluation_contract_hash,
            execution_mode=(
                "LIVE_DIAGNOSTIC" if self.mode == SystemEvalMode.LIVE
                else "SCRIPTED_HARNESS_VALIDATION_ONLY"
            ),
            policy_version=self.policy.version,
            trial_results=tuple(self.results),
            replayable_trials=len({(item.case_id, item.trial_number) for item in completed}),
            not_replayable_trials=sum(item.effect == CounterfactualEffect.NOT_REPLAYABLE for item in self.results),
            attempted_branches=sum(item.replay_index is not None for item in self.results),
            full_rescues=sum(item.effect == CounterfactualEffect.FULL_RESCUE for item in completed),
            partial_rescues=sum(item.effect == CounterfactualEffect.PARTIAL_RESCUE for item in completed),
            no_effect=sum(item.effect == CounterfactualEffect.NO_EFFECT for item in completed),
            regressions=sum(item.effect == CounterfactualEffect.REGRESSION for item in completed),
            inconclusive=sum(item.effect == CounterfactualEffect.INCONCLUSIVE for item in self.results),
            invalid_replays=sum(item.effect == CounterfactualEffect.INVALID_REPLAY for item in self.results),
            rescue_rate=rescue_rate,
            total_model_calls=sum(item.model_calls for item in self.results),
            total_tool_calls=sum(item.tool_calls for item in self.results),
            total_input_tokens=_metric_sum(self.results, "input_tokens", "tokens"),
            total_output_tokens=_metric_sum(self.results, "output_tokens", "tokens"),
            total_cost_usd=_metric_sum(self.results, "cost_usd", "USD"),
        )

    async def replay_trial(
        self,
        *,
        case: BenchmarkCase,
        trial_number: int,
        factual_state: Mapping[str, Any],
        attribution: FailureAttribution | None,
        judged: Any,
        published_judged: Any,
        judge: IndependentBenchmarkJudge,
        graph: Any,
        factual_config: Mapping[str, Any],
        runtime_context: Any,
        fixture: Any,
        system_identity: Any,
    ) -> tuple[Any, ...]:
        from app.evaluation.counterfactual.contracts import canonical_digest

        allowed_digest = self.allowed_case_digests.get(case.case_id)
        if (
            allowed_digest is None
            or canonical_digest(case.model_dump(mode="json")) != allowed_digest
        ):
            return (self._result(
                case=case,
                trial_number=trial_number,
                failure_class=attribution.failure_class.value if attribution is not None else None,
                status="NOT_REPLAYABLE",
                effect=CounterfactualEffect.NOT_REPLAYABLE,
                reason_code="CASE_OUTSIDE_PUBLIC_RUN_INVENTORY",
            ),)
        factual = _outcome_for_state(case, factual_state, judge)
        eligibility = select_replay_intervention(
            case,
            factual_state,
            attribution,
            judged=judged,
            published_judged=published_judged,
            judge=judge,
        )
        failure_name = attribution.failure_class.value if attribution is not None else None
        if not eligibility.eligible:
            return (self._result(
                case=case,
                trial_number=trial_number,
                failure_class=failure_name,
                status="NOT_REPLAYABLE",
                effect=CounterfactualEffect.NOT_REPLAYABLE,
                reason_code=eligibility.reason_code[:64],
                factual=factual,
            ),)

        if self.mode == SystemEvalMode.LIVE:
            expected_pair = (
                str(getattr(self.expected_provider, "value", self.expected_provider) or "").lower(),
                self.expected_model,
            )
            factual_pairs, factual_identity_measured = _recorded_model_pairs(factual_state)
            if not factual_identity_measured or not expected_pair[0] or not expected_pair[1] or factual_pairs != {expected_pair}:
                return (self._result(
                    case=case,
                    trial_number=trial_number,
                    failure_class=attribution.failure_class.value if attribution is not None else None,
                    status="INVALID_REPLAY",
                    effect=CounterfactualEffect.INVALID_REPLAY,
                    reason_code="FACTUAL_MODEL_IDENTITY_UNVERIFIED",
                    factual=factual,
                ),)

        trial_key = (case.case_id, trial_number)
        if trial_key in self.trials_attempted or len(self.trials_attempted) >= self.policy.max_trials_per_run:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                reason_code="RUN_TRIAL_LIMIT", factual=factual,
            ),)
        if self._remaining_seconds() <= 0:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                reason_code="WALL_CLOCK_LIMIT", factual=factual,
            ),)

        from app.evaluation.system.identity import (
            full_analysis_evaluation_contract_hash,
            full_analysis_graph_identity_digest,
        )

        if (
            system_identity.scope != "FULL_ANALYSIS_GRAPH"
            or system_identity.graph_identity_digest is None
            or system_identity.graph_identity_digest != full_analysis_graph_identity_digest()
            or system_identity.evaluation_contract_hash != full_analysis_evaluation_contract_hash(
                system_identity.graph_identity_digest
            )
        ):
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                reason_code="SYSTEM_IDENTITY_INVALID", factual=factual,
            ),)
        if str(factual_state.get("commit_hash") or "") != fixture.snapshot_id:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                reason_code="STALE_SNAPSHOT", factual=factual,
            ),)

        target_id = eligibility.target_finding_id
        assert target_id and eligibility.target_node and eligibility.intervention_kind
        try:
            checkpoint, checkpoint_reason = await asyncio.wait_for(
                locate_factual_checkpoint(
                    graph,
                    factual_config,
                    target_node=eligibility.target_node,
                    target_finding_id=target_id,
                    expected_snapshot_id=fixture.snapshot_id,
                    max_history=self.policy.max_history_checkpoints,
                ),
                timeout=self._remaining_seconds(),
            )
        except asyncio.TimeoutError:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                reason_code="WALL_CLOCK_LIMIT", factual=factual,
            ),)
        if checkpoint is None:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                reason_code=checkpoint_reason, factual=factual,
            ),)
        checkpoint_values = getattr(checkpoint, "values", None)
        if not isinstance(checkpoint_values, Mapping):
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                reason_code="CHECKPOINT_STATE_INVALID", factual=factual,
            ),)
        checkpoint_config = getattr(checkpoint, "config", None)
        checkpoint_digest = checkpoint_id_digest(checkpoint_config or {})
        if checkpoint_digest is None:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                reason_code="CHECKPOINT_ID_MISSING", factual=factual,
            ),)

        pre_revision_checkpoint = None
        pre_revision_values = None
        if eligibility.intervention_kind == CounterfactualInterventionKind.REVISION_RESTORE_VALID_CANDIDATE.value:
            try:
                pre_revision_checkpoint, pre_reason = await asyncio.wait_for(
                    locate_pre_revision_checkpoint(
                        graph,
                        factual_config,
                        target_finding_id=target_id,
                        expected_snapshot_id=fixture.snapshot_id,
                        max_history=self.policy.max_history_checkpoints,
                    ),
                    timeout=self._remaining_seconds(),
                )
            except asyncio.TimeoutError:
                return (self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                    reason_code="WALL_CLOCK_LIMIT", factual=factual,
                ),)
            if pre_revision_checkpoint is None:
                return (self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                    reason_code=pre_reason, factual=factual,
                ),)
            pre_revision_values = getattr(pre_revision_checkpoint, "values", None)
            if not isinstance(pre_revision_values, Mapping):
                return (self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                    reason_code="PRE_REVISION_STATE_INVALID", factual=factual,
                ),)

        kind = CounterfactualInterventionKind(eligibility.intervention_kind)
        patch, patch_status = _state_patch(
            kind,
            checkpoint_values,
            target_id,
            runtime_context,
            pre_revision_values,
        )
        if patch is None:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="NOT_REPLAYABLE", effect=CounterfactualEffect.NOT_REPLAYABLE,
                reason_code=patch_status, factual=factual,
            ),)

        if self.mode == SystemEvalMode.SCRIPTED and eligibility.target_node == "verifier":
            from app.agents.graph import route_after_verifier

            projected_state = dict(checkpoint_values)
            projected_state.update(patch)
            if route_after_verifier(projected_state) == "investigate":
                return (self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                    reason_code="SCRIPTED_PATH_EXCEEDS_MODEL_CALL_BOUND", factual=factual,
                ),)

        field_order = (
            "verified_findings", "rejected_findings", "revision_candidates",
            "revision_count", "verification_decision", "revision_target_ids",
        )
        changed_fields = tuple(name for name in field_order if name in patch)
        before_projection = {name: _jsonable(checkpoint_values.get(name)) for name in changed_fields}
        after_projection = {name: _jsonable(patch[name]) for name in changed_fields}
        attribution_data = _jsonable(attribution.model_dump(mode="json")) if attribution is not None else None
        from app.evaluation.counterfactual.contracts import canonical_digest
        from app.evaluation.agent.loader import canonical_json

        factual_trial_digest = hashlib.sha256(
            canonical_json({
                "case_id": case.case_id,
                "trial_number": trial_number,
                "state_digest": checkpoint_state_digest(factual_state),
                "attribution": attribution_data,
                "outcome": factual.model_dump(mode="json"),
            }).encode("utf-8")
        ).hexdigest()
        intervention = make_intervention(
            intervention_kind=kind,
            case_id=case.case_id,
            trial_number=trial_number,
            failure_class=failure_name or "UNKNOWN_ATTRIBUTION",
            target_node=eligibility.target_node,
            target_finding_digest=canonical_digest({"finding_id": target_id}),
            snapshot_id=fixture.snapshot_id,
            factual_trial_digest=factual_trial_digest,
            checkpoint_id_digest=checkpoint_digest,
            checkpoint_state_digest=checkpoint_state_digest(checkpoint_values),
            system_identity_digest=system_identity.system_digest,
            graph_identity_digest=system_identity.graph_identity_digest,
            evaluation_contract_hash=system_identity.evaluation_contract_hash,
            before_state_projection_digest=canonical_digest(before_projection),
            changed_state_projection_digest=canonical_digest(after_projection),
            state_fields_changed=changed_fields,
        )

        factual_trace = _jsonable(checkpoint_values.get("workflow_trace", []))
        factual_final_trace = _jsonable(factual_state.get("workflow_trace", []))
        if factual_final_trace[:len(factual_trace)] != factual_trace:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                reason_code="FACTUAL_TRACE_PREFIX_MISMATCH", intervention=intervention,
                factual=factual,
            ),)
        if self.mode == SystemEvalMode.LIVE and str(
            getattr(self.expected_provider, "value", self.expected_provider)
        ).lower() == "ollama":
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="NOT_REPLAYABLE", effect=CounterfactualEffect.NOT_REPLAYABLE,
                reason_code="LOCAL_PROVIDER_CALL_LIMIT_UNENFORCEABLE", factual=factual,
            ),)

        branches = (
            self.policy.live_branches_per_intervention
            if self.mode == SystemEvalMode.LIVE
            else self.policy.scripted_branches_per_intervention
        )
        branches = min(branches, self.policy.max_total_branches_per_run - self.total_branches)
        if branches <= 0:
            return (self._result(
                case=case, trial_number=trial_number, failure_class=failure_name,
                status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                reason_code="RUN_BRANCH_LIMIT", intervention=intervention, factual=factual,
            ),)
        self.trials_attempted.add(trial_key)
        output_results = []
        for replay_index in range(1, branches + 1):
            remaining_seconds = self._remaining_seconds()
            remaining_model_calls = self.policy.max_total_replay_model_calls - self.total_model_calls
            if remaining_seconds <= 0 or remaining_model_calls < 0:
                output_results.append(self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                    reason_code="REPLAY_RESOURCE_LIMIT", intervention=intervention,
                    factual=factual, replay_index=None,
                ))
                break
            if self.total_branches >= self.policy.max_total_branches_per_run:
                break
            branch_started = time.perf_counter()
            branch_budget = WorkflowCloudBudget.from_snapshot(checkpoint_values.get("ai_cloud_budget"))
            call_allowance = min(self.policy.max_replay_model_calls_per_branch, remaining_model_calls)
            token_allowance = self.policy.max_replay_tokens_per_branch
            branch_budget.max_cloud_calls = min(
                branch_budget.max_cloud_calls,
                branch_budget.used_cloud_calls + call_allowance,
            )
            branch_budget.max_cloud_tokens = min(
                branch_budget.max_cloud_tokens,
                branch_budget.used_cloud_tokens + token_allowance,
            )
            branch_call_start = branch_budget.used_cloud_calls
            budget_token = bind_workflow_cloud_budget(branch_budget)
            branch_runtime_context = runtime_context
            try:
                branch_config = await asyncio.wait_for(
                    graph.aupdate_state(
                        checkpoint_config,
                        copy.deepcopy(patch),
                        as_node=eligibility.target_node,
                    ),
                    timeout=min(10.0, self._remaining_seconds()),
                )
                if not isinstance(branch_config, Mapping) or checkpoint_id_digest(branch_config) is None:
                    raise _ReplayGuardError("BRANCH_CONFIG_INVALID")
                branch_base = await asyncio.wait_for(
                    graph.aget_state(branch_config),
                    timeout=min(10.0, self._remaining_seconds()),
                )
                branch_base_values = getattr(branch_base, "values", None)
                if not isinstance(branch_base_values, Mapping):
                    raise _ReplayGuardError("BRANCH_STATE_INVALID")
                if str(branch_base_values.get("commit_hash") or "") != fixture.snapshot_id:
                    raise _ReplayGuardError("BRANCH_SNAPSHOT_MISMATCH")
                if _jsonable(branch_base_values.get("workflow_trace", [])) != factual_trace:
                    raise _ReplayGuardError("BRANCH_PREFIX_MISMATCH")
                if eligibility.target_node == "verifier":
                    from app.agents.graph import route_after_verifier
                    expected_route = route_after_verifier(branch_base_values)
                    expected_node = {
                        "finalize": "finalize",
                        "revise": "mcp_enrich",
                        "investigate": "investigator_prepare",
                        "finalize_uncertain": "finalize_uncertain",
                    }[expected_route]
                else:
                    expected_node = "verifier"
                if tuple(branch_base.next or ()) != (expected_node,):
                    raise _ReplayGuardError("BRANCH_ROUTING_MISMATCH")
                factual_executor = getattr(runtime_context, "mcp_executor", None)
                if factual_executor is not None:
                    fork = getattr(factual_executor, "fork", None)
                    if not callable(fork):
                        raise _ReplayGuardError("MCP_EXECUTOR_NOT_FORKABLE")
                    branch_runtime_context = replace(
                        runtime_context,
                        mcp_executor=fork(checkpoint_values),
                    )
                branch_state = await asyncio.wait_for(
                    graph.ainvoke(None, config=branch_config, context=branch_runtime_context),
                    timeout=self._remaining_seconds(),
                )
            except asyncio.TimeoutError:
                reserved_model_calls = max(0, branch_budget.used_cloud_calls - branch_call_start)
                self.total_model_calls += reserved_model_calls
                output_results.append(self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INCONCLUSIVE", effect=CounterfactualEffect.INCONCLUSIVE,
                    reason_code="REPLAY_TIMEOUT", intervention=intervention,
                    factual=factual, replay_index=replay_index,
                    model_calls=reserved_model_calls,
                    tool_calls=_branch_tool_call_count(branch_runtime_context, checkpoint_values),
                    duration_ms=(time.perf_counter() - branch_started) * 1000.0,
                ))
                self.total_branches += 1
                break
            except Exception as exc:
                reserved_model_calls = max(0, branch_budget.used_cloud_calls - branch_call_start)
                self.total_model_calls += reserved_model_calls
                output_results.append(self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                    reason_code=(
                        exc.reason_code if isinstance(exc, _ReplayGuardError)
                        else "BRANCH_TRANSITION_REJECTED"
                    ),
                    intervention=intervention, factual=factual,
                    replay_index=replay_index,
                    model_calls=reserved_model_calls,
                    tool_calls=_branch_tool_call_count(branch_runtime_context, checkpoint_values),
                    duration_ms=(time.perf_counter() - branch_started) * 1000.0,
                ))
                self.total_branches += 1
                break
            finally:
                reset_workflow_cloud_budget(budget_token)

            branch_state = dict(branch_state)
            branch_trace = _jsonable(branch_state.get("workflow_trace", []))
            model_executions = branch_state.get("model_executions", [])
            prior_model_executions = checkpoint_values.get("model_executions", [])
            replay_executions = (
                list(model_executions)[len(prior_model_executions):]
                if isinstance(model_executions, list) else []
            )
            model_calls = len(replay_executions)
            if self.mode == SystemEvalMode.LIVE:
                model_calls = max(
                    model_calls,
                    branch_budget.used_cloud_calls - branch_call_start,
                )
            # Account usage before any post-run integrity rejection so an
            # invalid branch cannot free global call allowance for a retry.
            self.total_model_calls += model_calls
            observed_tools = _branch_tool_call_count(
                branch_runtime_context,
                checkpoint_values,
                branch_trace[len(factual_trace):] if isinstance(branch_trace, list) else (),
            )
            if not isinstance(branch_trace, list) or branch_trace[:len(factual_trace)] != factual_trace:
                output_results.append(self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                    reason_code="BRANCH_TRACE_PREFIX_MISMATCH", intervention=intervention,
                    factual=factual, replay_index=replay_index,
                    model_calls=model_calls,
                    tool_calls=observed_tools,
                ))
                self.total_branches += 1
                break
            suffix_raw = branch_trace[len(factual_trace):]
            trace = _safe_trace_events(suffix_raw)
            executed_nodes = tuple(item.node for item in trace)
            if eligibility.target_node == "verifier" and (
                any(node in {"mapper", "architecture", "integration", "security", "bug", "verifier"} for node in executed_nodes)
            ):
                output_results.append(self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                    reason_code="UPSTREAM_NODE_REEXECUTED", intervention=intervention,
                    factual=factual, replay_index=replay_index, trace=trace,
                    model_calls=model_calls,
                    tool_calls=observed_tools,
                ))
                self.total_branches += 1
                break
            actual_pairs = set()
            for execution in replay_executions:
                provider = _get(execution, "provider")
                model = _get(execution, "model_name") or _get(execution, "model")
                if provider and model:
                    actual_pairs.add((str(getattr(provider, "value", provider)).lower(), str(model)))
            expected_pair = (
                str(getattr(self.expected_provider, "value", self.expected_provider)).lower(),
                self.expected_model,
            )
            if self.mode == SystemEvalMode.LIVE and model_calls > 0 and actual_pairs != {expected_pair}:
                output_results.append(self._result(
                    case=case, trial_number=trial_number, failure_class=failure_name,
                    status="INVALID_REPLAY", effect=CounterfactualEffect.INVALID_REPLAY,
                    reason_code="MODEL_IDENTITY_CHANGED", intervention=intervention,
                    factual=factual, replay_index=replay_index, trace=trace,
                    model_calls=model_calls,
                ))
                self.total_branches += 1
                break
            counterfactual = _outcome_for_state(
                case, branch_state, judge, intervened_node=eligibility.target_node,
            )
            effect = _classify_effect(factual, counterfactual)
            from app.evaluation.system.full_analysis import _trial_usage_metrics

            input_metric, output_metric, cost_metric, _, _ = _trial_usage_metrics(
                replay_executions,
                model_calls=model_calls,
                mode=self.mode,
                provider_usage_unknown=False,
            )
            output_results.append(self._result(
                case=case,
                trial_number=trial_number,
                failure_class=failure_name,
                status="COMPLETED",
                effect=effect,
                reason_code="CORRECTIVE_REPLAY_COMPLETED",
                intervention=intervention,
                factual=factual,
                counterfactual=counterfactual,
                replay_index=replay_index,
                target_digest=intervention.target_finding_digest,
                trace=trace,
                model_calls=model_calls,
                tool_calls=observed_tools,
                input_tokens=ReplayMetric(
                    status=ReplayMetricStatus(input_metric.status.value),
                    value=input_metric.value,
                    unit=input_metric.unit,
                ),
                output_tokens=ReplayMetric(
                    status=ReplayMetricStatus(output_metric.status.value),
                    value=output_metric.value,
                    unit=output_metric.unit,
                ),
                cost_usd=ReplayMetric(
                    status=ReplayMetricStatus(cost_metric.status.value),
                    value=cost_metric.value,
                    unit=cost_metric.unit,
                ),
                duration_ms=(time.perf_counter() - branch_started) * 1000.0,
            ))
            self.total_branches += 1
        return tuple(output_results)


__all__ = ["CounterfactualReplayCoordinator"]
