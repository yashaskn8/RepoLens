"""Bounded SQL-authoritative service-level measurements for agent operations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.execution.types import ExecutionState, WorkKind
from app.models.ai_execution import AIExecutionModel
from app.models.change_analysis import ChangeAnalysisModel
from app.models.execution import FailureRecordModel, WorkItemModel, WorkLeaseModel
from app.models.platform import OutboxEventModel, ReconciliationRecordModel


SLO_POLICY_VERSION = "agent-operations-slo-policy/1.0"
SLI_CLASSIFICATION_VERSION = "agent-operations-sli-classification/1.0"
SLO_REPORT_SCHEMA_VERSION = "agent-operations-slo-report/1.0"
MAX_LATENCY_SAMPLES = 2_000
_WINDOWS: dict[str, timedelta] = {
    "5m": timedelta(minutes=5),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
_SLICES = frozenset({
    "work_reliability",
    "github_automation_reliability",
    "provider_reliability",
})
_TERMINAL = (
    ExecutionState.SUCCEEDED.value,
    ExecutionState.FAILED.value,
    ExecutionState.CANCELLED.value,
    ExecutionState.TIMED_OUT.value,
)
_GITHUB_KINDS = frozenset({WorkKind.GITHUB_DELIVERY.value, WorkKind.REVIEW_PUBLICATION.value})


class SLOMode(str, Enum):
    OBSERVE = "OBSERVE"
    ENFORCED = "ENFORCED"


class SLIStatus(str, Enum):
    OBSERVATION_ONLY = "OBSERVATION_ONLY"
    NO_DATA = "NO_DATA"
    INSUFFICIENT_SAMPLE = "INSUFFICIENT_SAMPLE"
    OBJECTIVE_MET = "OBJECTIVE_MET"
    OBJECTIVE_BREACHED = "OBJECTIVE_BREACHED"


class SLOPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = SLO_POLICY_VERSION
    mode: SLOMode = SLOMode.OBSERVE
    objectives: dict[str, float] = Field(default_factory=dict)
    minimum_samples: int = Field(default=20, ge=1, le=100_000)
    burn_rate_threshold: float | None = Field(default=None, gt=0, le=10_000)

    @field_validator("objectives")
    @classmethod
    def validate_objectives(cls, values: dict[str, float]) -> dict[str, float]:
        if set(values) - _SLICES:
            raise ValueError("Unsupported SLI objective")
        if any(not math.isfinite(value) or not 0.0 <= value < 1.0 for value in values.values()):
            raise ValueError("SLO objectives must be finite and in [0, 1)")
        return values

    @model_validator(mode="after")
    def require_enforced_targets(self) -> "SLOPolicy":
        if self.mode is SLOMode.ENFORCED and not self.objectives:
            raise ValueError("ENFORCED mode requires explicit SLO objectives")
        return self

    @classmethod
    def from_settings(cls, settings: Any) -> "SLOPolicy":
        return cls(
            mode=getattr(settings, "AGENT_SLO_MODE", SLOMode.OBSERVE.value),
            objectives=dict(getattr(settings, "AGENT_SLO_OBJECTIVES", {}) or {}),
            minimum_samples=int(getattr(settings, "AGENT_SLO_MIN_SAMPLES", 20)),
            burn_rate_threshold=getattr(settings, "AGENT_SLO_BURN_RATE_THRESHOLD", None),
        )

    @property
    def digest(self) -> str:
        payload = {
            "policy": self.model_dump(mode="json"),
            "classification_version": SLI_CLASSIFICATION_VERSION,
            "windows_seconds": {name: int(duration.total_seconds()) for name, duration in _WINDOWS.items()},
            "latency_sample_limit": MAX_LATENCY_SAMPLES,
        }
        return hashlib.sha256(_canonical(payload)).hexdigest()


class SLIResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    eligible_events: int = Field(ge=0)
    good_events: int = Field(ge=0)
    bad_events: int = Field(ge=0)
    excluded_events: int = Field(ge=0)
    reliability: float | None = Field(default=None, ge=0, le=1)
    objective: float | None = Field(default=None, ge=0, lt=1)
    error_budget_burn_rate: float | None = Field(default=None, ge=0)
    status: SLIStatus

    @model_validator(mode="after")
    def totals_are_consistent(self) -> "SLIResult":
        if self.good_events + self.bad_events != self.eligible_events:
            raise ValueError("SLI good/bad counts must equal eligible events")
        if self.eligible_events == 0 and self.reliability is not None:
            raise ValueError("Reliability must be unknown when there are no eligible events")
        return self


class LatencySummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    eligible_samples: int = Field(ge=0)
    sampled_values: int = Field(ge=0, le=MAX_LATENCY_SAMPLES)
    p50_seconds: float | None = Field(default=None, ge=0)
    p95_seconds: float | None = Field(default=None, ge=0)
    truncated: bool
    sample_method: str = "MOST_RECENT_BOUNDED_SAMPLE"


class BurnRateWindowPair(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sli: str
    short_window: str
    long_window: str
    short_burn_rate: float | None
    long_burn_rate: float | None
    threshold: float | None
    threshold_exceeded: bool | None
    eligible_samples: int = Field(ge=0)


class SLOReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = SLO_REPORT_SCHEMA_VERSION
    policy: SLOPolicy
    policy_digest: str
    classification_version: str = SLI_CLASSIFICATION_VERSION
    generated_at: datetime
    primary_window: str
    windows: dict[str, dict[str, SLIResult]]
    burn_rate_pairs: list[BurnRateWindowPair]
    low_traffic_signals: list[str]
    latency: dict[str, LatencySummary]
    invariant_observations: dict[str, int]
    report_digest: str = ""

    @model_validator(mode="after")
    def validate_digest(self) -> "SLOReport":
        payload = self.model_dump(mode="json", exclude={"report_digest"})
        actual = hashlib.sha256(_canonical(payload)).hexdigest()
        if self.report_digest and self.report_digest != actual:
            raise ValueError("SLO report digest does not match its content")
        if not self.report_digest:
            object.__setattr__(self, "report_digest", actual)
        if self.primary_window not in self.windows:
            raise ValueError("Primary SLO window is missing")
        return self


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    # Nearest-rank percentile avoids a dependency and is deterministic.
    index = max(0, math.ceil(probability * len(ordered)) - 1)
    return round(ordered[index], 6)


def _sli_result(
    *,
    name: str,
    good: int,
    bad: int,
    excluded: int,
    policy: SLOPolicy,
) -> SLIResult:
    eligible = good + bad
    objective = policy.objectives.get(name)
    reliability = good / eligible if eligible else None
    burn = None
    if eligible and objective is not None:
        burn = (bad / eligible) / (1.0 - objective)
    if not eligible:
        status = SLIStatus.NO_DATA
    elif objective is None:
        status = SLIStatus.OBSERVATION_ONLY
    elif eligible < policy.minimum_samples:
        status = SLIStatus.INSUFFICIENT_SAMPLE
    else:
        status = SLIStatus.OBJECTIVE_MET if reliability >= objective else SLIStatus.OBJECTIVE_BREACHED
    return SLIResult(
        name=name,
        eligible_events=eligible,
        good_events=good,
        bad_events=bad,
        excluded_events=excluded,
        reliability=reliability,
        objective=objective,
        error_budget_burn_rate=burn,
        status=status,
    )


def _work_counts(db: Session, start: datetime, end: datetime) -> dict[tuple[str, str, bool], int]:
    user_failure = db.query(FailureRecordModel.id).filter(
        FailureRecordModel.work_item_id == WorkItemModel.id,
        FailureRecordModel.category == "USER",
    ).exists()
    rows = (
        db.query(WorkItemModel.work_kind, WorkItemModel.state, user_failure, func.count(WorkItemModel.id))
        .filter(
            WorkItemModel.terminal_at.is_not(None),
            WorkItemModel.terminal_at >= start,
            WorkItemModel.terminal_at <= end,
            WorkItemModel.state.in_(_TERMINAL),
        )
        .group_by(WorkItemModel.work_kind, WorkItemModel.state, user_failure)
        .all()
    )
    return {(str(kind), str(state), bool(user_error)): int(count) for kind, state, user_error, count in rows}


def _provider_counts(db: Session, start: datetime, end: datetime) -> dict[tuple[str, bool], int]:
    rows = (
        db.query(AIExecutionModel.provider, AIExecutionModel.success, func.count(AIExecutionModel.id))
        .filter(AIExecutionModel.created_at >= start, AIExecutionModel.created_at <= end)
        .group_by(AIExecutionModel.provider, AIExecutionModel.success)
        .limit(32)
        .all()
    )
    return {(str(provider), bool(success)): int(count) for provider, success, count in rows}


def _window_results(db: Session, start: datetime, end: datetime, policy: SLOPolicy) -> dict[str, SLIResult]:
    work = _work_counts(db, start, end)
    providers = _provider_counts(db, start, end)

    def counts(kinds: frozenset[str] | None = None) -> tuple[int, int, int]:
        good = bad = excluded = 0
        for (kind, state, user_error), count in work.items():
            if kinds is not None and kind not in kinds:
                continue
            if state == ExecutionState.SUCCEEDED.value:
                good += count
            elif state in {ExecutionState.FAILED.value, ExecutionState.TIMED_OUT.value}:
                if user_error:
                    excluded += count
                else:
                    bad += count
            elif state == ExecutionState.CANCELLED.value:
                excluded += count
        return good, bad, excluded

    work_good, work_bad, work_excluded = counts()
    github_good, github_bad, github_excluded = counts(_GITHUB_KINDS)
    # GitHub App pull-request analysis uses the canonical CHANGE_ANALYSIS work
    # kind; installation-bound change rows distinguish it from manual analysis.
    user_failure = db.query(FailureRecordModel.id).filter(
        FailureRecordModel.work_item_id == WorkItemModel.id,
        FailureRecordModel.category == "USER",
    ).exists()
    github_change_rows = db.query(
        WorkItemModel.state,
        user_failure,
        func.count(WorkItemModel.id),
    ).join(
        ChangeAnalysisModel,
        ChangeAnalysisModel.id == WorkItemModel.resource_id,
    ).filter(
        WorkItemModel.work_kind == WorkKind.CHANGE_ANALYSIS.value,
        ChangeAnalysisModel.github_app_installation_id.is_not(None),
        WorkItemModel.terminal_at.is_not(None),
        WorkItemModel.terminal_at >= start,
        WorkItemModel.terminal_at <= end,
        WorkItemModel.state.in_(_TERMINAL),
    ).group_by(WorkItemModel.state, user_failure).all()
    for state, user_error, count in github_change_rows:
        count = int(count)
        if state == ExecutionState.SUCCEEDED.value:
            github_good += count
        elif state in {ExecutionState.FAILED.value, ExecutionState.TIMED_OUT.value}:
            if user_error:
                github_excluded += count
            else:
                github_bad += count
        elif state == ExecutionState.CANCELLED.value:
            github_excluded += count
    provider_good = sum(value for (_, success), value in providers.items() if success)
    provider_bad = sum(value for (_, success), value in providers.items() if not success)
    return {
        "work_reliability": _sli_result(
            name="work_reliability", good=work_good, bad=work_bad,
            excluded=work_excluded, policy=policy,
        ),
        "github_automation_reliability": _sli_result(
            name="github_automation_reliability", good=github_good, bad=github_bad,
            excluded=github_excluded, policy=policy,
        ),
        "provider_reliability": _sli_result(
            name="provider_reliability", good=provider_good, bad=provider_bad,
            excluded=0, policy=policy,
        ),
    }


def _latency_summary(db: Session, *, field: str, start: datetime, end: datetime) -> LatencySummary:
    if field == "start":
        count_query = db.query(func.count(WorkItemModel.id)).filter(
            WorkItemModel.started_at >= start, WorkItemModel.started_at <= end
        )
        rows = (
            db.query(WorkItemModel.created_at, WorkItemModel.started_at)
            .filter(WorkItemModel.started_at >= start, WorkItemModel.started_at <= end)
            .order_by(WorkItemModel.started_at.desc())
            .limit(MAX_LATENCY_SAMPLES + 1)
            .all()
        )
    else:
        terminal_filter = (
            WorkItemModel.terminal_at >= start,
            WorkItemModel.terminal_at <= end,
            WorkItemModel.started_at.is_not(None),
            WorkItemModel.state.in_((ExecutionState.SUCCEEDED.value, ExecutionState.FAILED.value, ExecutionState.TIMED_OUT.value)),
        )
        count_query = db.query(func.count(WorkItemModel.id)).filter(*terminal_filter)
        rows = (
            db.query(WorkItemModel.started_at, WorkItemModel.terminal_at)
            .filter(*terminal_filter)
            .order_by(WorkItemModel.terminal_at.desc())
            .limit(MAX_LATENCY_SAMPLES + 1)
            .all()
        )
    eligible_count = int(count_query.scalar() or 0)
    truncated = eligible_count > MAX_LATENCY_SAMPLES
    samples: list[float] = []
    for left, right in rows[:MAX_LATENCY_SAMPLES]:
        if left is None or right is None:
            continue
        elapsed = (_aware(right) - _aware(left)).total_seconds()
        if math.isfinite(elapsed) and elapsed >= 0:
            samples.append(elapsed)
    return LatencySummary(
        eligible_samples=eligible_count,
        sampled_values=len(samples),
        p50_seconds=_quantile(samples, 0.50),
        p95_seconds=_quantile(samples, 0.95),
        truncated=truncated,
    )


def _invariant_observations(db: Session, now: datetime) -> dict[str, int]:
    return {
        "expired_active_work_leases": int(db.query(func.count(WorkLeaseModel.id)).filter(
            WorkLeaseModel.state == "ACTIVE", WorkLeaseModel.expires_at <= now
        ).scalar() or 0),
        "failed_outbox_events": int(db.query(func.count(OutboxEventModel.id)).filter(
            OutboxEventModel.status == "FAILED"
        ).scalar() or 0),
        "expired_outbox_leases": int(db.query(func.count(OutboxEventModel.id)).filter(
            OutboxEventModel.status == "PROCESSING", OutboxEventModel.lease_expires_at <= now
        ).scalar() or 0),
        "expired_reconciliation_leases": int(db.query(func.count(ReconciliationRecordModel.id)).filter(
            ReconciliationRecordModel.status == "RUNNING", ReconciliationRecordModel.lease_expires_at <= now
        ).scalar() or 0),
    }


def build_slo_report(
    db: Session,
    *,
    policy: SLOPolicy,
    primary_window: str = "24h",
    now: datetime | None = None,
) -> SLOReport:
    """Build a fixed-cost, bounded-window SLO report from canonical SQL state."""
    if primary_window not in _WINDOWS:
        raise ValueError("Unsupported SLO window")
    current = _aware(now or datetime.now(timezone.utc))
    windows: dict[str, dict[str, SLIResult]] = {}
    for name, duration in _WINDOWS.items():
        windows[name] = _window_results(db, current - duration, current, policy)

    burns: list[BurnRateWindowPair] = []
    for sli in sorted(_SLICES):
        objective = policy.objectives.get(sli)
        if objective is None:
            continue
        for short_name, long_name in (("5m", "1h"), ("1h", "6h")):
            short = windows[short_name][sli]
            long = windows[long_name][sli]
            short_burn = short.error_budget_burn_rate
            long_burn = long.error_budget_burn_rate
            enough = min(short.eligible_events, long.eligible_events) >= policy.minimum_samples
            threshold_exceeded = None
            if policy.burn_rate_threshold is not None and enough and short_burn is not None and long_burn is not None:
                threshold_exceeded = (
                    short_burn >= policy.burn_rate_threshold
                    and long_burn >= policy.burn_rate_threshold
                )
            burns.append(BurnRateWindowPair(
                sli=sli,
                short_window=short_name,
                long_window=long_name,
                short_burn_rate=short_burn,
                long_burn_rate=long_burn,
                threshold=policy.burn_rate_threshold,
                threshold_exceeded=threshold_exceeded,
                eligible_samples=min(short.eligible_events, long.eligible_events),
            ))

    low_traffic: list[str] = []
    for window_name, results in windows.items():
        for sli, result in results.items():
            if result.bad_events > 0 and result.eligible_events < policy.minimum_samples:
                low_traffic.append(f"{window_name}:{sli}:BAD_EVENT_PRESENT_BELOW_MINIMUM_SAMPLE")

    latency = {
        "queue_to_start": _latency_summary(
            db, field="start", start=current - _WINDOWS[primary_window], end=current
        ),
        "start_to_terminal": _latency_summary(
            db, field="terminal", start=current - _WINDOWS[primary_window], end=current
        ),
    }
    return SLOReport(
        policy=policy,
        policy_digest=policy.digest,
        generated_at=current,
        primary_window=primary_window,
        windows=windows,
        burn_rate_pairs=burns,
        low_traffic_signals=low_traffic,
        latency=latency,
        invariant_observations=_invariant_observations(db, current),
    )


__all__ = [
    "MAX_LATENCY_SAMPLES",
    "SLI_CLASSIFICATION_VERSION",
    "SLIResult",
    "SLIStatus",
    "SLOMode",
    "SLOPolicy",
    "SLOReport",
    "SLO_REPORT_SCHEMA_VERSION",
    "SLO_POLICY_VERSION",
    "build_slo_report",
]
