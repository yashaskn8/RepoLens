"""Canonical coverage, outcome, and safe failure taxonomies."""

from enum import Enum
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from app.security.redaction import redact_secrets


class FailureCode(str, Enum):
    USER_INPUT_ERROR = "USER_INPUT_ERROR"
    REPOSITORY_UNAVAILABLE = "REPOSITORY_UNAVAILABLE"
    REPOSITORY_LIMIT_EXCEEDED = "REPOSITORY_LIMIT_EXCEEDED"
    SNAPSHOT_POLICY_VIOLATION = "SNAPSHOT_POLICY_VIOLATION"
    ANALYZER_UNAVAILABLE = "ANALYZER_UNAVAILABLE"
    ANALYZER_TIMEOUT = "ANALYZER_TIMEOUT"
    ANALYZER_INVALID_OUTPUT = "ANALYZER_INVALID_OUTPUT"
    PROVIDER_RATE_LIMITED = "PROVIDER_RATE_LIMITED"
    PROVIDER_AUTH_FAILURE = "PROVIDER_AUTH_FAILURE"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    MODEL_CONTEXT_LIMIT = "MODEL_CONTEXT_LIMIT"
    MODEL_INVALID_OUTPUT = "MODEL_INVALID_OUTPUT"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    WORKFLOW_TIMEOUT = "WORKFLOW_TIMEOUT"
    WORKER_LOST = "WORKER_LOST"
    CANCELLED_BY_USER = "CANCELLED_BY_USER"
    EXTERNAL_STATE_UNCERTAIN = "EXTERNAL_STATE_UNCERTAIN"
    INTERNAL_INVARIANT_VIOLATION = "INTERNAL_INVARIANT_VIOLATION"


class DomainOutcome(str, Enum):
    COMPLETE = "COMPLETE"
    DEGRADED = "DEGRADED"
    BOUNDED = "BOUNDED"


class CoverageState(str, Enum):
    SUCCESSFULLY_ANALYZED = "SUCCESSFULLY_ANALYZED"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    TRUNCATED = "TRUNCATED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class CoverageUnit(BaseModel):
    model_config = ConfigDict(frozen=True)

    component: str = Field(min_length=1, max_length=128)
    state: CoverageState
    reason_code: FailureCode | None = None
    explanation: str | None = Field(default=None, max_length=512)
    observed_count: int | None = Field(default=None, ge=0)
    analyzed_count: int | None = Field(default=None, ge=0)


class AnalysisCoverage(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.0"
    outcome: DomainOutcome
    units: list[CoverageUnit] = Field(default_factory=list)
    budget_exhausted: bool = False
    truncated: bool = False
    explanation: str = Field(min_length=1, max_length=1024)

    @classmethod
    def from_units(
        cls,
        units: Iterable[CoverageUnit],
        *,
        budget_exhausted: bool = False,
        truncated: bool = False,
    ) -> "AnalysisCoverage":
        materialized = list(units)
        states = {unit.state for unit in materialized}
        if budget_exhausted or truncated:
            outcome = DomainOutcome.BOUNDED
            explanation = "Analysis completed within an explicit resource boundary; omitted scope is recorded."
        elif states & {CoverageState.UNAVAILABLE, CoverageState.FAILED, CoverageState.UNSUPPORTED, CoverageState.SKIPPED}:
            outcome = DomainOutcome.DEGRADED
            explanation = "Analysis completed with unavailable, failed, unsupported, or skipped coverage."
        else:
            outcome = DomainOutcome.COMPLETE
            explanation = "All recorded analysis components completed successfully."
        return cls(
            outcome=outcome,
            units=materialized,
            budget_exhausted=budget_exhausted,
            truncated=truncated,
            explanation=explanation,
        )

    @classmethod
    def from_analyzers(
        cls,
        analyzers: Iterable[dict],
        *,
        truncated: bool = False,
        budget_exhausted: bool = False,
    ) -> "AnalysisCoverage":
        status_map = {
            "COMPLETED": CoverageState.SUCCESSFULLY_ANALYZED,
            "UNAVAILABLE": CoverageState.UNAVAILABLE,
            "TIMEOUT": CoverageState.FAILED,
            "INVALID_OUTPUT": CoverageState.FAILED,
            "FAILED": CoverageState.FAILED,
            "SKIPPED": CoverageState.SKIPPED,
            "UNSUPPORTED": CoverageState.UNSUPPORTED,
        }
        reason_map = {
            "UNAVAILABLE": FailureCode.ANALYZER_UNAVAILABLE,
            "TIMEOUT": FailureCode.ANALYZER_TIMEOUT,
            "INVALID_OUTPUT": FailureCode.ANALYZER_INVALID_OUTPUT,
            "FAILED": FailureCode.ANALYZER_INVALID_OUTPUT,
        }
        units = []
        for analyzer in analyzers:
            raw_status = str(analyzer.get("status") or "FAILED").upper()
            units.append(CoverageUnit(
                component=str(analyzer.get("tool") or analyzer.get("component") or "unknown")[:128],
                state=status_map.get(raw_status, CoverageState.FAILED),
                reason_code=reason_map.get(raw_status),
                explanation=str(analyzer.get("failure_reason"))[:512] if analyzer.get("failure_reason") else None,
                analyzed_count=int(analyzer.get("findings_count") or 0),
            ))
        if truncated:
            units.append(CoverageUnit(component="repository_scope", state=CoverageState.TRUNCATED))
        return cls.from_units(units, budget_exhausted=budget_exhausted, truncated=truncated)


class CanonicalFailure(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: FailureCode
    message: str = Field(min_length=1, max_length=512)
    retryable: bool = False


def safe_failure(
    exc: Exception,
    *,
    default: FailureCode = FailureCode.INTERNAL_INVARIANT_VIOLATION,
) -> CanonicalFailure:
    """Map internal exceptions to a stable external failure without persisting raw traces."""
    name = type(exc).__name__.upper()
    text = redact_secrets(str(exc))[:512]
    if "TIMEOUT" in name:
        return CanonicalFailure(code=FailureCode.WORKFLOW_TIMEOUT, message="The operation exceeded its time budget.", retryable=True)
    if "RATE" in name and "LIMIT" in name:
        return CanonicalFailure(code=FailureCode.PROVIDER_RATE_LIMITED, message="The selected provider is rate limited.", retryable=True)
    if "AUTH" in name:
        return CanonicalFailure(code=FailureCode.PROVIDER_AUTH_FAILURE, message="Provider authentication failed.", retryable=False)
    if "REPOSITORY" in name or "GIT" in name:
        return CanonicalFailure(code=FailureCode.REPOSITORY_UNAVAILABLE, message="The repository revision could not be acquired.", retryable=True)
    return CanonicalFailure(
        code=default,
        message="The operation failed safely; use the request ID to inspect internal diagnostics." if text else "The operation failed safely.",
        retryable=False,
    )
