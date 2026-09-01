"""Immutable, content-minimized AI execution provenance records and stores."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from threading import RLock
from typing import Callable, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.llm.exceptions import ProviderFailureCode
from app.llm.types import AIValidationResult, LLMProvider, LLMRequest, ModelCapability


class AIExecutionRecord(BaseModel):
    """Append-only lineage for one provider attempt; never contains prompt/output text."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.0"
    execution_id: str = Field(min_length=36, max_length=36)
    tenant_id: str | None = None
    request_id: str | None = None
    work_item_id: str | None = None
    attempt_id: str | None = None
    parent_execution_id: str | None = None
    sequence: int = Field(ge=1)
    provider: LLMProvider
    model: str = Field(min_length=1, max_length=256)
    model_revision: str | None = Field(default=None, max_length=128)
    capability: ModelCapability
    prompt_template_version: str = Field(min_length=1, max_length=128)
    prompt_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_schema_version: str | None = Field(default=None, max_length=128)
    output_schema_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    evidence_digest: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    policy_snapshot_id: str | None = None
    generation_settings: dict[str, object]
    request_budget: dict[str, object]
    estimated_input_tokens: int = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    latency_ms: float = Field(ge=0)
    validation_result: AIValidationResult
    success: bool
    failure_code: ProviderFailureCode | None = None
    fallback_reason: str | None = Field(default=None, max_length=128)
    escalation_reason: str | None = Field(default=None, max_length=128)
    quota_reservation_id: str | None = None
    output_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    routing_policy_version: str = Field(min_length=1, max_length=128)
    model_registry_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime


class AIExecutionStore(Protocol):
    def append(self, record: AIExecutionRecord) -> None: ...


class NullAIExecutionStore:
    """Compatibility store used until an application unit-of-work supplies persistence."""

    def append(self, record: AIExecutionRecord) -> None:
        del record


class InMemoryAIExecutionStore:
    """Append-only test/local store; production should use a database store."""

    def __init__(self) -> None:
        self._records: list[AIExecutionRecord] = []
        self._lock = RLock()

    def append(self, record: AIExecutionRecord) -> None:
        with self._lock:
            if any(existing.execution_id == record.execution_id for existing in self._records):
                raise ValueError("AI execution IDs are immutable and unique")
            self._records.append(record)

    @property
    def records(self) -> tuple[AIExecutionRecord, ...]:
        with self._lock:
            return tuple(self._records)


class SessionAIExecutionStore:
    """Append in an existing unit-of-work so execution and outbox can be atomic."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def append(self, record: AIExecutionRecord) -> None:
        self.session.add(_to_model(record))
        self.session.flush()


class SQLAlchemyAIExecutionStore:
    """Standalone durable append store for gateway processes."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self.session_factory = session_factory

    def append(self, record: AIExecutionRecord) -> None:
        with self.session_factory() as db, db.begin():
            db.add(_to_model(record))


class CanonicalSQLAlchemyAIExecutionStore:
    """Persist an AI attempt and its first-class artifact in one SQL transaction."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self.session_factory = session_factory

    def append(self, record: AIExecutionRecord) -> None:
        from app.artifacts.schemas import (
            ArtifactCoverage,
            ArtifactSensitivity,
            ArtifactType,
            CoverageStatus,
            RetentionClass,
        )
        from app.artifacts.service import CanonicalArtifactService
        from app.governance.policies import OperationalPolicyService
        from app.governance.telemetry import TelemetryRecorder

        with self.session_factory() as db, db.begin():
            policy_id = record.policy_snapshot_id
            if not policy_id:
                active = OperationalPolicyService.active(db, record.tenant_id)
                if active is None:
                    active = OperationalPolicyService.ensure_active(db)
                policy_id = active.id
            tenant_id = record.tenant_id or "platform"
            payload = record.model_dump(mode="json")
            registration = CanonicalArtifactService(db).publish_json(
                tenant_id=tenant_id,
                repository_id=None,
                revision_id=None,
                artifact_type=ArtifactType.AI_EXECUTION,
                payload=payload,
                producer=f"{record.provider.value}:{record.model}"[:128],
                producer_version=record.model_revision or "unspecified",
                policy_snapshot_id=policy_id,
                coverage=ArtifactCoverage(
                    status=(
                        CoverageStatus.SUCCESSFULLY_ANALYZED
                        if record.success
                        else CoverageStatus.FAILED
                    ),
                    discovered_count=1,
                    analyzed_count=1 if record.success else 0,
                    failed_count=0 if record.success else 1,
                    explanation=None if record.success else "The provider attempt did not produce a valid result.",
                ),
                sensitivity=ArtifactSensitivity.INTERNAL,
                retention_class=RetentionClass.ANALYSIS_ARTIFACT,
                referrer=("WORK_ITEM", record.work_item_id) if record.work_item_id else None,
                actor_id=record.tenant_id,
                request_id=record.request_id,
            )
            model = _to_model(record)
            model.artifact_id = registration.artifact.artifact_id
            db.add(model)
            dimensions = {
                "provider": record.provider.value,
                "model": record.model,
                "capability": record.capability.value,
                "success": record.success,
            }
            TelemetryRecorder.record(
                db,
                tenant_id=record.tenant_id,
                request_id=record.request_id,
                work_item_id=record.work_item_id,
                metric_name="provider.calls",
                value=1,
                unit="count",
                dimensions=dimensions,
            )
            TelemetryRecorder.record(
                db,
                tenant_id=record.tenant_id,
                request_id=record.request_id,
                work_item_id=record.work_item_id,
                metric_name="provider.latency",
                value=record.latency_ms,
                unit="milliseconds",
                dimensions=dimensions,
            )
            TelemetryRecorder.record(
                db,
                tenant_id=record.tenant_id,
                request_id=record.request_id,
                work_item_id=record.work_item_id,
                metric_name="provider.tokens",
                value=float(record.total_tokens or 0),
                unit="tokens",
                dimensions=dimensions,
            )


class AIExecutionRecorder:
    """Build safe immutable records and delegate their persistence."""

    def __init__(self, store: AIExecutionStore | None = None) -> None:
        self.store = store or NullAIExecutionStore()

    def record(
        self,
        *,
        execution_id: str,
        sequence: int,
        request: LLMRequest,
        capability: ModelCapability,
        provider: LLMProvider,
        model: str,
        model_revision: str | None,
        estimated_input_tokens: int,
        input_tokens: int | None,
        output_tokens: int | None,
        latency_ms: float,
        validation_result: AIValidationResult,
        success: bool,
        failure_code: ProviderFailureCode | None,
        fallback_reason: str | None,
        escalation_reason: str | None,
        quota_reservation_id: str | None,
        output: str | None,
        routing_policy_version: str,
        model_registry_version: str,
    ) -> AIExecutionRecord:
        created_at = datetime.now(timezone.utc)
        prompt_digest = _digest(
            [{"role": message.role, "content": message.content} for message in request.messages]
        )
        schema_digest = _digest(request.output_schema) if request.output_schema is not None else None
        output_digest = hashlib.sha256(output.encode("utf-8")).hexdigest() if output is not None else None
        generation_settings: dict[str, object] = {
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "json_mode": request.json_mode,
        }
        lineage = request.lineage
        payload = {
            "schema_version": "1.0",
            "execution_id": execution_id,
            "tenant_id": lineage.tenant_id,
            "request_id": lineage.request_id,
            "work_item_id": lineage.work_item_id,
            "attempt_id": lineage.attempt_id,
            "parent_execution_id": lineage.parent_execution_id,
            "sequence": sequence,
            "provider": provider.value,
            "model": model,
            "model_revision": model_revision,
            "capability": capability.value,
            "prompt_template_version": lineage.prompt_template_version,
            "prompt_digest": prompt_digest,
            "output_schema_version": lineage.output_schema_version,
            "output_schema_digest": schema_digest,
            "evidence_digest": lineage.evidence_digest,
            "policy_snapshot_id": lineage.policy_snapshot_id,
            "generation_settings": generation_settings,
            "request_budget": request.budget.model_dump(mode="json"),
            "estimated_input_tokens": estimated_input_tokens,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": (
                input_tokens + output_tokens
                if input_tokens is not None and output_tokens is not None
                else None
            ),
            "latency_ms": max(0.0, latency_ms),
            "validation_result": validation_result.value,
            "success": success,
            "failure_code": failure_code.value if failure_code else None,
            "fallback_reason": fallback_reason,
            "escalation_reason": escalation_reason,
            "quota_reservation_id": quota_reservation_id,
            "output_digest": output_digest,
            "routing_policy_version": routing_policy_version,
            "model_registry_version": model_registry_version,
            "created_at": created_at.isoformat(),
        }
        record = AIExecutionRecord(**payload, record_digest=_digest(payload))
        self.store.append(record)
        return record


def _digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _to_model(record: AIExecutionRecord):
    from app.models.ai_execution import AIExecutionModel

    return AIExecutionModel(
        id=record.execution_id,
        tenant_id=record.tenant_id,
        request_id=record.request_id,
        work_item_id=record.work_item_id,
        attempt_id=record.attempt_id,
        parent_execution_id=record.parent_execution_id,
        sequence=record.sequence,
        provider=record.provider.value,
        model=record.model,
        model_revision=record.model_revision,
        capability=record.capability.value,
        prompt_template_version=record.prompt_template_version,
        prompt_digest=record.prompt_digest,
        output_schema_version=record.output_schema_version,
        output_schema_digest=record.output_schema_digest,
        evidence_digest=record.evidence_digest,
        policy_snapshot_id=record.policy_snapshot_id,
        generation_settings=record.generation_settings,
        request_budget=record.request_budget,
        estimated_input_tokens=record.estimated_input_tokens,
        input_tokens=record.input_tokens,
        output_tokens=record.output_tokens,
        total_tokens=record.total_tokens,
        latency_ms=record.latency_ms,
        validation_result=record.validation_result.value,
        success=record.success,
        failure_code=record.failure_code.value if record.failure_code else None,
        fallback_reason=record.fallback_reason,
        escalation_reason=record.escalation_reason,
        quota_reservation_id=record.quota_reservation_id,
        output_digest=record.output_digest,
        routing_policy_version=record.routing_policy_version,
        model_registry_version=record.model_registry_version,
        record_digest=record.record_digest,
        created_at=record.created_at,
    )
