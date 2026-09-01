"""Application boundary for idempotent, policy-bound durable work submission."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.execution.engine import DurableExecutionEngine
from app.execution.types import (
    EnqueueRequest,
    EnqueueResult,
    RequestBudget,
    ResourceDimension,
    ResourceProfile,
    SideEffectClass,
    WorkKind,
)
from app.governance.events import AuditLedger, DomainOutbox
from app.governance.policies import OperationalPolicy, OperationalPolicyService
from app.governance.telemetry import TelemetryRecorder
from app.models.execution import WorkItemModel


class NewWorkPaused(RuntimeError):
    """Raised when the active operational policy pauses new work."""


class WorkPolicyViolation(RuntimeError):
    """Raised when a work request conflicts with the active policy snapshot."""


def canonical_request_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def deterministic_resource_id(tenant_id: str, scope: str, idempotency_identity: str) -> str:
    """Derive the same opaque resource ID for retries without persisting the caller key."""
    return str(uuid5(NAMESPACE_URL, f"repolens:{tenant_id}:{scope}:{idempotency_identity}"))


@dataclass(frozen=True)
class WorkSubmission:
    result: EnqueueResult
    policy_snapshot_id: str


class WorkSubmissionService:
    """Submit domain work and its durable events in the caller's transaction."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def submit(
        self,
        db: Session,
        *,
        tenant_id: str,
        actor_id: str,
        request_id: str,
        work_kind: WorkKind,
        resource_type: str,
        resource_id: str,
        request_payload: Mapping[str, Any],
        idempotency_key: str,
        resource_profile: ResourceProfile,
        budget: RequestBudget,
        external_idempotency_key: str | None = None,
        side_effect_class: SideEffectClass = SideEffectClass.SAFE_RECOMPUTATION,
        input_artifact_id: str | None = None,
        coverage_artifact_id: str | None = None,
        priority: int = 50,
        max_attempts: int | None = None,
        allow_when_paused: bool = False,
    ) -> WorkSubmission:
        policy_model = OperationalPolicyService.active(db, tenant_id)
        if policy_model is None:
            policy_model = OperationalPolicyService.ensure_active(db)
        policy = OperationalPolicy.model_validate(policy_model.policy_payload)
        if policy.pause_new_jobs and not allow_when_paused:
            raise NewWorkPaused("New jobs are paused by the active operational policy.")
        if (
            resource_profile == ResourceProfile.GITHUB_WRITE
            and not policy.github_writes_enabled
        ):
            raise WorkPolicyViolation("GitHub writes are disabled by the active operational policy.")
        tier_limit = {"FREE": 0, "CHEAP": 1, "STANDARD": 2, "PREMIUM": 3}[
            policy.max_model_cost_tier
        ]
        if budget.max_escalation_tier > tier_limit:
            budget = replace(budget, max_escalation_tier=tier_limit)

        capacities = {
            ResourceDimension.WORKER: max(
                1,
                policy.max_concurrent_scans
                + policy.max_renderer_concurrency
                + policy.max_ai_concurrency,
            ),
            ResourceDimension.SCANNER: policy.max_concurrent_scans,
            ResourceDimension.AI: policy.max_ai_concurrency,
            ResourceDimension.RENDERER: policy.max_renderer_concurrency,
            ResourceDimension.LARGE_REPOSITORY: policy.max_large_repository_jobs,
            ResourceDimension.EMBEDDING: policy.max_ai_concurrency,
            ResourceDimension.PATCH: policy.max_ai_concurrency,
            ResourceDimension.GITHUB_WRITE: 1,
        }
        request_digest = canonical_request_digest(request_payload)
        engine = DurableExecutionEngine(
            db,
            lease_seconds=self.settings.EXECUTION_LEASE_SECONDS,
            per_tenant_active_jobs=policy.max_active_jobs_per_user,
            resource_capacities=capacities,
            auto_commit=False,
        )
        for dimension, capacity in capacities.items():
            engine.configure_capacity(
                dimension,
                capacity,
                policy_snapshot_id=policy_model.id,
            )
        engine.configure_capacity(
            ResourceDimension.TENANT_ACTIVE_JOB,
            policy.max_active_jobs_per_user,
            policy_snapshot_id=policy_model.id,
            scope_id=tenant_id,
        )
        result = engine.enqueue(
            EnqueueRequest(
                tenant_id=tenant_id,
                request_id=request_id,
                requested_by=actor_id,
                policy_snapshot_id=policy_model.id,
                work_kind=work_kind,
                resource_type=resource_type,
                resource_id=resource_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_profile=resource_profile,
                budget=budget,
                side_effect_class=side_effect_class,
                external_idempotency_key=external_idempotency_key,
                input_artifact_id=input_artifact_id,
                coverage_artifact_id=coverage_artifact_id,
                priority=priority,
                max_attempts=max_attempts or self.settings.EXECUTION_MAX_ATTEMPTS,
            )
        )
        if result.reused:
            TelemetryRecorder.record(
                db,
                tenant_id=tenant_id,
                request_id=request_id,
                work_item_id=result.work_item_id,
                metric_name="work.idempotent_reuse",
                value=1,
                unit="count",
                dimensions={"work_kind": work_kind.value},
            )
            return WorkSubmission(result=result, policy_snapshot_id=policy_model.id)

        DomainOutbox.append(
            db,
            tenant_id=tenant_id,
            aggregate_type="WORK_ITEM",
            aggregate_id=result.work_item_id,
            event_type="WORK_ITEM_QUEUED",
            deduplication_key=f"work:{result.work_item_id}:queued",
            payload={
                "work_kind": work_kind.value,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "policy_snapshot_id": policy_model.id,
            },
        )
        AuditLedger.append(
            db,
            tenant_id=tenant_id,
            actor_id=actor_id,
            request_id=request_id,
            event_type="JOB_CREATED",
            resource_type="WORK_ITEM",
            resource_id=result.work_item_id,
            state_digest=request_digest,
            payload={
                "work_kind": work_kind.value,
                "domain_resource_type": resource_type,
                "domain_resource_id": resource_id,
                "policy_snapshot_id": policy_model.id,
            },
        )
        TelemetryRecorder.record(
            db,
            tenant_id=tenant_id,
            request_id=request_id,
            work_item_id=result.work_item_id,
            metric_name="job.queued",
            value=1,
            unit="count",
            dimensions={"work_kind": work_kind.value, "resource_profile": resource_profile.value},
        )
        return WorkSubmission(result=result, policy_snapshot_id=policy_model.id)

    @staticmethod
    def find_by_external_identity(
        db: Session,
        *,
        tenant_id: str,
        work_kind: WorkKind,
        identity: str,
    ) -> WorkItemModel | None:
        return db.query(WorkItemModel).filter(
            WorkItemModel.tenant_id == tenant_id,
            WorkItemModel.work_kind == work_kind.value,
            WorkItemModel.external_idempotency_key == identity,
        ).first()


__all__ = [
    "NewWorkPaused",
    "WorkPolicyViolation",
    "WorkSubmission",
    "WorkSubmissionService",
    "canonical_request_digest",
    "deterministic_resource_id",
]
