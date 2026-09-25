"""Bounded, operator-only snapshots over existing RepoLens authorities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any

from sqlalchemy import case, func, inspect
from sqlalchemy.orm import Session

from app.agents.checkpointer import (
    CheckpointBackend,
    resolve_checkpoint_backend,
    validate_analysis_checkpointer_ready,
)
from app.agent_tools.registry import AgentToolRegistry
from app.core.schema_readiness import missing_scan_storage_tables
from app.execution.types import ExecutionState
from app.llm.capabilities import ModelCapabilityRegistry
from app.models.ai_execution import AIExecutionModel, AIProviderHealthModel
from app.models.execution import WorkItemModel, WorkLeaseModel
from app.models.github_app import GitHubAppInstallationModel, GitHubAppWebhookDeliveryModel
from app.models.platform import OutboxEventModel, ReconciliationRecordModel


CORE_REQUIRED_TABLES = frozenset({
    "execution_work_items",
    "execution_attempts",
    "ai_executions",
    "ai_provider_health",
    "telemetry_metrics",
    "outbox_events",
    "reconciliation_records",
})
CHECKPOINTER_TABLES = frozenset({"checkpoints"})
MAX_RECENT_MODELS = 25
MAX_CONFIGURED_MODELS = 64


async def check_checkpointer_readiness(settings: Any) -> dict[str, Any]:
    """Read-only checkpointer probe; never creates SQLite files or runs setup."""
    try:
        backend = resolve_checkpoint_backend(settings)
        if backend == CheckpointBackend.MEMORY_TEST_ONLY:
            return {"ready": not settings.is_production, "backend": backend.value, "state": "TEST_ONLY"}
        if backend == CheckpointBackend.POSTGRES:
            await validate_analysis_checkpointer_ready()
            return {"ready": True, "backend": backend.value, "state": "CONNECTED"}
        path = Path(settings.CHECKPOINT_DB_FILE)
        if not path.is_file():
            return {"ready": False, "backend": backend.value, "state": "MISSING"}
        uri = f"{path.resolve().as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1.0) as connection:
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 32"
                ).fetchall()
            }
        ready = CHECKPOINTER_TABLES.issubset(tables)
        return {
            "ready": ready,
            "backend": backend.value,
            "state": "CONNECTED" if ready else "SCHEMA_MISSING",
        }
    except Exception:
        # Connection/driver exceptions may contain hostnames or credentials.
        return {"ready": False, "backend": "UNKNOWN", "state": "UNAVAILABLE"}


def schema_readiness(db: Session) -> dict[str, Any]:
    available = set(inspect(db.get_bind()).get_table_names())
    missing = CORE_REQUIRED_TABLES.difference(available)
    missing_scan = missing_scan_storage_tables(db)
    return {
        "ready": not missing and not missing_scan,
        "missing_core_table_count": len(missing),
        "missing_scan_table_count": len(missing_scan),
    }


def _counts(rows: list[tuple[Any, Any]]) -> dict[str, int]:
    # DB-backed enum labels are bounded and never contain resource identities.
    return {str(key): int(value) for key, value in rows}


def build_operations_overview(db: Session, *, settings: Any, checkpointer: dict[str, Any]) -> dict[str, Any]:
    """Return system-wide operational state without tenant/resource identifiers."""
    now = datetime.now(timezone.utc)
    schema = schema_readiness(db)
    work_states = _counts(
        db.query(WorkItemModel.state, func.count(WorkItemModel.id))
        .group_by(WorkItemModel.state)
        .limit(32)
        .all()
    )
    work_kinds = _counts(
        db.query(WorkItemModel.work_kind, func.count(WorkItemModel.id))
        .group_by(WorkItemModel.work_kind)
        .limit(32)
        .all()
    )
    work_snapshot_rows = db.query(
        WorkItemModel.work_kind,
        WorkItemModel.state,
        func.count(WorkItemModel.id),
    ).group_by(WorkItemModel.work_kind, WorkItemModel.state).limit(128).all()
    queue_states = {
        state: count
        for state, count in work_states.items()
        if state in {
            ExecutionState.QUEUED.value,
            ExecutionState.ADMITTED.value,
            ExecutionState.READY.value,
            ExecutionState.RETRY_WAIT.value,
        }
    }
    oldest_queued = (
        db.query(func.min(WorkItemModel.created_at))
        .filter(
            WorkItemModel.state.in_(tuple(queue_states) or (ExecutionState.QUEUED.value,)),
            WorkItemModel.available_at <= now,
        )
        .scalar()
    )
    oldest_queue_seconds = None
    if oldest_queued is not None:
        stamp = oldest_queued if oldest_queued.tzinfo else oldest_queued.replace(tzinfo=timezone.utc)
        oldest_queue_seconds = max(0.0, (now - stamp).total_seconds())

    expired_work_leases = int(db.query(func.count(WorkLeaseModel.id)).filter(
        WorkLeaseModel.state == "ACTIVE", WorkLeaseModel.expires_at <= now
    ).scalar() or 0)
    provider_circuits: dict[str, dict[str, int]] = {}
    for provider, state, count in db.query(
        AIProviderHealthModel.provider,
        AIProviderHealthModel.circuit_state,
        func.count(AIProviderHealthModel.id),
    ).group_by(AIProviderHealthModel.provider, AIProviderHealthModel.circuit_state).limit(64).all():
        provider_circuits.setdefault(str(provider), {})[str(state)] = int(count)

    recently_used_models = [
        {"provider": str(provider), "model": str(model), "last_used_at": last_used.isoformat()}
        for provider, model, last_used in db.query(
            AIExecutionModel.provider,
            AIExecutionModel.model,
            func.max(AIExecutionModel.created_at),
        ).group_by(AIExecutionModel.provider, AIExecutionModel.model)
        .order_by(func.max(AIExecutionModel.created_at).desc())
        .limit(MAX_RECENT_MODELS)
        .all()
    ]
    usage_row = db.query(
        func.count(AIExecutionModel.id),
        func.sum(AIExecutionModel.input_tokens),
        func.sum(AIExecutionModel.output_tokens),
        func.count(AIExecutionModel.input_tokens),
        func.count(AIExecutionModel.output_tokens),
        func.sum(case((AIExecutionModel.success.is_(False), 1), else_=0)),
        func.sum(case((AIExecutionModel.fallback_reason.is_not(None), 1), else_=0)),
    ).filter(
        AIExecutionModel.created_at >= now - timedelta(hours=24),
        AIExecutionModel.created_at <= now,
    ).one()
    (ai_calls, input_sum, output_sum, input_count, output_count, failed_calls, fallback_calls) = usage_row
    registry = ModelCapabilityRegistry.from_settings(settings)
    configured_models = [
        {
            "provider": spec.provider.value,
            "model": spec.model,
            "enabled": spec.enabled,
            "capabilities": sorted(capability.value for capability in spec.capabilities),
        }
        for spec in sorted(registry.specifications, key=lambda item: (item.provider.value, item.model))[:MAX_CONFIGURED_MODELS]
    ]

    tools = AgentToolRegistry.canonical_metadata()
    tool_capabilities: dict[str, int] = {}
    for metadata in tools:
        key = metadata.capability.value
        tool_capabilities[key] = tool_capabilities.get(key, 0) + 1

    outbox_status = _counts(
        db.query(OutboxEventModel.status, func.count(OutboxEventModel.id))
        .group_by(OutboxEventModel.status).limit(16).all()
    )
    expired_outbox_leases = int(db.query(func.count(OutboxEventModel.id)).filter(
        OutboxEventModel.status == "PROCESSING", OutboxEventModel.lease_expires_at <= now
    ).scalar() or 0)
    reconciliation_status = _counts(
        db.query(ReconciliationRecordModel.status, func.count(ReconciliationRecordModel.id))
        .group_by(ReconciliationRecordModel.status).limit(16).all()
    )
    expired_reconciliation_leases = int(db.query(func.count(ReconciliationRecordModel.id)).filter(
        ReconciliationRecordModel.status == "RUNNING", ReconciliationRecordModel.lease_expires_at <= now
    ).scalar() or 0)

    try:
        from app.observability.metrics import replace_metric_gauges

        replace_metric_gauges(
            "repolens.work.items.sql_snapshot",
            [
                (count, {"repolens.work.kind": str(kind), "repolens.work.state": str(state)})
                for kind, state, count in work_snapshot_rows
            ],
        )
        replace_metric_gauges(
            "repolens.outbox.items.sql_snapshot",
            [(count, {"repolens.outbox.state": state}) for state, count in outbox_status.items()],
        )
        replace_metric_gauges(
            "repolens.reconciliation.items.sql_snapshot",
            [(count, {"repolens.reconciliation.state": state}) for state, count in reconciliation_status.items()],
        )
    except Exception:
        # Optional exporter state is never an operational authority.
        pass

    available = set(inspect(db.get_bind()).get_table_names())
    github_app: dict[str, Any] = {"enabled": bool(getattr(settings, "GITHUB_APP_ENABLED", False))}
    if "github_app_installations" in available:
        github_app["installations_by_status"] = _counts(
            db.query(GitHubAppInstallationModel.status, func.count(GitHubAppInstallationModel.installation_id))
            .group_by(GitHubAppInstallationModel.status).limit(16).all()
        )
    else:
        github_app["installations_by_status"] = None
    if "github_app_webhook_deliveries" in available:
        github_app["deliveries_last_24h_by_status"] = _counts(
            db.query(GitHubAppWebhookDeliveryModel.status, func.count(GitHubAppWebhookDeliveryModel.delivery_id))
            .filter(GitHubAppWebhookDeliveryModel.received_at >= now - timedelta(hours=24))
            .group_by(GitHubAppWebhookDeliveryModel.status).limit(16).all()
        )
    else:
        github_app["deliveries_last_24h_by_status"] = None

    return {
        "generated_at": now.isoformat(),
        "schema": schema,
        "checkpointer": checkpointer,
        "durable_work": {
            "items_by_state": work_states,
            "items_by_kind": work_kinds,
            "queued_by_state": queue_states,
            "oldest_runnable_queue_age_seconds": oldest_queue_seconds,
            "expired_active_lease_count": expired_work_leases,
        },
        "providers": {
            "circuits_by_provider_and_state": provider_circuits,
            "configured_capability_registry_version": registry.version,
            "configured_models": configured_models,
            "recently_used_models": recently_used_models,
            "recently_used_model_limit": MAX_RECENT_MODELS,
            "usage_last_24h": {
                "provider_attempts": int(ai_calls or 0),
                "failed_provider_attempts": int(failed_calls or 0),
                "fallback_attempts": int(fallback_calls or 0),
                "input_tokens_measured_sum": int(input_sum) if input_count else None,
                "input_token_measurement_count": int(input_count or 0),
                "output_tokens_measured_sum": int(output_sum) if output_count else None,
                "output_token_measurement_count": int(output_count or 0),
                "cost": {"status": "NOT_MEASURED", "source": None},
            },
        },
        "tools": {
            "authority": "AgentToolRegistry",
            "contract_version": tools[0].tool_version if tools else None,
            "registered_count": len(tools),
            "read_only_count": sum(1 for tool in tools if tool.read_only),
            "capabilities": tool_capabilities,
            "runtime_health": "NOT_PROBED_READ_ONLY_INVENTORY_ONLY",
        },
        "github_app": github_app,
        "outbox": {
            "items_by_status": outbox_status,
            "expired_processing_lease_count": expired_outbox_leases,
        },
        "reconciliation": {
            "items_by_status": reconciliation_status,
            "expired_running_lease_count": expired_reconciliation_leases,
        },
        "telemetry": _metric_telemetry_status(),
    }


def _metric_telemetry_status() -> dict[str, Any]:
    try:
        from app.observability.metrics import METRIC_CATALOG_VERSION, metrics_enabled

        return {
            "metric_catalog_version": METRIC_CATALOG_VERSION,
            "otel_metrics_active": metrics_enabled(),
        }
    except Exception:
        return {"metric_catalog_version": "unknown", "otel_metrics_active": False}


__all__ = [
    "CORE_REQUIRED_TABLES",
    "MAX_CONFIGURED_MODELS",
    "MAX_RECENT_MODELS",
    "build_operations_overview",
    "check_checkpointer_readiness",
    "schema_readiness",
]
