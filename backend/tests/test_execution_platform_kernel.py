"""Focused invariants for the shared durable execution authority."""

from datetime import datetime, timedelta, timezone
import hashlib
import threading
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.execution import (
    BudgetConsumption,
    DomainOutcome,
    DurableExecutionEngine,
    EnqueueRequest,
    ExecutionState,
    FailureCode,
    IdempotencyConflict,
    RequestBudget,
    ResourceProfile,
    SideEffectClass,
    WorkKind,
)
from app.models.execution import FailureRecordModel, RequestBudgetModel, ResourcePoolModel, WorkItemModel
from app.models.scan import ScanModel
from app.models.user import UserModel
from app.execution.dispatcher import DurableWorkDispatcher
from app.execution.dispatcher import WorkHandlerResult


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


@pytest.fixture
def execution_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(
        UserModel(
            id="tenant-1",
            email="execution@example.com",
            password_hash="not-used",
            role="USER",
        )
    )
    session.commit()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _request(
    key: str,
    *,
    resource_id: str = "scan-1",
    side_effect: SideEffectClass = SideEffectClass.SAFE_RECOMPUTATION,
) -> EnqueueRequest:
    return EnqueueRequest(
        tenant_id="tenant-1",
        request_id=f"request-{key}",
        requested_by="user:tenant-1",
        policy_snapshot_id="policy-sha256:abc",
        work_kind=WorkKind.GITHUB_DELIVERY if side_effect == SideEffectClass.EXTERNAL_SIDE_EFFECT else WorkKind.SCAN,
        resource_type="SCAN",
        resource_id=resource_id,
        idempotency_key=key,
        request_digest=hashlib.sha256(resource_id.encode()).hexdigest(),
        resource_profile=(
            ResourceProfile.GITHUB_WRITE
            if side_effect == SideEffectClass.EXTERNAL_SIDE_EFFECT
            else ResourceProfile.SMALL_REPO_SCAN
        ),
        budget=RequestBudget(
            max_wall_clock_seconds=300,
            max_analyzer_seconds=60,
            max_ai_calls=1,
            max_input_tokens=100,
            max_output_tokens=100,
            max_escalation_tier=1,
            max_retrieval_context_tokens=100,
            max_embedding_calls=1,
            max_report_bytes=1024,
            max_report_pages=10,
        ),
        side_effect_class=side_effect,
        external_idempotency_key=f"github:{resource_id}" if side_effect == SideEffectClass.EXTERNAL_SIDE_EFFECT else None,
    )


def test_idempotent_enqueue_bounded_claim_and_budget_exhaustion(execution_db):
    clock = MutableClock()
    engine = DurableExecutionEngine(execution_db, lease_seconds=30, clock=clock)
    first = engine.enqueue(_request("same-key"))
    duplicate = engine.enqueue(_request("same-key"))
    assert duplicate.work_item_id == first.work_item_id
    assert duplicate.reused is True

    with pytest.raises(IdempotencyConflict):
        engine.enqueue(_request("same-key", resource_id="different-scan"))

    second = engine.enqueue(_request("other-key", resource_id="scan-2"))
    claim = engine.claim_next("worker-a")
    assert claim is not None and claim.work_item_id == first.work_item_id
    assert engine.claim_next("worker-b") is None  # SQLite worker and tenant capacity are database-backed.
    engine.start(claim.work_item_id, claim.lease_token)

    allowed = engine.consume_budget(
        claim.work_item_id,
        claim.lease_token,
        BudgetConsumption(ai_calls=1, input_tokens=80),
    )
    assert allowed.allowed is True
    bounded = engine.consume_budget(
        claim.work_item_id,
        claim.lease_token,
        BudgetConsumption(ai_calls=1),
    )
    assert bounded.allowed is False
    assert bounded.exhausted_dimension == "ai_calls"

    work = execution_db.get(WorkItemModel, first.work_item_id)
    budget = execution_db.query(RequestBudgetModel).filter_by(work_item_id=work.id).one()
    assert work.state == ExecutionState.SUCCEEDED.value
    assert work.domain_outcome == DomainOutcome.BOUNDED.value
    assert work.coverage_summary["status"] == "TRUNCATED"
    assert budget.used_ai_calls == 1
    assert budget.exhausted_dimension == "ai_calls"
    assert all(pool.reserved_units == 0 for pool in execution_db.query(ResourcePoolModel).all())
    assert engine.claim_next("worker-b").work_item_id == second.work_item_id


def test_expiry_retries_safe_work_but_requires_external_reconciliation(execution_db):
    clock = MutableClock()
    engine = DurableExecutionEngine(execution_db, lease_seconds=10, clock=clock)
    safe = engine.enqueue(_request("safe"))
    safe_claim = engine.claim_next("worker-a")
    engine.start(safe.work_item_id, safe_claim.lease_token)
    clock.advance(11)
    recovered = engine.recover_expired()
    assert recovered.retry_wait == 1
    safe_row = execution_db.get(WorkItemModel, safe.work_item_id)
    assert safe_row.state == ExecutionState.RETRY_WAIT.value

    retried = engine.claim_next("worker-b")
    engine.start(retried.work_item_id, retried.lease_token)
    engine.complete(
        retried.work_item_id,
        retried.lease_token,
        outcome=DomainOutcome.DEGRADED,
        coverage_summary={"status": "UNAVAILABLE", "reason": "One optional analyzer was unavailable."},
    )

    external = engine.enqueue(
        _request("external", resource_id="delivery-1", side_effect=SideEffectClass.EXTERNAL_SIDE_EFFECT)
    )
    external_claim = engine.claim_next("worker-c")
    engine.start(external.work_item_id, external_claim.lease_token)
    engine.mark_side_effect_started(
        external.work_item_id,
        external_claim.lease_token,
        external_operation_id="github-request-123",
    )
    clock.advance(11)
    recovered = engine.recover_expired()
    assert recovered.uncertain == 1
    external_row = execution_db.get(WorkItemModel, external.work_item_id)
    assert external_row.state == ExecutionState.FAILED.value
    assert external_row.reconciliation_required is True
    assert engine.claim_next("worker-d") is None


def test_orphan_reconciliation_trusts_existing_domain_row_over_process_memory(execution_db):
    """An absent process-local task entry cannot terminate SQL-authoritative work."""
    scan_id = str(uuid4())
    execution_db.add(
        ScanModel(
            id=scan_id,
            owner_user_id="tenant-1",
            repository_url="https://github.com/org/repo.git",
            status="RUNNING",
        )
    )
    execution_db.commit()
    engine = DurableExecutionEngine(execution_db, lease_seconds=60)
    enqueued = engine.enqueue(_request("orphan-safety", resource_id=scan_id))
    claim = engine.claim_next("same-process-worker")
    engine.start(enqueued.work_item_id, claim.lease_token)

    reconciled = DurableWorkDispatcher._reconcile_missing_active_work(execution_db, limit=10)

    execution_db.refresh(execution_db.get(WorkItemModel, enqueued.work_item_id))
    assert reconciled == 0
    assert execution_db.get(WorkItemModel, enqueued.work_item_id).state == ExecutionState.RUNNING.value


def test_terminal_execution_reconciliation_closes_stuck_scan(execution_db):
    scan_id = str(uuid4())
    execution_db.add(
        ScanModel(
            id=scan_id,
            owner_user_id="tenant-1",
            repository_url="https://github.com/org/repo.git",
            status="RUNNING",
            model_metadata={"index_coverage": {"indexed_files": 10}},
        )
    )
    execution_db.commit()
    engine = DurableExecutionEngine(execution_db, lease_seconds=60)
    enqueued = engine.enqueue(_request("terminal-reconcile", resource_id=scan_id))
    claim = engine.claim_next("worker-a")
    engine.start(enqueued.work_item_id, claim.lease_token)
    engine.fail(
        enqueued.work_item_id,
        claim.lease_token,
        code=FailureCode.INTERNAL_INVARIANT_VIOLATION,
        public_message="Analysis stopped safely.",
        retryable=False,
    )

    reconciled = DurableWorkDispatcher._reconcile_terminal_scan_statuses(execution_db, limit=10)
    execution_db.expire_all()
    scan = execution_db.get(ScanModel, scan_id)

    assert reconciled == 1
    assert scan.status == "FAILED"
    assert scan.completed_at is not None
    assert scan.model_metadata["failure_code"] == FailureCode.INTERNAL_INVARIANT_VIOLATION.value
    assert scan.model_metadata["index_coverage"] == {"indexed_files": 10}


@pytest.mark.asyncio
async def test_scan_domain_runs_off_dispatcher_event_loop(monkeypatch):
    observed = {}
    dispatcher_thread = threading.get_ident()

    async def fake_scan(**_kwargs):
        observed["thread"] = threading.get_ident()

    monkeypatch.setattr("app.api.routes.scans.execute_background_scan", fake_scan)
    monkeypatch.setattr(DurableWorkDispatcher, "_scan_payload", lambda _scan_id: ("https://github.com/org/repo.git", "main"))
    monkeypatch.setattr(
        DurableWorkDispatcher,
        "_scan_result",
        lambda _scan_id: WorkHandlerResult(
            outcome=DomainOutcome.COMPLETE,
            coverage_summary={"status": "COMPLETE"},
        ),
    )

    result = await DurableWorkDispatcher._execute_domain(
        type("Claim", (), {"work_kind": WorkKind.SCAN, "resource_id": "scan-id"})()
    )

    assert result.outcome == DomainOutcome.COMPLETE
    assert observed["thread"] != dispatcher_thread
