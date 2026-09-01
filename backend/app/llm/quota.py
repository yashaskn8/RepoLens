"""Provider allowance ledger with reserve/settle semantics for AI attempts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Callable, Mapping, Protocol
from uuid import uuid4

from sqlalchemy.orm import Session

from app.llm.types import LLMProvider


@dataclass(frozen=True, slots=True)
class ProviderQuotaLimit:
    max_calls: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None

    def __post_init__(self) -> None:
        for value in (self.max_calls, self.max_input_tokens, self.max_output_tokens):
            if value is not None and value < 0:
                raise ValueError("Provider quota limits cannot be negative")


@dataclass(frozen=True, slots=True)
class QuotaReservation:
    reservation_id: str
    execution_id: str
    provider: LLMProvider
    model: str
    estimated_input_tokens: int
    estimated_output_tokens: int


class ProviderQuotaLedger(Protocol):
    def reserve(
        self,
        *,
        execution_id: str,
        provider: LLMProvider,
        model: str,
        request_id: str | None,
        tenant_id: str | None,
        estimated_input_tokens: int,
        estimated_output_tokens: int,
    ) -> QuotaReservation | None: ...

    def settle(
        self,
        reservation: QuotaReservation,
        *,
        consume: bool,
        actual_input_tokens: int | None,
        actual_output_tokens: int | None,
    ) -> None: ...


@dataclass(slots=True)
class _Usage:
    reserved_calls: int = 0
    reserved_input: int = 0
    reserved_output: int = 0
    consumed_calls: int = 0
    consumed_input: int = 0
    consumed_output: int = 0


class LocalProviderQuotaLedger:
    """Single-process ledger for SQLite development and deterministic tests."""

    def __init__(
        self,
        limits: Mapping[tuple[LLMProvider, str], ProviderQuotaLimit] | None = None,
    ) -> None:
        self._limits = dict(limits or {})
        self._usage: dict[tuple[LLMProvider, str], _Usage] = {}
        self._reservations: dict[str, tuple[QuotaReservation, bool]] = {}
        self._lock = RLock()

    def _limit(self, provider: LLMProvider, model: str) -> ProviderQuotaLimit:
        return self._limits.get((provider, model), self._limits.get((provider, "*"), ProviderQuotaLimit()))

    def reserve(
        self,
        *,
        execution_id: str,
        provider: LLMProvider,
        model: str,
        request_id: str | None,
        tenant_id: str | None,
        estimated_input_tokens: int,
        estimated_output_tokens: int,
    ) -> QuotaReservation | None:
        del request_id, tenant_id
        key = (provider, model)
        with self._lock:
            limit = self._limit(provider, model)
            usage = self._usage.setdefault(key, _Usage())
            if not _fits(limit.max_calls, usage.reserved_calls + usage.consumed_calls, 1):
                return None
            if not _fits(
                limit.max_input_tokens,
                usage.reserved_input + usage.consumed_input,
                estimated_input_tokens,
            ):
                return None
            if not _fits(
                limit.max_output_tokens,
                usage.reserved_output + usage.consumed_output,
                estimated_output_tokens,
            ):
                return None
            reservation = QuotaReservation(
                reservation_id=str(uuid4()),
                execution_id=execution_id,
                provider=provider,
                model=model,
                estimated_input_tokens=estimated_input_tokens,
                estimated_output_tokens=estimated_output_tokens,
            )
            usage.reserved_calls += 1
            usage.reserved_input += estimated_input_tokens
            usage.reserved_output += estimated_output_tokens
            self._reservations[reservation.reservation_id] = (reservation, False)
            return reservation

    def settle(
        self,
        reservation: QuotaReservation,
        *,
        consume: bool,
        actual_input_tokens: int | None,
        actual_output_tokens: int | None,
    ) -> None:
        key = (reservation.provider, reservation.model)
        with self._lock:
            current = self._reservations.get(reservation.reservation_id)
            if current is None or current[1]:
                return
            usage = self._usage[key]
            usage.reserved_calls -= 1
            usage.reserved_input -= reservation.estimated_input_tokens
            usage.reserved_output -= reservation.estimated_output_tokens
            if consume:
                usage.consumed_calls += 1
                usage.consumed_input += max(0, actual_input_tokens or reservation.estimated_input_tokens)
                usage.consumed_output += max(0, actual_output_tokens or 0)
            self._reservations[reservation.reservation_id] = (reservation, True)

    def usage(self, provider: LLMProvider, model: str) -> dict[str, int]:
        with self._lock:
            usage = self._usage.get((provider, model), _Usage())
            return {
                "reserved_calls": usage.reserved_calls,
                "reserved_input_tokens": usage.reserved_input,
                "reserved_output_tokens": usage.reserved_output,
                "consumed_calls": usage.consumed_calls,
                "consumed_input_tokens": usage.consumed_input,
                "consumed_output_tokens": usage.consumed_output,
            }


class SQLAlchemyProviderQuotaLedger:
    """Row-locked quota authority for PostgreSQL; SQLite remains single-worker."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        limits: Mapping[tuple[LLMProvider, str], ProviderQuotaLimit] | None = None,
        *,
        window_seconds: int = 86_400,
        reservation_ttl_seconds: int = 300,
        scope_id: str = "*",
    ) -> None:
        if window_seconds < 1 or reservation_ttl_seconds < 1:
            raise ValueError("Quota window and reservation TTL must be positive")
        self.session_factory = session_factory
        self.limits = dict(limits or {})
        self.window_seconds = window_seconds
        self.reservation_ttl_seconds = reservation_ttl_seconds
        self.scope_id = scope_id

    def _limit(self, provider: LLMProvider, model: str) -> ProviderQuotaLimit:
        return self.limits.get((provider, model), self.limits.get((provider, "*"), ProviderQuotaLimit()))

    def _window(self, now: datetime) -> tuple[str, datetime, datetime]:
        epoch = int(now.timestamp())
        start_epoch = epoch - (epoch % self.window_seconds)
        start = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
        end = start + timedelta(seconds=self.window_seconds)
        return str(start_epoch), start, end

    def reserve(
        self,
        *,
        execution_id: str,
        provider: LLMProvider,
        model: str,
        request_id: str | None,
        tenant_id: str | None,
        estimated_input_tokens: int,
        estimated_output_tokens: int,
    ) -> QuotaReservation | None:
        from app.models.ai_execution import AIQuotaBucketModel, AIQuotaReservationModel

        now = datetime.now(timezone.utc)
        window_key, starts, ends = self._window(now)
        limit = self._limit(provider, model)
        with self.session_factory() as db, db.begin():
            bucket = (
                db.query(AIQuotaBucketModel)
                .filter(
                    AIQuotaBucketModel.scope_id == self.scope_id,
                    AIQuotaBucketModel.provider == provider.value,
                    AIQuotaBucketModel.model == model,
                    AIQuotaBucketModel.window_key == window_key,
                )
                .with_for_update()
                .one_or_none()
            )
            if bucket is None:
                bucket = AIQuotaBucketModel(
                    scope_id=self.scope_id,
                    provider=provider.value,
                    model=model,
                    window_key=window_key,
                    window_starts_at=starts,
                    window_ends_at=ends,
                    call_limit=limit.max_calls,
                    input_token_limit=limit.max_input_tokens,
                    output_token_limit=limit.max_output_tokens,
                )
                db.add(bucket)
                db.flush()
            if not _fits(bucket.call_limit, bucket.reserved_calls + bucket.consumed_calls, 1):
                return None
            if not _fits(
                bucket.input_token_limit,
                bucket.reserved_input_tokens + bucket.consumed_input_tokens,
                estimated_input_tokens,
            ):
                return None
            if not _fits(
                bucket.output_token_limit,
                bucket.reserved_output_tokens + bucket.consumed_output_tokens,
                estimated_output_tokens,
            ):
                return None
            reservation_id = str(uuid4())
            bucket.reserved_calls += 1
            bucket.reserved_input_tokens += estimated_input_tokens
            bucket.reserved_output_tokens += estimated_output_tokens
            bucket.version += 1
            bucket.updated_at = now
            db.add(
                AIQuotaReservationModel(
                    id=reservation_id,
                    bucket_id=bucket.id,
                    execution_id=execution_id,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    estimated_input_tokens=estimated_input_tokens,
                    estimated_output_tokens=estimated_output_tokens,
                    expires_at=now + timedelta(seconds=self.reservation_ttl_seconds),
                )
            )
        return QuotaReservation(
            reservation_id=reservation_id,
            execution_id=execution_id,
            provider=provider,
            model=model,
            estimated_input_tokens=estimated_input_tokens,
            estimated_output_tokens=estimated_output_tokens,
        )

    def settle(
        self,
        reservation: QuotaReservation,
        *,
        consume: bool,
        actual_input_tokens: int | None,
        actual_output_tokens: int | None,
    ) -> None:
        from app.models.ai_execution import AIQuotaBucketModel, AIQuotaReservationModel

        now = datetime.now(timezone.utc)
        with self.session_factory() as db, db.begin():
            row = (
                db.query(AIQuotaReservationModel)
                .filter(AIQuotaReservationModel.id == reservation.reservation_id)
                .with_for_update()
                .one_or_none()
            )
            if row is None or row.state != "RESERVED":
                return
            bucket = (
                db.query(AIQuotaBucketModel)
                .filter(AIQuotaBucketModel.id == row.bucket_id)
                .with_for_update()
                .one()
            )
            bucket.reserved_calls -= 1
            bucket.reserved_input_tokens -= row.estimated_input_tokens
            bucket.reserved_output_tokens -= row.estimated_output_tokens
            if consume:
                row.actual_input_tokens = max(0, actual_input_tokens or row.estimated_input_tokens)
                row.actual_output_tokens = max(0, actual_output_tokens or 0)
                bucket.consumed_calls += 1
                bucket.consumed_input_tokens += row.actual_input_tokens
                bucket.consumed_output_tokens += row.actual_output_tokens
                row.state = "COMMITTED"
            else:
                row.state = "RELEASED"
            row.settled_at = now
            bucket.version += 1
            bucket.updated_at = now

    def reconcile_expired(self, *, limit: int = 500) -> int:
        from app.models.ai_execution import AIQuotaBucketModel, AIQuotaReservationModel

        now = datetime.now(timezone.utc)
        released = 0
        with self.session_factory() as db, db.begin():
            rows = (
                db.query(AIQuotaReservationModel)
                .filter(
                    AIQuotaReservationModel.state == "RESERVED",
                    AIQuotaReservationModel.expires_at <= now,
                )
                .order_by(AIQuotaReservationModel.expires_at.asc())
                .limit(max(1, limit))
                .with_for_update()
                .all()
            )
            for row in rows:
                bucket = (
                    db.query(AIQuotaBucketModel)
                    .filter(AIQuotaBucketModel.id == row.bucket_id)
                    .with_for_update()
                    .one()
                )
                bucket.reserved_calls -= 1
                bucket.reserved_input_tokens -= row.estimated_input_tokens
                bucket.reserved_output_tokens -= row.estimated_output_tokens
                bucket.version += 1
                bucket.updated_at = now
                row.state = "EXPIRED"
                row.settled_at = now
                released += 1
        return released


def _fits(limit: int | None, used: int, requested: int) -> bool:
    return limit is None or used + requested <= limit

