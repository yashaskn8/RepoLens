"""Provider health registry with local and database-authoritative circuit breakers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Callable, Protocol

from sqlalchemy.orm import Session

from app.llm.exceptions import ProviderFailureCode
from app.llm.types import LLMProvider


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass(frozen=True, slots=True)
class ProviderHealthSnapshot:
    provider: LLMProvider
    model: str
    state: CircuitState
    consecutive_failures: int
    successes: int
    failures: int
    opened_until: datetime | None = None
    last_failure_code: ProviderFailureCode | None = None


class ProviderHealth(Protocol):
    def allow_request(self, provider: LLMProvider, model: str) -> bool: ...

    def record_success(self, provider: LLMProvider, model: str) -> None: ...

    def record_failure(
        self,
        provider: LLMProvider,
        model: str,
        code: ProviderFailureCode,
        *,
        retry_after_seconds: float | None = None,
    ) -> None: ...

    def snapshot(self, provider: LLMProvider, model: str) -> ProviderHealthSnapshot: ...


@dataclass(slots=True)
class _MutableHealth:
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    successes: int = 0
    failures: int = 0
    opened_until: datetime | None = None
    probe_claimed_until: datetime | None = None
    last_failure_code: ProviderFailureCode | None = None


class ProviderHealthRegistry:
    """Thread-safe local health cache for SQLite/single-worker operation."""

    def __init__(self, *, failure_threshold: int = 3, cooldown_seconds: float = 30.0) -> None:
        if failure_threshold < 1 or cooldown_seconds <= 0:
            raise ValueError("Circuit breaker limits must be positive")
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._states: dict[tuple[LLMProvider, str], _MutableHealth] = {}
        self._lock = RLock()

    def _entry(self, provider: LLMProvider, model: str) -> _MutableHealth:
        return self._states.setdefault((provider, model), _MutableHealth())

    def allow_request(self, provider: LLMProvider, model: str) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            state = self._entry(provider, model)
            if state.state == CircuitState.CLOSED:
                return True
            if state.state == CircuitState.OPEN:
                if state.opened_until is not None and state.opened_until > now:
                    return False
                state.state = CircuitState.HALF_OPEN
                state.probe_claimed_until = now + timedelta(seconds=self.cooldown_seconds)
                return True
            if state.probe_claimed_until is not None and state.probe_claimed_until > now:
                return False
            state.probe_claimed_until = now + timedelta(seconds=self.cooldown_seconds)
            return True

    def record_success(self, provider: LLMProvider, model: str) -> None:
        with self._lock:
            state = self._entry(provider, model)
            state.state = CircuitState.CLOSED
            state.consecutive_failures = 0
            state.successes += 1
            state.opened_until = None
            state.probe_claimed_until = None
            state.last_failure_code = None

    def record_failure(
        self,
        provider: LLMProvider,
        model: str,
        code: ProviderFailureCode,
        *,
        retry_after_seconds: float | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            state = self._entry(provider, model)
            state.failures += 1
            state.consecutive_failures += 1
            state.last_failure_code = code
            should_open = code == ProviderFailureCode.AUTH_FAILURE or state.consecutive_failures >= self.failure_threshold
            if should_open:
                cooldown = max(self.cooldown_seconds, retry_after_seconds or 0.0)
                state.state = CircuitState.OPEN
                state.opened_until = now + timedelta(seconds=cooldown)
                state.probe_claimed_until = None

    def snapshot(self, provider: LLMProvider, model: str) -> ProviderHealthSnapshot:
        with self._lock:
            state = self._entry(provider, model)
            return ProviderHealthSnapshot(
                provider=provider,
                model=model,
                state=state.state,
                consecutive_failures=state.consecutive_failures,
                successes=state.successes,
                failures=state.failures,
                opened_until=state.opened_until,
                last_failure_code=state.last_failure_code,
            )


class SQLAlchemyProviderHealthRegistry:
    """Database-authoritative circuit state for PostgreSQL multi-worker operation."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self.session_factory = session_factory
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds

    @staticmethod
    def _row(db: Session, provider: LLMProvider, model: str, *, lock: bool):
        from app.models.ai_execution import AIProviderHealthModel

        query = db.query(AIProviderHealthModel).filter(
            AIProviderHealthModel.provider == provider.value,
            AIProviderHealthModel.model == model,
        )
        if lock:
            query = query.with_for_update()
        row = query.one_or_none()
        if row is None:
            row = AIProviderHealthModel(provider=provider.value, model=model)
            db.add(row)
            db.flush()
        return row

    def allow_request(self, provider: LLMProvider, model: str) -> bool:
        now = datetime.now(timezone.utc)
        with self.session_factory() as db, db.begin():
            row = self._row(db, provider, model, lock=True)
            opened_until = _aware(row.opened_until)
            probe_until = _aware(row.probe_claimed_until)
            if row.circuit_state == CircuitState.CLOSED.value:
                return True
            if row.circuit_state == CircuitState.OPEN.value:
                if opened_until is not None and opened_until > now:
                    return False
                row.circuit_state = CircuitState.HALF_OPEN.value
                row.probe_claimed_until = now + timedelta(seconds=self.cooldown_seconds)
                row.version += 1
                row.updated_at = now
                return True
            if probe_until is not None and probe_until > now:
                return False
            row.probe_claimed_until = now + timedelta(seconds=self.cooldown_seconds)
            row.version += 1
            row.updated_at = now
            return True

    def record_success(self, provider: LLMProvider, model: str) -> None:
        now = datetime.now(timezone.utc)
        with self.session_factory() as db, db.begin():
            row = self._row(db, provider, model, lock=True)
            row.circuit_state = CircuitState.CLOSED.value
            row.consecutive_failures = 0
            row.successes += 1
            row.last_failure_code = None
            row.opened_until = None
            row.probe_claimed_until = None
            row.version += 1
            row.updated_at = now

    def record_failure(
        self,
        provider: LLMProvider,
        model: str,
        code: ProviderFailureCode,
        *,
        retry_after_seconds: float | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        with self.session_factory() as db, db.begin():
            row = self._row(db, provider, model, lock=True)
            row.failures += 1
            row.consecutive_failures += 1
            row.last_failure_code = code.value
            if code == ProviderFailureCode.AUTH_FAILURE or row.consecutive_failures >= self.failure_threshold:
                cooldown = max(self.cooldown_seconds, retry_after_seconds or 0.0)
                row.circuit_state = CircuitState.OPEN.value
                row.opened_until = now + timedelta(seconds=cooldown)
                row.probe_claimed_until = None
            row.version += 1
            row.updated_at = now

    def snapshot(self, provider: LLMProvider, model: str) -> ProviderHealthSnapshot:
        with self.session_factory() as db:
            row = self._row(db, provider, model, lock=False)
            db.commit()
            return ProviderHealthSnapshot(
                provider=provider,
                model=model,
                state=CircuitState(row.circuit_state),
                consecutive_failures=row.consecutive_failures,
                successes=row.successes,
                failures=row.failures,
                opened_until=_aware(row.opened_until),
                last_failure_code=(
                    ProviderFailureCode(row.last_failure_code) if row.last_failure_code else None
                ),
            )


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)

