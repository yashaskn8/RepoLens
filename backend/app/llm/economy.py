"""Shared, deterministic cloud-capacity governor for one analysis workflow."""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any, Mapping

from app.core.config import get_settings
from app.llm.types import LLMProvider


@dataclass(frozen=True, slots=True)
class CloudBudgetSnapshot:
    mode: str
    max_cloud_calls: int
    max_cloud_tokens: int
    used_cloud_calls: int
    used_cloud_tokens: int
    exhausted: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "max_cloud_calls": self.max_cloud_calls,
            "max_cloud_tokens": self.max_cloud_tokens,
            "used_cloud_calls": self.used_cloud_calls,
            "used_cloud_tokens": self.used_cloud_tokens,
            "exhausted": self.exhausted,
        }


class WorkflowCloudBudget:
    """Small in-memory governor shared by all async specialists in one scan."""

    def __init__(self, *, mode: str, max_cloud_calls: int, max_cloud_tokens: int,
                 used_cloud_calls: int = 0, used_cloud_tokens: int = 0) -> None:
        self.mode = mode
        self.max_cloud_calls = max(0, int(max_cloud_calls))
        self.max_cloud_tokens = max(0, int(max_cloud_tokens))
        self.used_cloud_calls = max(0, int(used_cloud_calls))
        self.used_cloud_tokens = max(0, int(used_cloud_tokens))
        self._schedule: dict[str, int] = {}
        self._scheduled_grants: dict[str, int] = {}

    @classmethod
    def from_settings(cls) -> "WorkflowCloudBudget":
        settings = get_settings()
        mode = settings.AI_ECONOMY_MODE
        return cls(
            mode=mode,
            max_cloud_calls=getattr(settings, f"AI_ECONOMY_{mode.upper()}_MAX_CLOUD_CALLS"),
            max_cloud_tokens=getattr(settings, f"AI_ECONOMY_{mode.upper()}_MAX_CLOUD_TOKENS"),
        )

    @classmethod
    def from_snapshot(
        cls,
        snapshot: Mapping[str, Any] | None,
        *,
        mode: str | None = None,
        max_cloud_calls: int | None = None,
        max_cloud_tokens: int | None = None,
    ) -> "WorkflowCloudBudget":
        """Hydrate a budget monotonically from checkpoint/work metadata.

        Old checkpoints may not contain economy fields.  In that case the
        configured ceiling is used with zero usage; malformed snapshots are
        treated the same way rather than granting unbounded capacity.
        """
        raw = snapshot if isinstance(snapshot, Mapping) else {}
        configured = cls.from_settings()
        def _integer(value: Any, fallback: int) -> int:
            try:
                return max(0, int(value))
            except (TypeError, ValueError):
                return max(0, int(fallback))
        return cls(
            mode=str(raw.get("mode") or mode or configured.mode),
            max_cloud_calls=_integer(raw.get("max_cloud_calls", max_cloud_calls if max_cloud_calls is not None else configured.max_cloud_calls), configured.max_cloud_calls),
            max_cloud_tokens=_integer(raw.get("max_cloud_tokens", max_cloud_tokens if max_cloud_tokens is not None else configured.max_cloud_tokens), configured.max_cloud_tokens),
            used_cloud_calls=_integer(raw.get("used_cloud_calls", 0) or 0, 0),
            used_cloud_tokens=_integer(raw.get("used_cloud_tokens", 0) or 0, 0),
        )

    def hydrate(self, snapshot: Mapping[str, Any] | None) -> None:
        """Merge a persisted snapshot without ever decreasing usage."""
        if not isinstance(snapshot, Mapping):
            return
        # The checkpoint also carries the original ceilings.  A resumed
        # worker must not gain allowance because process-local settings were
        # raised after the crash; retain the stricter persisted ceiling.
        for name in ("max_cloud_calls", "max_cloud_tokens"):
            try:
                persisted_cap = max(0, int(snapshot.get(name)))
            except (TypeError, ValueError):
                persisted_cap = None
            if persisted_cap is not None:
                current_cap = getattr(self, name)
                setattr(self, name, min(current_cap, persisted_cap))
        try:
            calls = max(0, int(snapshot.get("used_cloud_calls", 0) or 0))
        except (TypeError, ValueError):
            calls = 0
        try:
            tokens = max(0, int(snapshot.get("used_cloud_tokens", 0) or 0))
        except (TypeError, ValueError):
            tokens = 0
        self.used_cloud_calls = max(self.used_cloud_calls, calls)
        self.used_cloud_tokens = max(self.used_cloud_tokens, tokens)

    def set_schedule(self, priorities: Mapping[str, int]) -> None:
        """Register a deterministic admission order before specialists start."""
        self._schedule = {
            str(key): max(0, int(value))
            for key, value in priorities.items()
            if str(key)
        }
        self._scheduled_grants.clear()

    def _scheduled_allowed(self, task_key: str | None) -> bool:
        if not task_key or not self._schedule:
            return True
        ordered = [key for key, _ in sorted(self._schedule.items(), key=lambda item: (-item[1], item[0]))]
        # Reserve at least one deterministic slot for the highest-value work;
        # tasks outside the capacity are denied before provider invocation.
        capacity = min(len(ordered), self.max_cloud_calls)
        if task_key not in ordered[:capacity]:
            return False
        return True

    @property
    def strict(self) -> bool:
        return self.mode == "strict"

    def reserve(
        self,
        provider: LLMProvider,
        *,
        input_tokens: int,
        output_tokens: int,
        task_key: str | None = None,
        priority: int = 0,
    ) -> bool:
        """Reserve one actual remote execution; local Ollama is never charged."""
        if provider == LLMProvider.OLLAMA:
            return True
        if self._schedule and task_key and task_key not in self._schedule:
            self._schedule[task_key] = max(0, int(priority))
        if not self._scheduled_allowed(task_key):
            return False
        requested = max(0, int(input_tokens)) + max(0, int(output_tokens))
        if self.used_cloud_calls + 1 > self.max_cloud_calls:
            return False
        if self.used_cloud_tokens + requested > self.max_cloud_tokens:
            return False
        self.used_cloud_calls += 1
        self.used_cloud_tokens += requested
        return True

    def snapshot(self) -> CloudBudgetSnapshot:
        return CloudBudgetSnapshot(
            mode=self.mode,
            max_cloud_calls=self.max_cloud_calls,
            max_cloud_tokens=self.max_cloud_tokens,
            used_cloud_calls=self.used_cloud_calls,
            used_cloud_tokens=self.used_cloud_tokens,
            exhausted=(
                self.used_cloud_calls >= self.max_cloud_calls
                or self.used_cloud_tokens >= self.max_cloud_tokens
            ),
        )

    def release(self, provider: LLMProvider, *, input_tokens: int, output_tokens: int) -> None:
        """Undo a reservation when no provider invocation occurred."""
        if provider == LLMProvider.OLLAMA:
            return
        self.used_cloud_calls = max(0, self.used_cloud_calls - 1)
        requested = max(0, int(input_tokens)) + max(0, int(output_tokens))
        self.used_cloud_tokens = max(0, self.used_cloud_tokens - requested)


_current_budget: ContextVar[WorkflowCloudBudget | None] = ContextVar(
    "repolens_workflow_cloud_budget", default=None
)


def bind_workflow_cloud_budget(budget: WorkflowCloudBudget) -> Token:
    return _current_budget.set(budget)


def reset_workflow_cloud_budget(token: Token) -> None:
    _current_budget.reset(token)


def current_workflow_cloud_budget() -> WorkflowCloudBudget | None:
    return _current_budget.get()


__all__ = [
    "CloudBudgetSnapshot",
    "WorkflowCloudBudget",
    "bind_workflow_cloud_budget",
    "current_workflow_cloud_budget",
    "reset_workflow_cloud_budget",
]
