"""Shared, deterministic cloud-capacity governor for one analysis workflow."""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any

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

    def __init__(self, *, mode: str, max_cloud_calls: int, max_cloud_tokens: int) -> None:
        self.mode = mode
        self.max_cloud_calls = max(0, int(max_cloud_calls))
        self.max_cloud_tokens = max(0, int(max_cloud_tokens))
        self.used_cloud_calls = 0
        self.used_cloud_tokens = 0

    @classmethod
    def from_settings(cls) -> "WorkflowCloudBudget":
        settings = get_settings()
        mode = settings.AI_ECONOMY_MODE
        return cls(
            mode=mode,
            max_cloud_calls=getattr(settings, f"AI_ECONOMY_{mode.upper()}_MAX_CLOUD_CALLS"),
            max_cloud_tokens=getattr(settings, f"AI_ECONOMY_{mode.upper()}_MAX_CLOUD_TOKENS"),
        )

    @property
    def strict(self) -> bool:
        return self.mode == "strict"

    def reserve(self, provider: LLMProvider, *, input_tokens: int, output_tokens: int) -> bool:
        """Reserve one actual remote execution; local Ollama is never charged."""
        if provider == LLMProvider.OLLAMA:
            return True
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
