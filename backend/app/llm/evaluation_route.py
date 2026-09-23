"""Async-scoped candidate routing for explicit system-evaluation runs.

The override is consumed by the canonical ``LLMRouter``. It never constructs
provider clients, mutates settings, or changes routing in sibling async tasks.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Iterator

from app.llm.types import LLMProvider, LLMRequest


@dataclass(frozen=True, slots=True)
class EvaluationModelRoute:
    provider: LLMProvider
    model: str

    def apply(self, request: LLMRequest) -> LLMRequest:
        """Pin a request to the candidate and disable all reusable responses."""
        return request.model_copy(update={
            "provider": self.provider,
            "model": self.model,
            "allow_escalation": False,
            "cache_mode": "disabled",
        })


_active_evaluation_route: ContextVar[EvaluationModelRoute | None] = ContextVar(
    "repolens_evaluation_model_route", default=None
)


@contextmanager
def evaluation_model_route(provider: LLMProvider | str, model: str) -> Iterator[EvaluationModelRoute]:
    """Temporarily pin current async execution to one registered candidate.

    The context is restored even when graph execution raises or is cancelled.
    Capability routing, provider health, structured-output validation, request
    and workflow budgets, and canonical provider adapters remain authoritative.
    """
    if not model or len(model) > 256:
        raise ValueError("Evaluation model must be a non-empty bounded identifier.")
    route = EvaluationModelRoute(provider=LLMProvider(provider), model=model)
    token = _active_evaluation_route.set(route)
    try:
        yield route
    finally:
        _active_evaluation_route.reset(token)


def apply_evaluation_model_route(request: LLMRequest) -> LLMRequest:
    """Apply the current evaluation route, if this task is inside its scope."""
    route = _active_evaluation_route.get()
    return route.apply(request) if route is not None else request


def current_evaluation_model_route() -> EvaluationModelRoute | None:
    return _active_evaluation_route.get()


__all__ = [
    "EvaluationModelRoute",
    "apply_evaluation_model_route",
    "current_evaluation_model_route",
    "evaluation_model_route",
]
