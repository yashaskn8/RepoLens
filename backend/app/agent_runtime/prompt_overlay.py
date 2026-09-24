"""Context-local prompt overlays used only by evaluation runs.

Production prompt constants remain immutable.  The full-analysis evaluator installs
an overlay around one trial; ContextVar gives async tasks isolation and the token
reset guarantees exception-safe restoration.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator


def prompt_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PromptCandidateOverlay:
    optimization_run_id: str
    candidate_id: str
    component: str
    baseline_version: str
    baseline_digest: str
    candidate_version: str
    candidate_digest: str
    prompt_text: str

    def __post_init__(self) -> None:
        if not self.optimization_run_id or len(self.optimization_run_id) > 128:
            raise ValueError("optimization run identity must be non-empty and bounded")
        if not self.candidate_id or len(self.candidate_id) > 128:
            raise ValueError("candidate identity must be non-empty and bounded")
        if not self.component or len(self.component) > 128:
            raise ValueError("prompt component must be non-empty and bounded")
        if prompt_digest(self.prompt_text) != self.candidate_digest:
            raise ValueError("candidate prompt digest does not match its content")
        for digest in (self.baseline_digest, self.candidate_digest):
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError("prompt digests must be lowercase SHA-256 values")


_ACTIVE_PROMPT_OVERLAY: ContextVar[PromptCandidateOverlay | None] = ContextVar(
    "repolens_evaluation_prompt_overlay", default=None
)


def active_prompt_overlay() -> PromptCandidateOverlay | None:
    """Expose overlay presence for evaluation-only causal-isolation checks."""
    return _ACTIVE_PROMPT_OVERLAY.get()


@contextmanager
def evaluation_prompt_overlay(overlay: PromptCandidateOverlay | None) -> Iterator[None]:
    """Install one candidate overlay for the current async execution context."""
    token = _ACTIVE_PROMPT_OVERLAY.set(overlay)
    try:
        yield
    finally:
        _ACTIVE_PROMPT_OVERLAY.reset(token)


def resolve_agent_prompt(component: str, baseline_prompt: str) -> str:
    """Return the current candidate only when its frozen baseline matches."""
    overlay = _ACTIVE_PROMPT_OVERLAY.get()
    if overlay is None or overlay.component != component:
        return baseline_prompt
    if prompt_digest(baseline_prompt) != overlay.baseline_digest:
        raise RuntimeError("prompt overlay baseline no longer matches the active production prompt")
    return overlay.prompt_text


def resolve_agent_prompt_version(component: str, baseline_version: str) -> str:
    overlay = _ACTIVE_PROMPT_OVERLAY.get()
    if overlay is None or overlay.component != component:
        return baseline_version
    if overlay.baseline_version != baseline_version:
        raise RuntimeError("prompt overlay semantic version no longer matches the active production prompt")
    return overlay.candidate_version


__all__ = [
    "PromptCandidateOverlay",
    "active_prompt_overlay",
    "evaluation_prompt_overlay",
    "prompt_digest",
    "resolve_agent_prompt",
    "resolve_agent_prompt_version",
]
