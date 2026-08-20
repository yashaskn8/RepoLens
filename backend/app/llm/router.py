"""Canonical LLMRouter orchestrating task policy dispatch, provider adapters, and fallback execution."""

import logging
from typing import Dict, List, Optional, Tuple
from app.core.config import get_settings
from app.llm.adapters import GeminiAdapter, GroqAdapter, HuggingFaceAdapter, NvidiaAdapter
from app.llm.base import BaseLLMAdapter
from app.llm.exceptions import LLMAllFallbacksFailedError, LLMError
from app.llm.types import LLMProvider, LLMRequest, LLMResponse, TaskPolicy

logger = logging.getLogger(__name__)


class LLMRouter:
    """Canonical LLM Gateway Router.
    
    Dispatches LLM requests based on task policy to designated primary models and
    automatically executes fallback routes on provider failures or timeouts.
    """

    def __init__(
        self,
        adapters: Optional[Dict[LLMProvider, BaseLLMAdapter]] = None,
    ):
        self._adapters: Dict[LLMProvider, BaseLLMAdapter] = adapters or {
            LLMProvider.GEMINI: GeminiAdapter(),
            LLMProvider.GROQ: GroqAdapter(),
            LLMProvider.NVIDIA: NvidiaAdapter(),
            LLMProvider.HUGGINGFACE: HuggingFaceAdapter(),
        }

    def get_adapter(self, provider: LLMProvider) -> BaseLLMAdapter:
        """Retrieve registered adapter for a given provider."""
        if provider not in self._adapters:
            raise ValueError(f"No adapter registered for provider: {provider}")
        return self._adapters[provider]

    def register_adapter(self, provider: LLMProvider, adapter: BaseLLMAdapter) -> None:
        """Register or override an adapter (useful for testing and mocks)."""
        self._adapters[provider] = adapter

    def get_policy_routes(self, policy: TaskPolicy) -> Tuple[Tuple[LLMProvider, str], List[Tuple[LLMProvider, str]]]:
        """Return the primary (provider, model) and ordered list of fallback (provider, model) pairs."""
        settings = get_settings()

        routes: Dict[TaskPolicy, Tuple[Tuple[LLMProvider, str], List[Tuple[LLMProvider, str]]]] = {
            TaskPolicy.ARCHITECTURE: (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                ],
            ),
            TaskPolicy.INTEGRATION_CODE: (
                (LLMProvider.HUGGINGFACE, settings.MODEL_INTEGRATION_CODE),
                [
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                ],
            ),
            TaskPolicy.BUG_REASONING: (
                (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                ],
            ),
            TaskPolicy.SECURITY_REASONING: (
                (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                [
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                ],
            ),
            TaskPolicy.LIGHTWEIGHT_CLASSIFICATION: (
                (LLMProvider.GROQ, settings.MODEL_LIGHTWEIGHT_CLASSIFICATION),
                [
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                ],
            ),
            TaskPolicy.VERIFICATION: (
                (LLMProvider.NVIDIA, settings.MODEL_VERIFICATION),
                [
                    (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                ],
            ),
            TaskPolicy.RESEARCH: (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [
                    (LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING),
                    (LLMProvider.NVIDIA, settings.MODEL_BUG_REASONING),
                ],
            ),
        }

        return routes.get(
            policy,
            (
                (LLMProvider.GEMINI, settings.MODEL_ARCHITECTURE),
                [(LLMProvider.GROQ, settings.MODEL_SECURITY_REASONING)],
            ),
        )

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Route request according to policy/provider overrides with automatic fallback execution."""
        # 1. Direct explicit provider override
        if request.provider is not None:
            adapter = self.get_adapter(request.provider)
            return await adapter.generate(request)

        # 2. Determine policy route
        policy = request.task_policy or TaskPolicy.ARCHITECTURE
        primary, fallbacks = self.get_policy_routes(policy)
        execution_chain = [primary] + fallbacks

        attempted_errors: List[LLMError] = []

        for provider, model in execution_chain:
            try:
                adapter = self.get_adapter(provider)
                # Clone request with specific provider and model for this attempt
                attempt_request = request.model_copy(update={"provider": provider, "model": model})
                response = await adapter.generate(attempt_request)
                return response
            except LLMError as exc:
                logger.warning(
                    f"LLM execution failed for policy '{policy.value}' on {provider.value} ({model}): {exc.message}. "
                    f"Attempting fallback..."
                )
                attempted_errors.append(exc)
            except Exception as exc:
                logger.error(f"Unexpected error executing {provider.value} ({model}): {str(exc)}")
                attempted_errors.append(
                    LLMError(f"Unexpected execution failure: {str(exc)}", provider=provider, model=model)
                )

        # If all routes in the execution chain failed
        error_summary = "; ".join([f"[{err.provider.value if err.provider else 'unknown'}]: {err.message}" for err in attempted_errors])
        raise LLMAllFallbacksFailedError(
            f"All LLM candidate models for policy '{policy.value}' failed: {error_summary}",
            attempted_errors=attempted_errors,
        )


# Global default router instance
_default_router: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Return singleton LLMRouter instance."""
    global _default_router
    if _default_router is None:
        _default_router = LLMRouter()
    return _default_router
