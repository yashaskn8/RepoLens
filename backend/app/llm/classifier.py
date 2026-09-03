"""Lightweight, deterministic task and complexity classifier for LLM routing.

Provides zero-overhead, explainable classification using task policies, capabilities,
context size, schema complexity, and prompt signals to avoid unnecessary expensive model calls.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional

from app.core.config import get_settings
from app.llm.types import LLMMessage, LLMRequest, ModelCapability, TaskPolicy


class TaskCategory(str, Enum):
    """Categorization determining provider selection and execution strategy."""

    SIMPLE_GENERATION = "simple_generation"
    COMPLEX_REASONING = "complex_reasoning"
    RETRIEVAL = "retrieval"


# Heuristic keyword signals for text inspection
_COMPLEX_SIGNALS = re.compile(
    r"(?i)\b(analyze|analysis|architectural constraints|compare|trade-?offs?|multi-?step|recommendations?|"
    r"vulnerability|root cause|security invariant|refactor|proof|evaluate|edge cases?|concurrency|memory leak)\b"
)

_SIMPLE_SIGNALS = re.compile(
    r"(?i)\b(summarize|summary|briefly|short explanation|rewrite|classify|classification|extract|intent|ping|hello)\b"
)

_RETRIEVAL_SIGNALS = re.compile(
    r"(?i)\b(search|find documents?|semantic similarity|retrieve|rank|rerank|embeddings?)\b"
)


class TaskClassifier:
    """Deterministic classifier routing LLM requests without recursive LLM overhead."""

    @classmethod
    def classify(
        cls,
        request: LLMRequest,
        fallback_from_simple: bool = False,
    ) -> TaskCategory:
        """Deterministically classify an LLMRequest into a TaskCategory.

        Rules:
        1. Explicit retrieval capabilities/signals -> RETRIEVAL
        2. Escalation from previous simple provider failure -> COMPLEX_REASONING
        3. Strict reasoning policies (Bug, Security, Fix Planning, Patch) -> COMPLEX_REASONING
        4. Heavy context (> ROUTER_COMPLEXITY_CONTEXT_THRESHOLD tokens/chars) -> COMPLEX_REASONING
        5. Complex structured output schemas -> COMPLEX_REASONING
        6. Lightweight policies (Classification, Short Summary, Extraction) -> SIMPLE_GENERATION
        7. Text pattern heuristics -> COMPLEX_REASONING vs SIMPLE_GENERATION
        8. Default -> SIMPLE_GENERATION (Cloudflare default provider)
        """
        settings = get_settings()

        # 1. Retrieval detection
        if request.capability in (ModelCapability.EMBEDDING, ModelCapability.RERANKING):
            return TaskCategory.RETRIEVAL

        # 2. Prior failure escalation
        if fallback_from_simple:
            return TaskCategory.COMPLEX_REASONING

        # 3. Policy & Capability-driven classification
        complex_policies = {
            TaskPolicy.BUG_REASONING,
            TaskPolicy.SECURITY_REASONING,
            TaskPolicy.FIX_PLANNING,
            TaskPolicy.PATCH_GENERATION,
            TaskPolicy.PATCH_CRITIC,
            TaskPolicy.CHANGE_REVIEW,
        }
        if request.task_policy in complex_policies:
            return TaskCategory.COMPLEX_REASONING

        complex_capabilities = {
            ModelCapability.DEEP_REASONING,
            ModelCapability.SECURITY_REASONING,
            ModelCapability.CODE_REASONING,
            ModelCapability.PATCH_GENERATION,
            ModelCapability.VERIFICATION,
        }
        if request.capability in complex_capabilities:
            return TaskCategory.COMPLEX_REASONING

        simple_policies = {
            TaskPolicy.LIGHTWEIGHT_CLASSIFICATION,
        }
        if request.task_policy in simple_policies:
            return TaskCategory.SIMPLE_GENERATION

        simple_capabilities = {
            ModelCapability.CLASSIFICATION,
        }
        if request.capability in simple_capabilities:
            return TaskCategory.SIMPLE_GENERATION

        # 4. Context length threshold inspection
        context_len = sum(len(m.content) for m in request.messages)
        threshold = getattr(settings, "ROUTER_COMPLEXITY_CONTEXT_THRESHOLD", 2000)
        if context_len > threshold:
            return TaskCategory.COMPLEX_REASONING

        # 5. Schema complexity inspection
        if request.output_schema is not None:
            properties = request.output_schema.get("properties", {})
            # If schema has more than 3 fields or nested object/array schemas, treat as complex
            if len(properties) > 3 or any(
                isinstance(v, dict) and v.get("type") in ("object", "array")
                for v in properties.values()
            ):
                return TaskCategory.COMPLEX_REASONING

        # 6. Prompt text heuristic signals
        all_text = " ".join(m.content for m in request.messages)
        if _RETRIEVAL_SIGNALS.search(all_text):
            return TaskCategory.RETRIEVAL
        if _COMPLEX_SIGNALS.search(all_text):
            return TaskCategory.COMPLEX_REASONING
        if _SIMPLE_SIGNALS.search(all_text):
            return TaskCategory.SIMPLE_GENERATION

        # 7. Default to lightweight simple generation (Cloudflare Workers AI)
        return TaskCategory.SIMPLE_GENERATION
