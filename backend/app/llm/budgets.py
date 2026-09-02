"""Reusable hard budgets for repository-facing AI workflows."""

from app.llm.types import AIRequestBudget, ModelCostTier


REPOSITORY_ANALYSIS_BUDGET = AIRequestBudget(
    max_ai_calls=2,
    max_input_tokens=12_000,
    max_output_tokens=2_400,
    max_escalation_tier=ModelCostTier.CHEAP,
    max_context_tokens=16_000,
)

REPOSITORY_VERIFICATION_BUDGET = AIRequestBudget(
    max_ai_calls=2,
    max_input_tokens=20_000,
    max_output_tokens=3_000,
    max_escalation_tier=ModelCostTier.CHEAP,
    max_context_tokens=24_000,
)

CHANGE_REVIEW_BUDGET = AIRequestBudget(
    max_ai_calls=2,
    max_input_tokens=24_000,
    max_output_tokens=4_000,
    max_escalation_tier=ModelCostTier.CHEAP,
    max_context_tokens=30_000,
)


__all__ = [
    "CHANGE_REVIEW_BUDGET",
    "REPOSITORY_ANALYSIS_BUDGET",
    "REPOSITORY_VERIFICATION_BUDGET",
]
