"""Conservative, provider-independent context estimation for admission and routing."""

from __future__ import annotations

from dataclasses import dataclass
import math

from app.llm.types import LLMRequest


@dataclass(frozen=True, slots=True)
class ContextEstimate:
    input_tokens: int
    requested_output_tokens: int
    total_tokens: int
    exact: bool = False


class ContextEstimator:
    """Estimate tokens without provider tokenizers or persisting prompt contents.

    The calculation intentionally overestimates ordinary source text: UTF-8 bytes
    are divided by three and per-message framing is added. Provider-reported usage
    replaces estimates when an attempt completes.
    """

    def __init__(self, *, bytes_per_token: float = 3.0, message_overhead_tokens: int = 12) -> None:
        if bytes_per_token <= 0:
            raise ValueError("bytes_per_token must be positive")
        self.bytes_per_token = bytes_per_token
        self.message_overhead_tokens = max(0, message_overhead_tokens)

    def estimate(self, request: LLMRequest) -> ContextEstimate:
        content_bytes = sum(len(message.content.encode("utf-8")) for message in request.messages)
        role_bytes = sum(len(message.role) for message in request.messages)
        input_tokens = max(
            1,
            math.ceil((content_bytes + role_bytes) / self.bytes_per_token)
            + len(request.messages) * self.message_overhead_tokens,
        )
        requested_output = request.max_tokens or min(4_096, request.budget.max_output_tokens)
        return ContextEstimate(
            input_tokens=input_tokens,
            requested_output_tokens=requested_output,
            total_tokens=input_tokens + requested_output,
        )

