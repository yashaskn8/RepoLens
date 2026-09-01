"""Strict JSON parsing and bounded schema validation for untrusted model output."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping, Sequence

from app.llm.exceptions import LLMResponseValidationError
from app.llm.types import AIValidationResult, LLMProvider


@dataclass(frozen=True, slots=True)
class StructuredValidation:
    value: Any
    result: AIValidationResult
    confidence: float | None = None


class StructuredOutputGateway:
    """Validate model JSON before a workflow can consume it.

    This intentionally implements a small deterministic JSON Schema subset used by
    RepoLens contracts. Unknown schema keywords are ignored, but type, required,
    property, collection, enum, and numeric/string bounds fail closed.
    """

    def __init__(self, *, max_output_chars: int = 2_000_000, max_depth: int = 32) -> None:
        self.max_output_chars = max_output_chars
        self.max_depth = max_depth

    def validate(
        self,
        content: str,
        *,
        schema: Mapping[str, Any] | None,
        confidence_threshold: float | None,
        provider: LLMProvider,
        model: str,
    ) -> StructuredValidation:
        normalized = self._unwrap_json_fence(content)
        if len(normalized) > self.max_output_chars:
            raise LLMResponseValidationError(
                "Structured model output exceeds the validation size limit.",
                provider=provider,
                model=model,
            )
        try:
            value = json.loads(normalized)
        except (TypeError, json.JSONDecodeError) as exc:
            raise LLMResponseValidationError(
                f"Structured model output is not valid JSON ({exc.__class__.__name__}).",
                provider=provider,
                model=model,
            ) from exc

        try:
            if schema is not None:
                self._validate_value(value, schema, path="$", depth=0)
        except ValueError as exc:
            raise LLMResponseValidationError(
                f"Structured model output failed schema validation: {exc}",
                provider=provider,
                model=model,
            ) from exc

        confidence = self._confidence(value)
        result = AIValidationResult.VALID
        if confidence_threshold is not None and (confidence is None or confidence < confidence_threshold):
            result = AIValidationResult.UNCERTAIN
        return StructuredValidation(value=value, result=result, confidence=confidence)

    @staticmethod
    def _unwrap_json_fence(content: str) -> str:
        """Accept one whole-response JSON fence while rejecting surrounding prose."""
        stripped = content.strip()
        match = re.fullmatch(r"```(?:json)?\s*([\s\S]*?)\s*```", stripped, flags=re.IGNORECASE)
        return match.group(1).strip() if match else stripped

    def _validate_value(self, value: Any, schema: Mapping[str, Any], *, path: str, depth: int) -> None:
        if depth > self.max_depth:
            raise ValueError(f"{path} exceeds maximum nesting depth")
        if "enum" in schema and value not in schema["enum"]:
            raise ValueError(f"{path} is not one of the allowed values")
        if "const" in schema and value != schema["const"]:
            raise ValueError(f"{path} does not match the required constant")

        expected = schema.get("type")
        if isinstance(expected, list):
            valid_type = any(self._matches_type(value, item) for item in expected)
        elif isinstance(expected, str):
            valid_type = self._matches_type(value, expected)
        else:
            valid_type = True
        if not valid_type:
            raise ValueError(f"{path} has the wrong type")

        if isinstance(value, dict):
            required = schema.get("required", [])
            if not isinstance(required, Sequence) or isinstance(required, (str, bytes)):
                raise ValueError(f"{path} has an invalid required declaration")
            missing = [key for key in required if key not in value]
            if missing:
                raise ValueError(f"{path} is missing required properties: {', '.join(map(str, missing))}")
            properties = schema.get("properties", {})
            if not isinstance(properties, Mapping):
                raise ValueError(f"{path} has an invalid properties declaration")
            if schema.get("additionalProperties") is False:
                extras = sorted(set(value) - set(properties))
                if extras:
                    raise ValueError(f"{path} contains additional properties: {', '.join(extras)}")
            for key, child_schema in properties.items():
                if key in value and isinstance(child_schema, Mapping):
                    self._validate_value(value[key], child_schema, path=f"{path}.{key}", depth=depth + 1)

        if isinstance(value, list):
            minimum = schema.get("minItems")
            maximum = schema.get("maxItems")
            if isinstance(minimum, int) and len(value) < minimum:
                raise ValueError(f"{path} contains too few items")
            if isinstance(maximum, int) and len(value) > maximum:
                raise ValueError(f"{path} contains too many items")
            child_schema = schema.get("items")
            if isinstance(child_schema, Mapping):
                for index, item in enumerate(value):
                    self._validate_value(item, child_schema, path=f"{path}[{index}]", depth=depth + 1)

        if isinstance(value, str):
            minimum = schema.get("minLength")
            maximum = schema.get("maxLength")
            if isinstance(minimum, int) and len(value) < minimum:
                raise ValueError(f"{path} is shorter than allowed")
            if isinstance(maximum, int) and len(value) > maximum:
                raise ValueError(f"{path} is longer than allowed")
            pattern = schema.get("pattern")
            if isinstance(pattern, str) and re.search(pattern, value) is None:
                raise ValueError(f"{path} does not match the required pattern")

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if isinstance(minimum, (int, float)) and value < minimum:
                raise ValueError(f"{path} is below the minimum")
            if isinstance(maximum, (int, float)) and value > maximum:
                raise ValueError(f"{path} is above the maximum")

    @staticmethod
    def _matches_type(value: Any, expected: str) -> bool:
        return {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "null": value is None,
        }.get(expected, False)

    @staticmethod
    def _confidence(value: Any) -> float | None:
        if not isinstance(value, dict):
            return None
        confidence = value.get("confidence")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            numeric = float(confidence)
            if 0.0 <= numeric <= 1.0:
                return numeric
        return None
