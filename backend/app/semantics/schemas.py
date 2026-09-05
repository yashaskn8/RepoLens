"""Small normalized semantic IR projected from Tree-sitter source facts."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SemanticCertainty(str, Enum):
    PROVEN = "PROVEN"
    POSSIBLE = "POSSIBLE"


class SemanticFact(BaseModel):
    fact_id: str
    language: str
    file_path: str
    symbol: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    commit_sha: str
    content_hash: str
    evidence_id: str
    certainty: SemanticCertainty


class SemanticFunction(SemanticFact):
    name: str
    parameter_names: list[str] = Field(default_factory=list, max_length=64)
    is_async: bool = False
    is_route_handler: bool = False


class SemanticParameter(SemanticFact):
    name: str
    position: int = Field(ge=0)


class SemanticCallSite(SemanticFact):
    callee: str
    argument_expressions: list[str] = Field(default_factory=list, max_length=32)
    argument_names: list[list[str]] = Field(default_factory=list, max_length=32)
    result_target: str | None = None
    awaited: bool = False
    result_discarded: bool = False


class SemanticAssignment(SemanticFact):
    target: str
    source_names: list[str] = Field(default_factory=list, max_length=32)


class SemanticReturn(SemanticFact):
    source_names: list[str] = Field(default_factory=list, max_length=32)


class SemanticGuard(SemanticFact):
    guard_kind: str
    expression: str
    referenced_names: list[str] = Field(default_factory=list, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SemanticResourceUse(SemanticFact):
    resource_kind: str
    operation: str
    argument_names: list[str] = Field(default_factory=list, max_length=32)


class SemanticSource(SemanticFact):
    source_kind: str
    name: str


class SemanticSink(SemanticFact):
    sink_kind: str
    name: str


class SemanticSanitizer(SemanticFact):
    sanitizer_kind: str
    name: str
    argument_names: list[str] = Field(default_factory=list, max_length=32)


class SemanticFlowEdge(BaseModel):
    source_fact_id: str
    target_fact_id: str
    relation: str
    certainty: SemanticCertainty


class SemanticFlow(BaseModel):
    source: SemanticSource
    sink: SemanticSink
    transformations: list[str] = Field(default_factory=list, max_length=32)
    sanitizers: list[SemanticSanitizer] = Field(default_factory=list, max_length=16)
    guards: list[SemanticGuard] = Field(default_factory=list, max_length=16)
    edges: list[SemanticFlowEdge] = Field(default_factory=list, max_length=64)
    certainty: SemanticCertainty
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)
    call_depth: int = Field(default=0, ge=0, le=8)


class SemanticProgram(BaseModel):
    coverage: dict[str, Any] = Field(default_factory=lambda: {"complete": True})
    functions: list[SemanticFunction] = Field(default_factory=list)
    parameters: list[SemanticParameter] = Field(default_factory=list)
    calls: list[SemanticCallSite] = Field(default_factory=list)
    assignments: list[SemanticAssignment] = Field(default_factory=list)
    returns: list[SemanticReturn] = Field(default_factory=list)
    guards: list[SemanticGuard] = Field(default_factory=list)
    resources: list[SemanticResourceUse] = Field(default_factory=list)
    sources: list[SemanticSource] = Field(default_factory=list)
    sinks: list[SemanticSink] = Field(default_factory=list)
    sanitizers: list[SemanticSanitizer] = Field(default_factory=list)


__all__ = [name for name in globals() if name.startswith("Semantic")]
