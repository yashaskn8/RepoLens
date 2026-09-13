"""Capability catalog loader and validation for RepoLens evaluation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.evaluation.ground_truth.schemas import EvaluationStage, RuleType

_DEFAULT_CATALOG_PATH = (
    Path(__file__).resolve().parents[3]
    / "evaluation_data"
    / "ground_truth"
    / "v1"
    / "catalog.json"
)


class CapabilityRule(BaseModel):
    """Machine-readable description of a verified RepoLens capability."""

    rule_id: str = Field(..., description="Unique rule identifier")
    subsystem: str = Field(..., description="RepoLens subsystem (security, correctness, contract, impact)")
    rule_type: RuleType = Field(..., description="ISSUE_SIGNAL or STRUCTURAL_FACT")
    evaluation_stage: EvaluationStage = Field(..., description="Native stage where this rule emits output")
    implementation: str = Field(..., description="File:callable or File:class that produces the output")
    output_field: Optional[str] = Field(default=None, description="Field on the result object containing deltas/impacts")
    implementation_languages: List[str] = Field(..., description="Languages handled by underlying parser/IR")
    benchmark_languages: List[str] = Field(..., description="Languages empirically validated in benchmark cases")
    output_kind: str = Field(..., description="Domain class or kind emitted by RepoLens")
    evidence_level: str = Field(..., description="Granularity of evidence")
    existing_test: str = Field(..., description="Test file proving capability exists today")
    native_predicate: Optional[str] = Field(default=None, description="Native predicate code or expression")
    limitations: List[str] = Field(default_factory=list, description="Known boundaries or constraints")

    model_config = ConfigDict(extra="forbid")


class CapabilityCatalog(BaseModel):
    """Full collection of verified RepoLens capabilities."""

    catalog_version: str = Field(default="1.0.0")
    capabilities: List[CapabilityRule] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

    def get_rule_map(self) -> Dict[str, CapabilityRule]:
        return {rule.rule_id: rule for rule in self.capabilities}


_CACHED_CATALOG: Optional[CapabilityCatalog] = None


def load_capability_catalog(path: Optional[Path | str] = None) -> CapabilityCatalog:
    """Load and validate the capability catalog JSON."""
    global _CACHED_CATALOG
    target_path = Path(path) if path else _DEFAULT_CATALOG_PATH
    if not target_path.exists():
        raise FileNotFoundError(f"Capability catalog not found at: {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    catalog = CapabilityCatalog.model_validate(data)
    if path is None:
        _CACHED_CATALOG = catalog
    return catalog


def get_rule(rule_id: str, catalog: Optional[CapabilityCatalog] = None) -> Optional[CapabilityRule]:
    """Look up a capability rule by its identifier."""
    cat = catalog or _CACHED_CATALOG or load_capability_catalog()
    return cat.get_rule_map().get(rule_id)
