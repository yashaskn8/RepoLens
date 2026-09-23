"""Canonical, content-free identity for the system configuration under test."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import ast
from pathlib import Path
from typing import Any, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent_runtime.prompt_overlay import PromptCandidateOverlay
from app.agent_runtime.prompts import INVESTIGATOR_PROMPT_VERSION, INVESTIGATOR_SYSTEM_PROMPT
from app.agent_runtime.schemas import (
    INVESTIGATOR_DECISION_SCHEMA_VERSION,
    INVESTIGATOR_STATE_VERSION,
    MAX_INVESTIGATOR_STEPS,
    MAX_INVESTIGATOR_TARGETS,
    MAX_INVESTIGATOR_TOOL_CALLS,
)
from app.agent_tools.registry import AgentToolRegistry
from app.agent_tools.schemas import AGENT_TOOL_CONTRACT_VERSION
from app.core.config import Settings, get_settings
from app.evaluation.agent.contract import EVALUATION_CONTRACT_VERSION, evaluation_contract_hash
from app.evaluation.agent.loader import canonical_json
from app.llm.capabilities import ModelCapabilityRegistry
from app.llm.router import LLMRouter, get_llm_router
from app.llm.types import LLMProvider


class _IdentityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PromptComponentIdentity(_IdentityModel):
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=128)
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class RuntimeFlag(_IdentityModel):
    name: str = Field(min_length=1, max_length=128)
    value: bool


class SystemBudgetProfile(_IdentityModel):
    max_targets: int = Field(ge=1, le=MAX_INVESTIGATOR_TARGETS)
    max_model_decisions_per_target: int = Field(ge=1, le=MAX_INVESTIGATOR_STEPS)
    max_tool_calls_per_target: int = Field(ge=1, le=MAX_INVESTIGATOR_TOOL_CALLS)
    max_context_tokens: int = Field(ge=1, le=12_000)
    max_output_tokens: int = Field(ge=1, le=700)
    max_ai_calls_per_decision: int = Field(ge=1, le=1)
    model_timeout_seconds: float = Field(ge=1.0, le=60.0)
    tool_timeout_seconds: float = Field(ge=1.0, le=30.0)
    economy_mode: str = Field(min_length=1, max_length=16)
    max_workflow_cloud_calls: int = Field(ge=0)
    max_workflow_cloud_tokens: int = Field(ge=0)
    max_retry_attempts: int = Field(ge=0, le=1)
    effective_context_tokens: int = Field(ge=1)
    effective_output_tokens: int = Field(ge=1)


class AgentSystemIdentity(_IdentityModel):
    """Identity names the actual evaluator scope and its effective resources."""

    schema_version: Literal["agent-system-identity/1.1", "agent-system-identity/1.2"] = "agent-system-identity/1.1"
    scope: Literal["PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH", "FULL_ANALYSIS_GRAPH"] = "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH"
    model_provider: LLMProvider | None = None
    model_identifier: str = Field(min_length=1, max_length=256)
    model_revision: str | None = Field(default=None, max_length=256)
    generation_temperature: float = Field(ge=0.0, le=2.0)
    prompt_components: tuple[PromptComponentIdentity, ...] = Field(min_length=1, max_length=16)
    tool_contract_version: str = Field(min_length=1, max_length=32)
    tool_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_manifest_count: int = Field(ge=1, le=32)
    state_version: str = Field(min_length=1, max_length=64)
    decision_schema_version: str = Field(min_length=1, max_length=64)
    context_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    workflow_implementation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_harness_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    router_policy_version: str = Field(min_length=1, max_length=64)
    model_registry_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_contract_version: str = Field(min_length=1, max_length=64)
    evaluation_contract_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget_profile: SystemBudgetProfile
    feature_flags: tuple[RuntimeFlag, ...] = Field(max_length=16)
    cache_policy: Literal["DISABLED_EXACT_SEMANTIC_AND_SINGLEFLIGHT"] = "DISABLED_EXACT_SEMANTIC_AND_SINGLEFLIGHT"
    fallback_policy: Literal["EXACT_CANDIDATE_ONLY_NO_CROSS_MODEL_FALLBACK"] = "EXACT_CANDIDATE_ONLY_NO_CROSS_MODEL_FALLBACK"
    source_revision: str | None = Field(default=None, max_length=128)
    graph_contract_version: str | None = Field(default=None, max_length=64, exclude_if=lambda value: value is None)
    graph_identity_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$", exclude_if=lambda value: value is None)
    compatibility_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    system_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_digests(self) -> "AgentSystemIdentity":
        payload = self.model_dump(mode="json", exclude={"compatibility_digest", "system_digest"})
        if self.schema_version == "agent-system-identity/1.1":
            if self.scope != "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH":
                raise ValueError("identity schema 1.1 is reserved for investigator-graph scope")
            payload.pop("graph_contract_version", None)
            payload.pop("graph_identity_digest", None)
        elif self.scope != "FULL_ANALYSIS_GRAPH" or not self.graph_contract_version or not self.graph_identity_digest:
            raise ValueError("identity schema 1.2 requires a full-analysis graph identity")
        expected_system = _digest(payload)
        compatibility = dict(payload)
        for key in ("model_provider", "model_identifier", "model_revision"):
            compatibility.pop(key, None)
        candidate_prompts = (
            {"evidence-investigator"}
            if self.scope == "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH"
            else {
                "evidence-investigator", "architecture-agent", "integration-agent", "security-agent",
                "bug-agent", "verifier-agent", "revision-agent",
            }
        )
        compatibility["prompt_components"] = [
            component for component in compatibility["prompt_components"]
            if component["name"] not in candidate_prompts
        ]
        expected_compatibility = _digest(compatibility)
        if self.system_digest != expected_system:
            raise ValueError("system identity digest does not match its canonical content")
        if self.compatibility_digest != expected_compatibility:
            raise ValueError("system compatibility digest does not match its canonical content")
        return self


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _source_digest(module_names: Iterable[str]) -> str:
    sources: dict[str, str] = {}
    for name in sorted(module_names):
        module = importlib.import_module(name)
        sources[name] = inspect.getsource(module)
    return _digest(sources)


def _module_prompt_digest(module_name: str) -> str:
    """Hash only stable system-prompt literals, keeping prompt candidates separate from code identity."""
    module = importlib.import_module(module_name)
    tree = ast.parse(inspect.getsource(module))
    values: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [
            target.id for target in targets if isinstance(target, ast.Name)
        ]
        if any(name.lower().endswith("system_prompt") or name.lower() == "system_prompt" for name in names):
            values.append(ast.dump(node.value, include_attributes=False))
    if not values:
        # Deterministic-only nodes still receive identity, without pretending they have a prompt.
        values = [inspect.getsource(module)]
    return _digest(sorted(values))


def _workflow_source_digest(module_names: Iterable[str]) -> str:
    """Hash workflow code while replacing prompt assignments with stable sentinels."""
    sources: dict[str, str] = {}
    for name in sorted(module_names):
        module = importlib.import_module(name)
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [target.id for target in targets if isinstance(target, ast.Name)]
            if any("prompt" in item.lower() and ("system" in item.lower() or item.lower() == "system_prompt") for item in names):
                node.value = ast.Constant(value="<prompt-content-is-identified-separately>")
        sources[name] = ast.unparse(tree)
    return _digest(sources)


FULL_ANALYSIS_GRAPH_CONTRACT_VERSION = "full-analysis-graph/1.1"
FULL_ANALYSIS_EVALUATION_CONTRACT_VERSION = "full-analysis-evaluation/1.5"
FULL_ANALYSIS_GRAPH_CONTRACT = {
    "version": FULL_ANALYSIS_GRAPH_CONTRACT_VERSION,
    "nodes": [
        "mapper", "architecture", "integration", "security", "bug", "verifier",
        "mcp_enrich", "investigator_prepare", "investigator_decide", "investigator_tool",
        "investigator_compact", "investigator_complete", "revise", "finalize", "finalize_uncertain",
    ],
    "edges": [
        ["START", "mapper"], ["mapper", "architecture|integration|security|bug"],
        ["architecture|integration|security|bug", "verifier"],
        ["verifier", "finalize|mcp_enrich|investigator_prepare|finalize_uncertain"],
        ["mcp_enrich", "revise"], ["investigator_prepare", "investigator_decide"],
        ["investigator_decide", "investigator_tool|investigator_complete"],
        ["investigator_tool", "investigator_compact"],
        ["investigator_compact", "investigator_decide|investigator_complete"],
        ["investigator_complete", "investigator_prepare|revise|finalize_uncertain"],
        ["revise", "verifier"], ["finalize|finalize_uncertain", "END"],
    ],
    "revision_limit": 1,
    "specialist_opportunity_trace_contract": "specialist-opportunity/1.0",
}


def full_analysis_graph_identity_digest() -> str:
    return _digest({
        "contract": FULL_ANALYSIS_GRAPH_CONTRACT,
        "implementation": _source_digest(["app.agents.graph"]),
    })


def full_analysis_evaluation_contract_hash(graph_digest: str | None = None) -> str:
    """Bind the full-graph evaluator, structural judge, and graph contract."""
    return _digest({
        "version": FULL_ANALYSIS_EVALUATION_CONTRACT_VERSION,
        "graph_identity_digest": graph_digest or full_analysis_graph_identity_digest(),
        "judge_implementation": _source_digest([
            "app.evaluation.ground_truth.matcher",
            "app.evaluation.ground_truth.schemas",
            "app.evaluation.system.full_analysis",
            "app.evaluation.system.specialist_attribution",
            "app.agents.specialist_provenance",
            "app.specialist_candidates",
        ]),
    })


def _tool_manifest(registry: AgentToolRegistry) -> tuple[str, int]:
    manifest = []
    for item in registry.list_tools():
        input_schema = item.input_schema
        properties = input_schema.get("properties", {}) if isinstance(input_schema, dict) else {}
        manifest.append({
            "name": item.tool_name,
            "version": item.tool_version,
            "capability": item.capability.value,
            "description_digest": _digest(item.description),
            "read_only": item.read_only,
            "deterministic": item.deterministic,
            "input_schema_digest": _digest(item.input_schema),
            "output_schema_digest": _digest(item.output_schema),
            "snapshot_binding_required": "snapshot_id" in properties,
        })
    return _digest(manifest), len(manifest)


def _evaluation_harness_digest() -> str:
    modules = _source_digest([
        "app.evaluation.agent.contract",
        "app.evaluation.agent.fixtures",
        "app.evaluation.agent.gate",
        "app.evaluation.agent.grading",
        "app.evaluation.agent.loader",
        "app.evaluation.agent.runner",
        "app.evaluation.agent.schemas",
        "app.evaluation.system.cli",
        "app.evaluation.system.comparison",
        "app.evaluation.system.identity",
        "app.evaluation.system.runner",
        "app.evaluation.system.schemas",
        "app.evaluation.system.full_analysis",
    ])
    gate_path = Path(__file__).resolve().parents[3] / "evaluation_data" / "agent" / "v1" / "regression_gate.json"
    gate_digest = hashlib.sha256(gate_path.read_bytes()).hexdigest()
    return _digest({"implementation": modules, "committed_regression_gate": gate_digest})


def build_agent_system_identity(
    *,
    provider: LLMProvider | str | None,
    model: str,
    registry: AgentToolRegistry,
    settings: Settings | None = None,
    router: LLMRouter | None = None,
    source_revision: str | None = None,
    scope: str = "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH",
    prompt_overlay: PromptCandidateOverlay | None = None,
) -> AgentSystemIdentity:
    """Derive a stable identity from canonical runtime contracts and sources."""
    if not model or len(model) > 256:
        raise ValueError("model identifier must be non-empty and bounded")
    configured = settings or get_settings()
    canonical_router = router or get_llm_router()
    capability_gateway = canonical_router._capability_gateway
    capability_registry: ModelCapabilityRegistry = capability_gateway.registry
    selected_provider = LLMProvider(provider) if provider is not None else None
    specification = (
        capability_registry.get(selected_provider, model)
        if selected_provider is not None else None
    )
    effective_context = min(
        configured.AGENT_INVESTIGATOR_CONTEXT_TOKENS + 700,
        specification.context_window_tokens if specification else configured.AGENT_INVESTIGATOR_CONTEXT_TOKENS + 700,
    )
    effective_output = min(
        700,
        specification.max_output_tokens if specification else 700,
    )
    mode = configured.AI_ECONOMY_MODE.upper()
    budget = SystemBudgetProfile(
        max_targets=configured.AGENT_INVESTIGATOR_MAX_TARGETS,
        max_model_decisions_per_target=configured.AGENT_INVESTIGATOR_MAX_STEPS,
        max_tool_calls_per_target=configured.AGENT_INVESTIGATOR_MAX_TOOL_CALLS,
        max_context_tokens=configured.AGENT_INVESTIGATOR_CONTEXT_TOKENS,
        max_output_tokens=700,
        max_ai_calls_per_decision=1,
        model_timeout_seconds=configured.AGENT_INVESTIGATOR_MODEL_TIMEOUT_SECONDS,
        tool_timeout_seconds=configured.AGENT_INVESTIGATOR_TOOL_TIMEOUT_SECONDS,
        economy_mode=configured.AI_ECONOMY_MODE,
        max_workflow_cloud_calls=getattr(configured, f"AI_ECONOMY_{mode}_MAX_CLOUD_CALLS"),
        max_workflow_cloud_tokens=getattr(configured, f"AI_ECONOMY_{mode}_MAX_CLOUD_TOKENS"),
        max_retry_attempts=0,
        effective_context_tokens=effective_context,
        effective_output_tokens=effective_output,
    )
    tool_digest, tool_count = _tool_manifest(registry)
    prompt_components = (
        PromptComponentIdentity(
            name="evidence-investigator",
            version=INVESTIGATOR_PROMPT_VERSION,
            content_digest=_digest(INVESTIGATOR_SYSTEM_PROMPT),
        ),
        PromptComponentIdentity(
            name="decision-schema",
            version=INVESTIGATOR_DECISION_SCHEMA_VERSION,
            content_digest=_digest(importlib.import_module("app.agent_runtime.schemas").INVESTIGATOR_DECISION_OUTPUT_SCHEMA),
        ),
    )
    context_digest = _source_digest([
        "app.agent_runtime.context",
        "app.agent_runtime.policy",
    ])
    if scope == "FULL_ANALYSIS_GRAPH":
        workflow_implementation_digest = _workflow_source_digest([
            "app.agents.mapper", "app.agents.architecture", "app.agents.integration",
            "app.agents.security", "app.agents.bug", "app.agents.verifier",
            "app.agents.investigator", "app.agents.revision", "app.agents.mcp_enrichment",
            "app.agent_runtime.stuck_detector", "app.agents.graph", "app.agents.state",
            "app.agents.specialist_provenance", "app.context.slices", "app.specialist_candidates",
        ])
    elif scope == "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH":
        workflow_implementation_digest = _source_digest([
            "app.agents.investigator",
            "app.agent_runtime.stuck_detector",
            "app.agents.graph",
        ])
    else:
        raise ValueError("unsupported system evaluation scope")
    retrieval_digest = _source_digest([
        "app.agent_tools.context",
        "app.agent_tools.tools",
        "app.agent_tools.registry",
        "app.retrieval.tokens",
    ])
    evaluation_digest = _evaluation_harness_digest()
    full_graph_digest = full_analysis_graph_identity_digest() if scope == "FULL_ANALYSIS_GRAPH" else None
    active_evaluation_contract_version = (
        FULL_ANALYSIS_EVALUATION_CONTRACT_VERSION
        if scope == "FULL_ANALYSIS_GRAPH" else EVALUATION_CONTRACT_VERSION
    )
    active_evaluation_contract_hash = (
        full_analysis_evaluation_contract_hash(full_graph_digest)
        if scope == "FULL_ANALYSIS_GRAPH" else evaluation_contract_hash()
    )
    router_digest = _digest({
        "routing_policy_version": capability_gateway.routing_policy.version,
        "model_registry_digest": capability_registry.version,
        "candidate_policy": "exact provider/model; one capability candidate; no cross-model fallback",
        "implementation_digest": _source_digest([
            "app.llm.evaluation_route",
            "app.llm.router",
            "app.llm.gateway",
            "app.llm.capabilities",
            "app.llm.economy",
            "app.llm.cache",
            "app.llm.structured",
        ]),
    })
    if scope == "FULL_ANALYSIS_GRAPH":
        prompt_components = (
            PromptComponentIdentity(name="mapper-agent", version="mapper/1.0", content_digest=_module_prompt_digest("app.agents.mapper")),
            PromptComponentIdentity(name="architecture-agent", version="architecture-agent/3.0", content_digest=_module_prompt_digest("app.agents.architecture")),
            PromptComponentIdentity(name="integration-agent", version="integration/1.0", content_digest=_module_prompt_digest("app.agents.integration")),
            PromptComponentIdentity(name="security-agent", version="security-agent/3.0", content_digest=_module_prompt_digest("app.agents.security")),
            PromptComponentIdentity(name="bug-agent", version="bug-agent/3.0", content_digest=_module_prompt_digest("app.agents.bug")),
            PromptComponentIdentity(name="verifier-agent", version="finding-verifier/2.0", content_digest=_module_prompt_digest("app.agents.verifier")),
            PromptComponentIdentity(name="revision-agent", version="revision-agent/1.0", content_digest=_module_prompt_digest("app.agents.revision")),
            prompt_components[0], prompt_components[1],
        )
        # Registered prompt identities bind the exact prompt text, not the
        # containing module's AST. This gives the Improvement Lab a baseline
        # digest that can be compared byte-for-byte with its overlay contract.
        from app.evaluation.improvement.registry import OptimizablePromptRegistry

        optimizable_prompts = OptimizablePromptRegistry()
        prompt_components = tuple(
            PromptComponentIdentity(
                name=item.name,
                version=optimizable_prompts.current_version(item.name),
                content_digest=optimizable_prompts.current_digest(item.name),
            ) if item.name in optimizable_prompts.names else item
            for item in prompt_components
        )
    if prompt_overlay is not None:
        if scope != "FULL_ANALYSIS_GRAPH":
            raise ValueError("prompt candidates are supported only by full-analysis evaluation")
        baseline_component = next(
            (item for item in prompt_components if item.name == prompt_overlay.component),
            None,
        )
        if baseline_component is None:
            raise ValueError("prompt overlay component is not present in the full-analysis identity")
        from app.evaluation.improvement.registry import OptimizablePromptRegistry

        prompt_registry = OptimizablePromptRegistry()
        if (
            baseline_component.version != prompt_overlay.baseline_version
            or baseline_component.content_digest != prompt_overlay.baseline_digest
            or prompt_registry.current_digest(prompt_overlay.component) != prompt_overlay.baseline_digest
        ):
            raise ValueError("prompt overlay semantic or content baseline is stale")
        prompt_components = tuple(
            PromptComponentIdentity(
                name=item.name,
                version=prompt_overlay.candidate_version,
                content_digest=prompt_overlay.candidate_digest,
            ) if item.name == prompt_overlay.component else item
            for item in prompt_components
        )
    raw = {
        "schema_version": "agent-system-identity/1.2" if scope == "FULL_ANALYSIS_GRAPH" else "agent-system-identity/1.1",
        "scope": scope,
        "model_provider": selected_provider.value if selected_provider else None,
        "model_identifier": model,
        "model_revision": specification.model_revision if specification else None,
        "generation_temperature": 0.0,
        "prompt_components": [item.model_dump(mode="json") for item in prompt_components],
        "tool_contract_version": AGENT_TOOL_CONTRACT_VERSION,
        "tool_manifest_digest": tool_digest,
        "tool_manifest_count": tool_count,
        "state_version": INVESTIGATOR_STATE_VERSION,
        "decision_schema_version": INVESTIGATOR_DECISION_SCHEMA_VERSION,
        "context_policy_digest": context_digest,
        "workflow_implementation_digest": workflow_implementation_digest,
        "evaluation_harness_digest": evaluation_digest,
        "retrieval_policy_digest": retrieval_digest,
        "router_policy_version": capability_gateway.routing_policy.version,
        "model_registry_digest": capability_registry.version,
        "evaluation_contract_version": active_evaluation_contract_version,
        "evaluation_contract_hash": active_evaluation_contract_hash,
        "budget_profile": budget.model_dump(mode="json"),
        "feature_flags": [
            {"name": "AGENT_INVESTIGATOR_ENABLED_IN_EVALUATION_HARNESS", "value": True},
            {"name": "AGENT_INVESTIGATOR_ENABLED_IN_PRODUCTION_SETTINGS", "value": configured.AGENT_INVESTIGATOR_ENABLED},
            {"name": "LOCAL_LLM_ENABLED", "value": configured.LOCAL_LLM_ENABLED},
        ],
        "cache_policy": "DISABLED_EXACT_SEMANTIC_AND_SINGLEFLIGHT",
        "fallback_policy": "EXACT_CANDIDATE_ONLY_NO_CROSS_MODEL_FALLBACK",
        "source_revision": source_revision,
    }
    if scope == "FULL_ANALYSIS_GRAPH":
        raw["graph_contract_version"] = FULL_ANALYSIS_GRAPH_CONTRACT_VERSION
        raw["graph_identity_digest"] = full_analysis_graph_identity_digest()
    compatibility_payload = dict(raw)
    for key in ("model_provider", "model_identifier", "model_revision"):
        compatibility_payload.pop(key, None)
    candidate_prompt_names = (
        {"evidence-investigator"}
        if scope == "PRODUCTION_EVIDENCE_INVESTIGATOR_GRAPH"
        else {
            "evidence-investigator", "architecture-agent", "integration-agent", "security-agent",
            "bug-agent", "verifier-agent", "revision-agent",
        }
    )
    compatibility_payload["prompt_components"] = [
        component for component in compatibility_payload["prompt_components"]
        if component["name"] not in candidate_prompt_names
    ]
    compatibility_hash = _digest(compatibility_payload)
    system_hash = _digest(raw)
    raw["compatibility_digest"] = compatibility_hash
    raw["system_digest"] = system_hash
    return AgentSystemIdentity.model_validate(raw)


def verify_agent_system_identity(identity: AgentSystemIdentity) -> None:
    """Revalidate mutable nested JSON after loading or in-process mutation."""
    AgentSystemIdentity.model_validate(identity.model_dump(mode="json"))


__all__ = [
    "AgentSystemIdentity",
    "PromptComponentIdentity",
    "RuntimeFlag",
    "SystemBudgetProfile",
    "FULL_ANALYSIS_GRAPH_CONTRACT_VERSION",
    "FULL_ANALYSIS_EVALUATION_CONTRACT_VERSION",
    "FULL_ANALYSIS_GRAPH_CONTRACT",
    "full_analysis_graph_identity_digest",
    "full_analysis_evaluation_contract_hash",
    "build_agent_system_identity",
    "verify_agent_system_identity",
]
