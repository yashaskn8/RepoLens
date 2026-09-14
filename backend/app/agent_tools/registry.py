"""Allow-listed registry and error-contained invocation boundary for agent tools."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from app.agent_tools.context import AgentToolContext
from app.agent_tools.schemas import (
    AGENT_TOOL_VERSION,
    AnalyzeChangeInput,
    AnalyzeChangeOutput,
    AnalyzeImpactInput,
    AnalyzeImpactOutput,
    FileInspectionOutput,
    InspectFileInput,
    InspectSymbolInput,
    RelationshipInput,
    RelationshipOutput,
    ScanSecurityInput,
    SearchSymbolInput,
    SecurityScanOutput,
    SymbolInspectionOutput,
    SymbolSearchOutput,
    TimeoutClass,
    ToolCapability,
    ToolError,
    ToolInvocationResult,
    ToolMetadata,
    ToolProvenance,
    ToolResultStatus,
    TraceDataflowInput,
    TraceDataflowOutput,
    VerificationVerdict,
    VerifyFindingInput,
    VerifyFindingOutput,
)
from app.agent_tools.tools import (
    ToolExecution,
    ToolFailure,
    analyze_change,
    analyze_impact,
    find_callees,
    find_callers,
    inspect_file,
    inspect_symbol,
    scan_security,
    search_symbol,
    trace_dataflow,
    verify_finding,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _ToolSpec:
    metadata: ToolMetadata
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: Callable[[BaseModel, AgentToolContext], ToolExecution]


def _metadata(
    name: str,
    description: str,
    input_model: type[BaseModel],
    output_model: type[BaseModel],
    capability: ToolCapability,
    timeout: TimeoutClass,
) -> ToolMetadata:
    return ToolMetadata(
        tool_name=name,
        tool_version=AGENT_TOOL_VERSION,
        description=description,
        input_schema=input_model.model_json_schema(mode="validation"),
        output_schema=output_model.model_json_schema(mode="serialization"),
        capability=capability,
        timeout_class=timeout,
        evidence_required=True,
    )


_SPECS = (
    _ToolSpec(
        _metadata(
            "inspect_file",
            "Return manifest and parser facts for one authorized source file. Use for language, size, symbols, imports, and source spans; do not use to obtain full source text or infer behavior.",
            InspectFileInput,
            FileInspectionOutput,
            ToolCapability.REPOSITORY,
            TimeoutClass.FAST,
        ),
        InspectFileInput,
        FileInspectionOutput,
        inspect_file,
    ),
    _ToolSpec(
        _metadata(
            "search_symbol",
            "Search deterministic manifest symbols with explicit exact, prefix, or substring matching. Use to discover stable symbol identities; it returns every bounded match and never chooses among ambiguous names.",
            SearchSymbolInput,
            SymbolSearchOutput,
            ToolCapability.SYMBOLS,
            TimeoutClass.FAST,
        ),
        SearchSymbolInput,
        SymbolSearchOutput,
        search_symbol,
    ),
    _ToolSpec(
        _metadata(
            "inspect_symbol",
            "Return the definition span, signature metadata, enclosing class, and available graph relationships for one stable symbol identity. Use after symbol search; do not use a guessed or ambiguous name.",
            InspectSymbolInput,
            SymbolInspectionOutput,
            ToolCapability.SYMBOLS,
            TimeoutClass.FAST,
        ),
        InspectSymbolInput,
        SymbolInspectionOutput,
        inspect_symbol,
    ),
    _ToolSpec(
        _metadata(
            "find_callers",
            "Return direct incoming CALLS edges for a known symbol. Use to identify deterministic callers; an incomplete graph yields explicit uncertainty instead of proving absence.",
            RelationshipInput,
            RelationshipOutput,
            ToolCapability.GRAPH,
            TimeoutClass.FAST,
        ),
        RelationshipInput,
        RelationshipOutput,
        find_callers,
    ),
    _ToolSpec(
        _metadata(
            "find_callees",
            "Return direct outgoing CALLS edges for a known symbol. Use to inspect deterministic call dependencies; unresolved or external calls remain absent with partial-coverage warnings.",
            RelationshipInput,
            RelationshipOutput,
            ToolCapability.GRAPH,
            TimeoutClass.FAST,
        ),
        RelationshipInput,
        RelationshipOutput,
        find_callees,
    ),
    _ToolSpec(
        _metadata(
            "trace_dataflow",
            "Trace bounded production source-to-sink flow for a known symbol. Use for SQL, command, filesystem, template, or network sink investigations; returns paths, sanitizers, guards, opaque calls, certainty, and explicit coverage without proving absence when incomplete.",
            TraceDataflowInput,
            TraceDataflowOutput,
            ToolCapability.FLOW,
            TimeoutClass.BOUNDED,
        ),
        TraceDataflowInput,
        TraceDataflowOutput,
        trace_dataflow,
    ),
    _ToolSpec(
        _metadata(
            "scan_security",
            "Query normalized findings already emitted by registered deterministic scanners, optionally scoped by file, symbol, rule, category, or analyzer. It never launches scanners or repository commands and reports incomplete scanner coverage explicitly.",
            ScanSecurityInput,
            SecurityScanOutput,
            ToolCapability.SECURITY,
            TimeoutClass.FAST,
        ),
        ScanSecurityInput,
        SecurityScanOutput,
        scan_security,
    ),
    _ToolSpec(
        _metadata(
            "analyze_change",
            "Return bounded structural facts from the production diff engine for two authorized snapshots. Use for files, symbols, routes, schemas, dependencies, and configuration changes; facts are not defect findings and Git is never invoked by this tool.",
            AnalyzeChangeInput,
            AnalyzeChangeOutput,
            ToolCapability.CHANGES,
            TimeoutClass.EXPENSIVE,
        ),
        AnalyzeChangeInput,
        AnalyzeChangeOutput,
        analyze_change,
    ),
    _ToolSpec(
        _metadata(
            "analyze_impact",
            "Compute bounded graph-aware impact from production structural diff facts. Use for caller and cross-layer blast radius with preserved direction and depth; cycles and limits are handled by the production impact engine.",
            AnalyzeImpactInput,
            AnalyzeImpactOutput,
            ToolCapability.IMPACT,
            TimeoutClass.BOUNDED,
        ),
        AnalyzeImpactInput,
        AnalyzeImpactOutput,
        analyze_impact,
    ),
    _ToolSpec(
        _metadata(
            "verify_finding",
            "Verify a structured security, dataflow, call-edge, or structural-change claim against current production evidence. Use before publishing a proposed finding; exact evidence references are required and unsupported or incomplete claims never become facts.",
            VerifyFindingInput,
            VerifyFindingOutput,
            ToolCapability.VERIFICATION,
            TimeoutClass.BOUNDED,
        ),
        VerifyFindingInput,
        VerifyFindingOutput,
        verify_finding,
    ),
)


class AgentToolRegistry:
    """Closed registry containing only trusted, deterministic, read-only tools."""

    def __init__(self, context: AgentToolContext):
        self._context = context
        self._specs = {spec.metadata.tool_name: spec for spec in _SPECS}

    def list_tools(self) -> list[ToolMetadata]:
        return [self._specs[name].metadata.model_copy(deep=True) for name in sorted(self._specs)]

    def get_tool(self, name: str) -> ToolMetadata | None:
        spec = self._specs.get(name)
        return spec.metadata.model_copy(deep=True) if spec else None

    def invoke(self, name: str, arguments: Mapping[str, object] | None) -> ToolInvocationResult:
        invocation_id = str(uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        started = time.perf_counter()
        spec = self._specs.get(name)
        if spec is None:
            result = ToolInvocationResult(
                tool=name or "unknown",
                tool_version=AGENT_TOOL_VERSION,
                status=ToolResultStatus.UNSUPPORTED,
                errors=[ToolError(code="UNKNOWN_TOOL", message="The requested tool is not registered.")],
            )
            self._log(invocation_id, started_at, started, result, 0)
            return result
        if not isinstance(arguments, Mapping):
            result = self._error_result(spec, ToolResultStatus.INVALID_INPUT, "ARGUMENTS_NOT_OBJECT", "Tool arguments must be a JSON object.")
            self._log(invocation_id, started_at, started, result, 0)
            return result
        try:
            parsed = spec.input_model.model_validate(dict(arguments))
        except ValidationError as exc:
            details = [
                {"location": [str(part) for part in item["loc"]], "type": item["type"], "message": item["msg"][:256]}
                for item in exc.errors(include_url=False, include_input=False, include_context=False)[:16]
            ]
            result = self._error_result(
                spec,
                ToolResultStatus.INVALID_INPUT,
                "SCHEMA_VALIDATION_FAILED",
                "Tool arguments do not match the declared input schema.",
                validation_errors=details,
            )
            self._log(invocation_id, started_at, started, result, 0)
            return result
        try:
            execution = spec.handler(parsed, self._context)
            output = None
            if execution.output is not None:
                validated = spec.output_model.model_validate(execution.output.model_dump(mode="json"))
                output = validated.model_dump(mode="json")
            provenance = None
            if execution.snapshot is not None:
                provenance = ToolProvenance(
                    production_components=list(execution.components),
                    component_versions=dict(execution.snapshot.component_versions),
                    repository_snapshot=execution.snapshot.snapshot_id,
                    analysis_stage=execution.stage,
                )
            result = ToolInvocationResult(
                tool=name,
                tool_version=spec.metadata.tool_version,
                status=execution.status,
                result=output,
                evidence=list(execution.evidence),
                provenance=provenance,
                warnings=list(execution.warnings),
            )
        except ToolFailure as exc:
            result = self._error_result(spec, exc.status, exc.error.code, exc.error.message, **exc.error.details)
        except Exception as exc:
            logger.error(
                "agent tool internal failure",
                extra={"invocation_id": invocation_id, "tool": name, "exception_type": type(exc).__name__},
            )
            result = self._error_result(
                spec,
                ToolResultStatus.INTERNAL_ERROR,
                "TOOL_EXECUTION_FAILED",
                "The deterministic tool failed internally.",
            )
        self._log(invocation_id, started_at, started, result, self._result_count(result))
        return result

    @staticmethod
    def _error_result(
        spec: _ToolSpec,
        status: ToolResultStatus,
        code: str,
        message: str,
        **details: object,
    ) -> ToolInvocationResult:
        return ToolInvocationResult(
            tool=spec.metadata.tool_name,
            tool_version=spec.metadata.tool_version,
            status=status,
            errors=[ToolError(code=code, message=message, details=dict(details))],
        )

    @staticmethod
    def _result_count(result: ToolInvocationResult) -> int:
        payload = result.result or {}
        for key in ("returned_matches", "returned_relationships", "returned_paths", "returned_findings", "returned_facts", "returned_impacts"):
            value = payload.get(key)
            if isinstance(value, int):
                return value
        return 1 if payload else 0

    @staticmethod
    def _log(invocation_id: str, started_at: str, started: float, result: ToolInvocationResult, count: int) -> None:
        logger.info(
            "agent_tool_invocation",
            extra={
                "invocation_id": invocation_id,
                "tool": result.tool,
                "started_at": started_at,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "status": result.status.value,
                "result_count": count,
                "error_code": result.errors[0].code if result.errors else None,
                "repository_snapshot": result.provenance.repository_snapshot if result.provenance else None,
            },
        )


def create_agent_tool_registry(context: AgentToolContext) -> AgentToolRegistry:
    return AgentToolRegistry(context)


__all__ = ["AgentToolRegistry", "create_agent_tool_registry"]
