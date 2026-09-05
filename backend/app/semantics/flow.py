"""Conservative bounded interprocedural flow over the normalized semantic IR."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from app.semantics.schemas import (
    SemanticCertainty,
    SemanticFlow,
    SemanticFlowEdge,
    SemanticProgram,
)


@dataclass(frozen=True, slots=True)
class FlowLimits:
    max_call_depth: int = 2
    max_paths: int = 16
    max_flow_nodes: int = 64
    max_aliases: int = 32

    def __post_init__(self):
        if self.max_call_depth < 0 or min(self.max_paths, self.max_flow_nodes, self.max_aliases) < 1:
            raise ValueError("invalid flow limits")


class FlowResults(list):
    def __init__(self, values=(), *, coverage):
        super().__init__(values)
        self.coverage = coverage


def analyze_security_flows(
    program: SemanticProgram,
    *,
    limits: FlowLimits = FlowLimits(),
) -> list[SemanticFlow]:
    """Track parameter/assignment/call flows with cycle and resource bounds."""
    functions = {function.symbol: function for function in program.functions}
    functions_by_name = defaultdict(list)
    for function in program.functions:
        functions_by_name[(function.file_path, function.name)].append(function)
    calls_by_symbol = defaultdict(list)
    assignments_by_symbol = defaultdict(list)
    returns_by_symbol = defaultdict(list)
    guards_by_symbol = defaultdict(list)
    sanitizers_by_symbol = defaultdict(list)
    sinks_by_key = {(sink.symbol, sink.start_line, sink.name): sink for sink in program.sinks}
    for fact in program.calls:
        calls_by_symbol[fact.symbol].append(fact)
    for fact in program.assignments:
        assignments_by_symbol[fact.symbol].append(fact)
    for fact in program.returns:
        returns_by_symbol[fact.symbol].append(fact)
    for fact in program.guards:
        guards_by_symbol[fact.symbol].append(fact)
    for fact in program.sanitizers:
        sanitizers_by_symbol[fact.symbol].append(fact)

    flows: list[SemanticFlow] = []
    visited_states: set[tuple[str, str, tuple[str, ...], int]] = set()
    traversed_nodes = 0
    stops: set[str] = set()

    def visit(
        *,
        source,
        function_name: str,
        tainted: set[str],
        depth: int,
        edges: list[SemanticFlowEdge],
        transformations: list[str],
        evidence_refs: list[str],
    ) -> None:
        nonlocal traversed_nodes
        if (
            depth > limits.max_call_depth
            or len(flows) >= limits.max_paths
            or traversed_nodes >= limits.max_flow_nodes
        ):
            stops.add("flow_budget")
            return
        state_key = (source.fact_id, function_name, tuple(sorted(tainted)), depth)
        if state_key in visited_states:
            return
        visited_states.add(state_key)
        traversed_nodes += 1

        aliases = set(tainted)
        assignment_position = 0
        assignments = assignments_by_symbol.get(function_name, [])
        for call in calls_by_symbol.get(function_name, []):
            traversed_nodes += 1
            if traversed_nodes > limits.max_flow_nodes:
                stops.add("flow_nodes")
                return
            while assignment_position < len(assignments) and assignments[assignment_position].start_line < call.start_line:
                assignment = assignments[assignment_position]
                if aliases.intersection(assignment.source_names) and len(aliases) < limits.max_aliases:
                    aliases.add(assignment.target)
                else:
                    if aliases.intersection(assignment.source_names):
                        stops.add("alias_budget")
                    aliases.discard(assignment.target)
                assignment_position += 1
            related_guards = [guard for guard in guards_by_symbol.get(function_name, [])
                if guard.start_line < call.start_line and aliases.intersection(guard.referenced_names)][:16]
            related_sanitizers = [item for item in sanitizers_by_symbol.get(function_name, [])
                if item.start_line < call.start_line and aliases.intersection(item.argument_names)][:16]
            tainted_positions = [
                position
                for position, names in enumerate(call.argument_names)
                if aliases.intersection(names)
            ]
            if not tainted_positions:
                continue
            sink = sinks_by_key.get((call.symbol, call.start_line, call.callee))
            next_evidence = list(dict.fromkeys([*evidence_refs, call.evidence_id]))[:16]
            next_edges = [
                *edges,
                SemanticFlowEdge(
                    source_fact_id=source.fact_id if not edges else edges[-1].target_fact_id,
                    target_fact_id=call.fact_id,
                    relation="ARGUMENT_FLOW",
                    certainty=SemanticCertainty.PROVEN,
                ),
            ][: limits.max_flow_nodes]
            if sink is not None and 0 in tainted_positions:
                certainty = (
                    SemanticCertainty.PROVEN
                    if source.certainty == SemanticCertainty.PROVEN and not related_sanitizers
                    else SemanticCertainty.POSSIBLE
                )
                flows.append(SemanticFlow(
                    source=source,
                    sink=sink,
                    transformations=transformations[:32],
                    sanitizers=related_sanitizers,
                    guards=related_guards,
                    edges=next_edges,
                    certainty=certainty,
                    evidence_refs=next_evidence,
                    call_depth=depth,
                ))
                if len(flows) >= limits.max_paths:
                    stops.add("path_budget")
                    return

            # Member calls and ambiguous bindings are not resolved by a
            # coincidental same-named function elsewhere in the repository.
            matches = functions_by_name.get((call.file_path, call.callee), [])
            callee = matches[0] if len(matches) == 1 else None
            if callee is None or depth >= limits.max_call_depth:
                if callee is not None:
                    stops.add("call_depth")
                elif sink is None:
                    stops.add("unresolved_call")
                continue
            mapped = {
                callee.parameter_names[position]
                for position in tainted_positions
                if position < len(callee.parameter_names)
            }
            if mapped:
                visit(
                    source=source,
                    function_name=callee.symbol,
                    tainted=mapped,
                    depth=depth + 1,
                    edges=next_edges,
                    transformations=[*transformations, f"call:{call.callee}"][:32],
                    evidence_refs=next_evidence,
                )

            # Return-value propagation is accepted only when a callee return
            # structurally references the mapped parameter.
            if call.result_target and mapped and any(
                mapped.intersection(return_fact.source_names)
                for return_fact in returns_by_symbol.get(callee.symbol, [])
            ) and len(aliases) < limits.max_aliases:
                aliases.add(call.result_target)

    for source in program.sources:
        function = functions.get(source.symbol)
        if function is None:
            continue
        visit(
            source=source,
            function_name=function.symbol,
            tainted={source.name},
            depth=0,
            edges=[],
            transformations=[],
            evidence_refs=[source.evidence_id],
        )
        if len(flows) >= limits.max_paths:
            break

    deduplicated = {
        (flow.source.fact_id, flow.sink.fact_id, tuple(flow.evidence_refs)): flow
        for flow in flows
    }
    return FlowResults([deduplicated[key] for key in sorted(deduplicated)], coverage={
        "complete": not stops and program.coverage.get("complete") is True,
        "stop_reasons": sorted(stops), "states_examined": traversed_nodes,
        "max_states": limits.max_flow_nodes, "max_paths": limits.max_paths,
    })


__all__ = ["FlowLimits", "analyze_security_flows"]
