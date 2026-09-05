"""Bounded graph pages persisted by the existing change-analysis checkpointer."""

import copy
import hashlib
import json

from app.analysis.authority import source_fingerprint
from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import NodeKind


def advance_frontier(graph, diff, previous=None, *, batch=16, max_nodes=256, max_edges=512, max_depth=3):
    index = getattr(graph, "index", None)
    authority = {"base": diff.base_commit_sha, "head": diff.head_commit_sha,
        "snapshot": getattr(index, "snapshot_id", None), "producer": getattr(index, "producer", None),
        "tenant": getattr(index, "tenant_id", None), "analyzer": source_fingerprint(__file__),
        "bounds": [batch, max_nodes, max_edges, max_depth],
        "diff": hashlib.sha256(diff.model_dump_json().encode()).hexdigest()}
    if previous and previous.get("authority") != authority:
        raise ValueError("Impact checkpoint authority mismatch")
    state = copy.deepcopy(previous) if previous else {"authority": authority, "queue": [],
        "visited": [], "nodes": {}, "edges": {}, "unknown": [], "pages": 0, "stopped": False}
    if not previous:
        seeds = []
        for symbol in diff.deleted_symbols + diff.modified_symbols:
            location = symbol.base_location or {}
            seeds.append(f"symbol:{symbol.file_path}:{symbol.symbol_kind}:{symbol.symbol_name}:{location.get('start_line', 0)}")
        seeds.extend(f"file:{delta.file_path}" for delta in diff.schema_deltas)
        seeds.extend(f"route:{delta.base_http_method}:{delta.base_path}" for delta in diff.route_deltas)
        state["queue"] = [[seed, 0] for seed in sorted(set(seeds))[:max_nodes]]
        if len(set(seeds)) > max_nodes:
            state["unknown"].append("SEED_BUDGET; remaining seeds reconstructable from diff")
    visited = set(state["visited"])
    for _ in range(batch):
        if len(visited) >= max_nodes:
            state["stopped"] = bool(state["queue"])
        if not state["queue"] or state["stopped"]:
            break
        node_id, depth = state["queue"][0]
        if node_id in visited:
            state["queue"].pop(0)
            continue
        node = graph.get_node(node_id)
        if node is None:
            state["unknown"].append(node_id)
            visited.add(node_id)
            state["queue"].pop(0)
            continue
        incoming = sorted(graph.get_incoming_edges(node_id), key=lambda edge: (edge.source, edge.kind.value))
        additions = {node_id: node.model_dump(mode="json")}
        new_edges, next_nodes = {}, []
        for edge in incoming:
            caller = graph.get_node(edge.source)
            if caller is None:
                continue
            additions[caller.id] = caller.model_dump(mode="json")
            key = hashlib.sha256(f"{edge.source}|{edge.target}|{edge.kind.value}".encode()).hexdigest()
            new_edges[key] = edge.model_dump(mode="json")
            if caller.id not in visited:
                next_nodes.append([caller.id, depth + 1])
        if (len(set(state["nodes"]) | set(additions)) > max_nodes or
                len(set(state["edges"]) | set(new_edges)) > max_edges or
                len(state["queue"]) + len(next_nodes) > max_nodes or
                len(json.dumps([state["nodes"], state["edges"], additions, new_edges])) > 524288):
            state["stopped"] = True  # Keep this unprocessed node in the frontier.
            break
        state["nodes"].update(additions)
        if depth >= max_depth and incoming:
            state["unknown"].append(node_id)
        else:
            state["edges"].update(new_edges)
            known = {item[0] for item in state["queue"]} | visited
            for item in next_nodes:
                if item[0] not in known:
                    state["queue"].append(item)
                    known.add(item[0])
        visited.add(node_id)
        state["queue"].pop(0)
    state["visited"] = sorted(visited)
    state["pages"] += 1
    if state["pages"] >= 16 or len(visited) >= max_nodes:
        state["stopped"] = bool(state["queue"])
    state["partial"] = bool(state["queue"] or state["unknown"] or getattr(graph, "query_truncated", False) or index is not None)
    return state


def frontier_graph(state):
    graph = RepositoryGraph()
    for value in state["nodes"].values():
        node = dict(value)
        node["node_id"] = node.pop("id")
        node["kind"] = NodeKind(node["kind"])
        graph.add_node(**node)
    from app.graph.schemas import EdgeKind
    for edge in state["edges"].values():
        graph.add_edge(edge["source"], edge["target"], EdgeKind(edge["kind"]), edge.get("metadata"))
    return graph
