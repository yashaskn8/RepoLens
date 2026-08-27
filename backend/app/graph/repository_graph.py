"""Canonical Repository Relationship Graph wrapping NetworkX DiGraph."""

from collections import Counter
from typing import Any, Dict, List, Optional
import networkx as nx

from app.graph.matcher import match_route_contract
from app.graph.schemas import (
    ContractMatchReport,
    ContractMatchStatus,
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RepositoryGraphData,
)


class RepositoryGraph:
    """Canonical, deterministic repository relationship graph.
    
    Provides:
    - Typed node and edge registration backed by NetworkX DiGraph.
    - Deterministic cross-layer contract matching.
    - Query helpers for neighbors, routes, dependencies, and test coverage.
    - Serialized export for API and multi-agent reasoning.
    """

    def __init__(self):
        self._graph = nx.DiGraph()

    def add_node(
        self,
        node_id: str,
        kind: NodeKind,
        label: str,
        file_path: Optional[str] = None,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Add or update a typed node in the relationship graph."""
        meta = metadata or {}
        node = GraphNode(
            id=node_id,
            kind=kind,
            label=label,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            metadata=meta,
        )
        self._graph.add_node(
            node_id,
            kind=kind.value,
            label=label,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            metadata=meta,
        )
        return node

    def update_node_metadata(self, node_id: str, metadata: Dict[str, Any]) -> bool:
        """Update metadata on an existing node."""
        if not self._graph.has_node(node_id):
            return False
        self._graph.nodes[node_id].setdefault("metadata", {}).update(metadata)
        return True

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        kind: EdgeKind,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[GraphEdge]:
        """Add a typed directed edge between existing nodes."""
        if not self._graph.has_node(source_id) or not self._graph.has_node(target_id):
            return None

        meta = metadata or {}
        edge = GraphEdge(
            source=source_id,
            target=target_id,
            kind=kind,
            metadata=meta,
        )
        self._graph.add_edge(
            source_id,
            target_id,
            kind=kind.value,
            metadata=meta,
        )
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node by its unique identifier."""
        if not self._graph.has_node(node_id):
            return None
        data = self._graph.nodes[node_id]
        return GraphNode(
            id=node_id,
            kind=NodeKind(data["kind"]),
            label=data["label"],
            file_path=data.get("file_path"),
            start_line=data.get("start_line"),
            end_line=data.get("end_line"),
            metadata=data.get("metadata", {}),
        )

    def get_nodes(self) -> List[GraphNode]:
        """Retrieve all nodes in the graph."""
        nodes = []
        for n_id, data in self._graph.nodes(data=True):
            nodes.append(
                GraphNode(
                    id=n_id,
                    kind=NodeKind(data["kind"]),
                    label=data["label"],
                    file_path=data.get("file_path"),
                    start_line=data.get("start_line"),
                    end_line=data.get("end_line"),
                    metadata=data.get("metadata", {}),
                )
            )
        return nodes

    def get_nodes_by_kind(self, kind: NodeKind) -> List[GraphNode]:
        """Retrieve all nodes matching a specific kind."""
        nodes = []
        for n_id, data in self._graph.nodes(data=True):
            if data.get("kind") == kind.value:
                nodes.append(
                    GraphNode(
                        id=n_id,
                        kind=kind,
                        label=data["label"],
                        file_path=data.get("file_path"),
                        start_line=data.get("start_line"),
                        end_line=data.get("end_line"),
                        metadata=data.get("metadata", {}),
                    )
                )
        return nodes


    def get_edges(self, kind: Optional[EdgeKind] = None) -> List[GraphEdge]:
        """Retrieve all edges, optionally filtered by kind."""
        edges = []
        for u, v, data in self._graph.edges(data=True):
            edge_kind_str = data.get("kind")
            if kind is None or edge_kind_str == kind.value:
                edges.append(
                    GraphEdge(
                        source=u,
                        target=v,
                        kind=EdgeKind(edge_kind_str),
                        metadata=data.get("metadata", {}),
                    )
                )
        return edges

    def get_edges_by_kind(self, kind: EdgeKind) -> List[GraphEdge]:
        """Retrieve all edges matching a specific EdgeKind."""
        return self.get_edges(kind=kind)

    def get_incoming_edges(self, node_id: str) -> List[GraphEdge]:
        """Retrieve all incoming edges to a specific node."""
        if not self._graph.has_node(node_id):
            return []
        edges = []
        for u, _, data in self._graph.in_edges(node_id, data=True):
            edges.append(
                GraphEdge(
                    source=u,
                    target=node_id,
                    kind=EdgeKind(data["kind"]),
                    metadata=data.get("metadata", {}),
                )
            )
        return edges

    def get_outgoing_edges(self, node_id: str) -> List[GraphEdge]:
        """Retrieve all outgoing edges from a specific node."""
        if not self._graph.has_node(node_id):
            return []
        edges = []
        for _, v, data in self._graph.out_edges(node_id, data=True):
            edges.append(
                GraphEdge(
                    source=node_id,
                    target=v,
                    kind=EdgeKind(data["kind"]),
                    metadata=data.get("metadata", {}),
                )
            )
        return edges

    def evaluate_route_contracts(self) -> ContractMatchReport:
        """Run deterministic cross-layer route contract matching and record MATCHES_ROUTE edges."""
        fe_requests = self.get_nodes_by_kind(NodeKind.FRONTEND_REQUEST)
        be_routes = self.get_nodes_by_kind(NodeKind.ROUTE)

        report = match_route_contract(fe_requests, be_routes)

        # Wire MATCHES_ROUTE edges for matched and method-mismatched requests
        for match in report.matches:
            if match.status in (ContractMatchStatus.MATCHED, ContractMatchStatus.METHOD_MISMATCH):
                for route_id in match.matched_route_ids:
                    self.add_edge(
                        source_id=match.frontend_request_id,
                        target_id=route_id,
                        kind=EdgeKind.MATCHES_ROUTE,
                        metadata={
                            "match_status": match.status.value,
                            "frontend_method": match.frontend_method,
                            "frontend_url": match.frontend_url,
                            "details": match.details,
                        },
                    )

        return report

    def to_domain_data(self) -> RepositoryGraphData:
        """Export serialized domain graph data with node/edge counts and contract match report."""
        nodes = []
        node_counts = Counter()
        for n_id, data in self._graph.nodes(data=True):
            kind = NodeKind(data["kind"])
            node_counts[kind.value] += 1
            nodes.append(
                GraphNode(
                    id=n_id,
                    kind=kind,
                    label=data["label"],
                    file_path=data.get("file_path"),
                    start_line=data.get("start_line"),
                    end_line=data.get("end_line"),
                    metadata=data.get("metadata", {}),
                )
            )

        edges = []
        edge_counts = Counter()
        for u, v, data in self._graph.edges(data=True):
            kind = EdgeKind(data["kind"])
            edge_counts[kind.value] += 1
            edges.append(
                GraphEdge(
                    source=u,
                    target=v,
                    kind=kind,
                    metadata=data.get("metadata", {}),
                )
            )

        contract_report = self.evaluate_route_contracts()

        return RepositoryGraphData(
            nodes=nodes,
            edges=edges,
            total_nodes=len(nodes),
            total_edges=len(edges),
            node_counts_by_kind=dict(node_counts),
            edge_counts_by_kind=dict(edge_counts),
            contract_report=contract_report,
        )
