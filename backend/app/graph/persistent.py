"""Snapshot-pinned graph queries over persisted file projections."""

from collections import OrderedDict

from sqlalchemy import select

from app.graph.repository_graph import RepositoryGraph
from app.graph.schemas import EdgeKind, GraphEdge, GraphNode, NodeKind
from app.models.intelligence import IndexFactModel


class PersistentRepositoryGraph(RepositoryGraph):
    """Load a bounded active graph; adjacency queries stay disk-backed.

    File-local extraction cannot establish complete cross-file resolution.
    That limitation is carried to admission and reports, never hidden.
    """

    def __init__(self, index, *, node_limit: int = 512, edge_limit: int = 2048):
        super().__init__()
        self.index = index
        self.node_limit = node_limit
        self.edge_limit = edge_limit
        self.query_truncated = False
        self._cross_cache = OrderedDict()

    def _facts(self, kind, *, lookup=None, target=None, limit=None):
        maximum = limit or self.edge_limit
        statement = select(IndexFactModel).where(
            IndexFactModel.tenant_id == self.index.tenant_id,
            IndexFactModel.repository_id == self.index.repository_id,
            IndexFactModel.kind == kind,
        )
        if lookup is not None:
            statement = statement.where(IndexFactModel.lookup == lookup)
        if target is not None:
            statement = statement.where(IndexFactModel.target == target)
        paths = self.index.db.execute(statement.with_only_columns(IndexFactModel.path).distinct()
            .order_by(IndexFactModel.path).limit(65)).scalars().all()
        self.query_truncated |= len(paths) > 64
        result = []
        for path in paths[:64]:
            projection = self.index.file_projection(path)
            if projection is None:
                continue
            remaining = maximum - len(result)
            rows = self.index.db.execute(statement.where(IndexFactModel.projection_id == projection.id)
                .order_by(IndexFactModel.fact_id).limit(remaining + 1)).scalars().all()
            self.query_truncated |= len(rows) > remaining
            result.extend(row.payload for row in rows[:remaining])
            if len(result) >= maximum:
                self.query_truncated = True
                break
        return result

    def get_node(self, node_id):
        if node_id.startswith("file:"):
            path = node_id[5:]
        elif node_id.startswith("symbol:"):
            path = node_id.split(":", 2)[1]
        else:
            path = None
        if path:
            return next((node for node in self.nodes_for_file(path) if node.id == node_id), None)
        rows = self._facts("NODE", lookup=node_id, limit=16)
        return GraphNode.model_validate(rows[0]) if len(rows) == 1 else None

    def nodes_for_file(self, path):
        return [GraphNode.model_validate(row.payload) for row in self.index.file_facts(path, "NODE", limit=self.node_limit)]

    def _cross_edges(self, path):
        """Resolve explicit imports against this snapshot, not the producer commit.

        Both sides' digests form the certificate. Changing a dependency therefore
        invalidates its relationship even when the caller projection is reused.
        """
        if path in self._cross_cache:
            self._cross_cache.move_to_end(path)
            return self._cross_cache[path]
        from app.graph.builder import build_repository_graph
        from app.graph.imports import import_paths
        from app.ingestion.schemas import FileEntry, RepositoryManifest
        source = self.index.file_projection(path)
        if source is None:
            return []
        files = [FileEntry.model_validate(source.payload["file"])]
        projections = {path: source}
        payload_bytes = source.payload_bytes
        targets = {}
        for target in import_paths(files[0]):
            projection = self.index.file_projection(target)
            if projection is None or target == path:
                continue
            targets[target] = projection
        # Never choose one definition from ambiguous same-name module files.
        from collections import Counter
        def module_key(target):
            import re
            return re.sub(r"(?:/__init__|/index)?\.(?:py|tsx?|jsx?)$", "", target)
        counts = Counter(module_key(target) for target in targets)
        for target, projection in targets.items():
            if counts[module_key(target)] > 1:
                self.query_truncated = True
                continue
            if len(files) >= 16 or payload_bytes + projection.payload_bytes > 4_194_304:
                self.query_truncated = True
                break
            files.append(FileEntry.model_validate(projection.payload["file"]))
            projections[target] = projection
            payload_bytes += projection.payload_bytes
        graph = build_repository_graph(RepositoryManifest(repository_url=self.index.repository_url,
            commit_hash=self.index.commit_sha, files=files))
        edges = []
        for edge in graph.get_edges():
            left, right = graph.get_node(edge.source), graph.get_node(edge.target)
            if (edge.kind not in {EdgeKind.CALLS, EdgeKind.IMPORTS} or not left or not right or
                    left.file_path != path or right.file_path == path):
                continue
            if len(edges) >= self.edge_limit:
                self.query_truncated = True
                break
            certificate = {"snapshot_id": self.index.snapshot_id, "resolution": "EXPLICIT_IMPORT",
                "source_sha256": source.content_hash,
                "target_sha256": projections[right.file_path].content_hash,
                "producer_digest": self.index.producer}
            edges.append(edge.model_copy(update={"metadata": {**edge.metadata, "dependency_certificate": certificate}}))
        self._cross_cache[path] = edges
        if len(self._cross_cache) > 4:
            self._cross_cache.popitem(last=False)
        return edges

    def get_nodes(self):
        return [GraphNode.model_validate(row) for row in self._facts("NODE", limit=self.node_limit)]

    def get_nodes_by_kind(self, kind):
        return [GraphNode.model_validate(row) for row in self._facts("NODE", target=kind.value, limit=self.node_limit)]

    def get_edges(self, kind=None):
        edges = [GraphEdge.model_validate(row) for row in self._facts("EDGE")
                 if kind is None or row["kind"] == kind.value]
        if kind is None or kind in {EdgeKind.IMPORTS, EdgeKind.CALLS}:
            for node in self.get_nodes_by_kind(NodeKind.FILE)[:16]:
                edges.extend(edge for edge in self._cross_edges(node.file_path) if kind is None or edge.kind == kind)
                if len(edges) >= self.edge_limit:
                    self.query_truncated = True
                    break
        unique = {(edge.source, edge.target, edge.kind): edge for edge in edges}
        return list(unique.values())[:self.edge_limit]

    def get_incoming_edges(self, node_id):
        edges = [GraphEdge.model_validate(row) for row in self._facts("EDGE", target=node_id)]
        node = self.get_node(node_id)
        if node and node.file_path:
            refs = self._facts("IMPORT_REF", target=node.file_path, limit=16)
            for ref in refs:
                edges.extend(edge for edge in self._cross_edges(ref["source_path"]) if edge.target == node_id)
        return edges[:self.edge_limit]

    def get_outgoing_edges(self, node_id):
        node = self.get_node(node_id)
        if node and node.file_path:
            rows = self.index.file_facts(node.file_path, "EDGE", limit=self.edge_limit)
            edges = [GraphEdge.model_validate(row.payload) for row in rows if row.lookup == node_id]
            edges.extend(edge for edge in self._cross_edges(node.file_path) if edge.source == node_id)
            return edges[:self.edge_limit]
        return []

    def evaluate_route_contracts(self):
        # A bounded request/route list cannot prove an endpoint is absent.
        from app.graph.schemas import ContractMatchReport
        from app.graph.matcher import match_route_contract
        requests = self.get_nodes_by_kind(NodeKind.FRONTEND_REQUEST)
        routes = self.get_nodes_by_kind(NodeKind.ROUTE)
        from app.graph.matcher import normalize_route_path
        report = ContractMatchReport(total_frontend_requests=len(requests), total_backend_routes=len(routes))
        for request in requests:
            # Suffix similarity is not proof of a contract across services.
            path = normalize_route_path(request.metadata.get("url", request.label))
            exact = [route for route in routes if normalize_route_path(route.metadata.get("path", route.label)) == path]
            partial = match_route_contract([request], exact)
            report.matches.extend(partial.matches)
            report.matched_count += partial.matched_count
        # File-local projections do not prove repository-wide absence.
        from app.graph.schemas import ContractMatchStatus
        report.matches = [match for match in report.matches if match.status == ContractMatchStatus.MATCHED]
        report.unmatched_count = report.method_mismatch_count = report.ambiguous_count = 0
        return report

    def to_domain_data(self):
        from collections import Counter
        from app.graph.schemas import RepositoryGraphData
        nodes, edges = self.get_nodes(), self.get_edges()
        active_ids = {node.id for node in nodes}
        retained = []
        for edge in edges:
            for node_id in (edge.source, edge.target):
                if node_id not in active_ids and len(nodes) < self.node_limit:
                    node = self.get_node(node_id)
                    if node:
                        nodes.append(node)
                        active_ids.add(node.id)
            if edge.source in active_ids and edge.target in active_ids:
                retained.append(edge)
            else:
                self.query_truncated = True
        edges = retained
        contracts = self.evaluate_route_contracts()
        return RepositoryGraphData(nodes=nodes, edges=edges, total_nodes=len(nodes), total_edges=len(edges),
            node_counts_by_kind=dict(Counter(node.kind.value for node in nodes)),
            edge_counts_by_kind=dict(Counter(edge.kind.value for edge in edges)), contract_report=contracts,
            complete=False, coverage={"status": "PARTIAL", "complete": False,
                "reason": "bounded_active_graph; explicit imports only; global absence remains unknown",
                "total_nodes": len(nodes), "total_edges": len(edges),
                "query_truncated": self.query_truncated, "unresolved_graph_relationships": 1,
                "snapshot_id": self.index.snapshot_id})
