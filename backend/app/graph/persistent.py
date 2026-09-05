"""Snapshot-pinned graph queries over persisted file projections."""

from collections import OrderedDict
import posixpath

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
        self.unresolved_frontier = {}
        self._module_resolver = None

    def _unresolved(self, path, reason):
        self.query_truncated = True
        if len(self.unresolved_frontier) < 64:
            self.unresolved_frontier.setdefault(path, reason)

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
        paths = self.index.query_rows(statement.with_only_columns(IndexFactModel.path).distinct()
            .order_by(IndexFactModel.path).limit(65), scalars=True)
        self.query_truncated |= len(paths) > 64 or bool(self.index.query_coverage.get("query_budget_exhausted"))
        result = []
        for path in paths[:64]:
            projection = self.index.file_projection(path)
            if projection is None:
                continue
            remaining = maximum - len(result)
            rows = self.index.query_rows(statement.where(IndexFactModel.projection_id == projection.id)
                .order_by(IndexFactModel.fact_id).limit(remaining + 1), scalars=True)
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
        cache_key = (self.index.snapshot_id, path)
        if cache_key in self._cross_cache:
            self._cross_cache.move_to_end(cache_key)
            return self._cross_cache[cache_key]
        from app.graph.builder import build_repository_graph
        from app.ingestion.schemas import FileEntry, RepositoryManifest
        from app.graph.module_resolution import ModuleResolution, TypeScriptModuleResolver
        from app.graph.imports import import_paths
        source = self.index.file_projection(path)
        if source is None:
            return []
        files = [FileEntry.model_validate(source.payload["file"])]
        projections = {path: source}
        payload_bytes = source.payload_bytes
        targets = {}
        if files[0].language == "python":
            resolutions = [ModuleResolution(target, "PROVEN", target, "PYTHON_LITERAL")
                           for target in import_paths(files[0])]
        else:
            if self._module_resolver is None:
                self._module_resolver = TypeScriptModuleResolver(self.index)
            resolutions = self._module_resolver.resolve_file(files[0])
        proven = {result.target: result for result in resolutions if result.state == "PROVEN" and result.target}
        for result in resolutions:
            if result.state != "PROVEN":
                self._unresolved(path, f"{result.state}:{result.method}:{result.reason or 'UNKNOWN'}")
        for target in proven:
            projection = self.index.file_projection(target)
            if projection is None or target == path:
                continue
            targets[target] = projection
        if resolutions and not targets:
            self._unresolved(path, "IMPORT_TARGET_NOT_IN_SNAPSHOT")
        # Never choose one definition from ambiguous same-name module files.
        from collections import Counter
        def module_key(target):
            import re
            return re.sub(r"(?:/__init__|/index)?\.(?:py|tsx?|jsx?)$", "", target)
        counts = Counter(module_key(target) for target in targets)
        for target, projection in targets.items():
            if counts[module_key(target)] > 1:
                self._unresolved(path, "AMBIGUOUS_IMPORT_TARGET")
                continue
            if len(files) >= 16 or payload_bytes + projection.payload_bytes > 4_194_304:
                self._unresolved(path, "DEPENDENCY_RESOLUTION_BUDGET")
                break
            files.append(FileEntry.model_validate(projection.payload["file"]))
            projections[target] = projection
            payload_bytes += projection.payload_bytes
        # The canonical graph builder consumes relative source specifiers. Give
        # it an immutable equivalent for proven aliases so CALLS edges share the
        # same resolution authority as IMPORTS edges.
        if files[0].language != "python" and proven:
            rewritten = []
            source_dir = posixpath.dirname(path)
            for symbol in files[0].symbols:
                details = dict(symbol.details)
                resolution = next((item for item in resolutions
                    if item.specifier == details.get("source") and item.state == "PROVEN" and item.target), None)
                if resolution:
                    relative = posixpath.relpath(resolution.target, source_dir or ".")
                    details["source"] = relative if relative.startswith(".") else "./" + relative
                rewritten.append(symbol.model_copy(update={"details": details}))
            files[0] = files[0].model_copy(update={"symbols": rewritten})
        graph = build_repository_graph(RepositoryManifest(repository_url=self.index.repository_url,
            commit_hash=self.index.commit_sha, files=files))
        edges = []
        for target, projection in projections.items():
            if target != path:
                edges.append(GraphEdge(source=f"file:{path}", target=f"file:{target}", kind=EdgeKind.IMPORTS,
                    metadata={"dependency_certificate": {"snapshot_id": self.index.snapshot_id,
                        "resolution": "PROVEN", "resolution_method": proven[target].method,
                        "specifier": proven[target].specifier,
                        "resolution_evidence": list(proven[target].evidence), "source_sha256": source.content_hash,
                        "target_sha256": projection.content_hash, "producer_digest": self.index.producer,
                        "source_behavior_digest": source.payload.get("facts_coverage", {}).get("behavior_digest"),
                        "target_behavior_digest": projection.payload.get("facts_coverage", {}).get("behavior_digest"),
                        "source_coverage": source.payload.get("facts_coverage", {}).get("status", "UNKNOWN"),
                        "target_coverage": projection.payload.get("facts_coverage", {}).get("status", "UNKNOWN")}}))
        for edge in graph.get_edges():
            left, right = graph.get_node(edge.source), graph.get_node(edge.target)
            if (edge.kind != EdgeKind.CALLS or not left or not right or
                    left.file_path != path or right.file_path == path):
                continue
            if len(edges) >= self.edge_limit:
                self.query_truncated = True
                break
            certificate = {"snapshot_id": self.index.snapshot_id, "resolution": "PROVEN",
                "resolution_method": proven[right.file_path].method,
                "specifier": proven[right.file_path].specifier,
                "resolution_evidence": list(proven[right.file_path].evidence),
                "source_sha256": source.content_hash,
                "target_sha256": projections[right.file_path].content_hash,
                "source_behavior_digest": source.payload.get("facts_coverage", {}).get("behavior_digest"),
                "target_behavior_digest": projections[right.file_path].payload.get("facts_coverage", {}).get("behavior_digest"),
                "source_coverage": source.payload.get("facts_coverage", {}).get("status", "UNKNOWN"),
                "target_coverage": projections[right.file_path].payload.get("facts_coverage", {}).get("status", "UNKNOWN"),
                "producer_digest": self.index.producer}
            edges.append(edge.model_copy(update={"metadata": {**edge.metadata, "dependency_certificate": certificate}}))
        self._cross_cache[cache_key] = edges
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
            # Alias/package imports cannot be keyed by their eventual target at
            # file-extraction time. Resolve a bounded source-spec frontier now.
            refs.extend(self._facts("IMPORT_SPEC", limit=64))
            seen = set()
            for ref in refs:
                source_path = ref["source_path"]
                if source_path in seen:
                    continue
                seen.add(source_path)
                edges.extend(edge for edge in self._cross_edges(source_path) if edge.target == node_id)
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
                "reason": "bounded_active_graph; statically proven imports only; global absence remains unknown",
                "total_nodes": len(nodes), "total_edges": len(edges),
                "query_truncated": self.query_truncated, "unresolved_graph_relationships": max(1, len(self.unresolved_frontier)),
                "unresolved_frontier": dict(self.unresolved_frontier), "frontier_exhaustive": False,
                "snapshot_id": self.index.snapshot_id})
