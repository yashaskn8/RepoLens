"""Deterministic, token-bounded repository evidence packing for model prompts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Any, Callable

from app.context.schemas import ContextBundle


@dataclass(frozen=True, slots=True)
class PackedRepositoryContext:
    text: str
    digest: str
    estimated_tokens: int
    included: dict[str, int]
    available: dict[str, int]
    truncated: bool
    evidence_index: dict[str, dict[str, Any]]


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def pack_repository_context(
    bundle: ContextBundle,
    *,
    token_budget: int,
    bytes_per_token: float = 3.0,
) -> PackedRepositoryContext:
    """Render the most relevant deterministic facts inside a strict byte budget.

    Repository content remains explicitly untrusted. Canonical identifiers and
    original content hashes survive excerpt truncation so downstream validation
    can always bind a model claim back to its source fact.
    """
    if token_budget < 256:
        raise ValueError("Repository prompt token budget must be at least 256")
    if bytes_per_token <= 0:
        raise ValueError("bytes_per_token must be positive")

    max_bytes = int(token_budget * bytes_per_token)
    available = {
        "chunks": len(bundle.relevant_chunks),
        "graph_edges": len(bundle.graph_relationships),
        "contracts": len(bundle.routes_and_contracts),
        "static_findings": len(bundle.static_findings),
    }
    payload: dict[str, Any] = {
        "schema": "repository-context/1.0",
        "scan_id": bundle.scan_id[:128],
        "intent": bundle.analysis_intent[:64],
        "query": bundle.query[:512],
        "coverage": {
            "available": available,
            "included": {key: 0 for key in available},
            "truncated": False,
        },
        "facts": {
            "chunks": [],
            "graph_edges": [],
            "contracts": [],
            "static_findings": [],
        },
    }

    def append_if_fits(kind: str, item: dict[str, Any]) -> bool:
        target = payload["facts"][kind]
        target.append(item)
        payload["coverage"]["included"][kind] += 1
        if len(_json_bytes(payload)) <= max_bytes:
            return True
        payload["coverage"]["included"][kind] -= 1
        target.pop()
        return False

    def append_excerpt(kind: str, item: dict[str, Any], content_key: str) -> bool:
        if append_if_fits(kind, item):
            return True
        original = str(item.get(content_key, ""))
        low, high = 0, len(original)
        best: dict[str, Any] | None = None
        while low <= high:
            midpoint = (low + high) // 2
            candidate = dict(item)
            candidate[content_key] = original[:midpoint]
            candidate["excerpt_truncated"] = midpoint < len(original)
            target = payload["facts"][kind]
            target.append(candidate)
            fits = len(_json_bytes(payload)) <= max_bytes
            target.pop()
            if fits:
                best = candidate
                low = midpoint + 1
            else:
                high = midpoint - 1
        if best is None or len(str(best.get(content_key, ""))) < 96:
            return False
        return append_if_fits(kind, best)

    chunks = [
        {
            "evidence_id": f"chunk:{result.chunk_id}",
            "id": result.chunk_id,
            "commit": result.chunk.commit_sha,
            "file": result.chunk.file_path,
            "symbol": result.chunk.symbol,
            "symbol_kind": _enum_value(result.chunk.symbol_kind),
            "lines": [result.chunk.start_line, result.chunk.end_line],
            "language": result.chunk.language,
            "score": round(float(result.score), 6),
            "channels": [_enum_value(channel) for channel in result.source_channels],
            "source_content_hash": result.chunk.content_hash,
            "content": result.chunk.content,
        }
        for result in bundle.relevant_chunks
    ]
    graph_edges = [
        {
            "evidence_id": f"edge:{_enum_value(edge.kind)}:{edge.source}->{edge.target}",
            "source": edge.source,
            "kind": _enum_value(edge.kind),
            "target": edge.target,
        }
        for edge in bundle.graph_relationships
    ]
    contracts = [
        {
            "evidence_id": f"contract:{match.frontend_request_id}",
            "request_id": match.frontend_request_id,
            "frontend": {
                "method": match.frontend_method,
                "url": match.frontend_url,
                "file": match.frontend_file,
                "line": match.frontend_line,
            },
            "status": _enum_value(match.status),
            "backend_paths": match.matched_backend_paths,
            "backend_methods": match.matched_backend_methods,
            "details": match.details[:600],
        }
        for match in bundle.routes_and_contracts
    ]
    static_findings = [
        {
            "evidence_id": (
                f"scanner:{finding.tool}:{finding.rule_id}:"
                f"{finding.evidence.file_path}:{finding.evidence.start_line or 1}"
            ),
            "tool": finding.tool,
            "rule_id": finding.rule_id,
            "severity": _enum_value(finding.severity),
            "title": finding.title,
            "description": finding.description[:800],
            "category": finding.category,
            "mitigation": finding.mitigation,
            "confidence": finding.confidence,
            "file": finding.evidence.file_path,
            "lines": [finding.evidence.start_line, finding.evidence.end_line],
            "code_snippet": finding.evidence.code_snippet,
            "source_tool": finding.source_tool or finding.tool,
            "detector_id": finding.detector_id or finding.rule_id,
            "detector_kind": finding.detector_kind or "static_scanner",
        }
        for finding in bundle.static_findings
    ]

    appenders: dict[str, tuple[list[dict[str, Any]], Callable[[str, dict[str, Any]], bool]]] = {
        "chunks": (chunks, lambda kind, item: append_excerpt(kind, item, "content")),
        "graph_edges": (graph_edges, append_if_fits),
        "contracts": (contracts, append_if_fits),
        "static_findings": (static_findings, append_if_fits),
    }
    order_by_intent = {
        "security": ("static_findings", "chunks", "graph_edges", "contracts"),
        "integration": ("contracts", "chunks", "graph_edges", "static_findings"),
        "architecture": ("graph_edges", "contracts", "chunks", "static_findings"),
        "verification": ("chunks", "static_findings", "graph_edges", "contracts"),
        "bug": ("chunks", "static_findings", "graph_edges", "contracts"),
    }
    order = order_by_intent.get(bundle.analysis_intent, ("chunks", "static_findings", "contracts", "graph_edges"))
    for kind in order:
        items, appender = appenders[kind]
        for item in items:
            if not appender(kind, item):
                break

    included = dict(payload["coverage"]["included"])
    truncated = any(included[key] < available[key] for key in available)
    payload["coverage"]["truncated"] = truncated
    text = _json_bytes(payload).decode("utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    evidence_index: dict[str, dict[str, Any]] = {}
    for item in payload["facts"]["chunks"]:
        evidence_index[item["evidence_id"]] = {
            "kind": "chunk",
            "file_path": item["file"],
            "start_line": item["lines"][0],
            "end_line": item["lines"][1],
            "code_snippet": item["content"],
            "content_hash": item["source_content_hash"],
            "commit_sha": item["commit"],
        }
    for item in payload["facts"]["static_findings"]:
        evidence_index[item["evidence_id"]] = {
            "kind": "static_finding",
            "file_path": item["file"],
            "start_line": item["lines"][0],
            "end_line": item["lines"][1],
            "code_snippet": item["code_snippet"],
            "tool": item["tool"],
            "rule_id": item["rule_id"],
            "title": item["title"],
            "description": item["description"],
            "severity": item["severity"],
            "category": item["category"],
            "mitigation": item["mitigation"],
            "confidence": item["confidence"],
            "source_tool": item["source_tool"],
            "detector_id": item["detector_id"],
            "detector_kind": item["detector_kind"],
        }
    for item in payload["facts"]["contracts"]:
        evidence_index[item["evidence_id"]] = {
            "kind": "contract",
            "file_path": item["frontend"]["file"],
            "start_line": item["frontend"]["line"],
            "end_line": item["frontend"]["line"],
            "code_snippet": None,
            "status": item["status"],
            "frontend_method": item["frontend"]["method"],
            "frontend_url": item["frontend"]["url"],
            "backend_paths": list(item["backend_paths"]),
            "backend_methods": list(item["backend_methods"]),
            "details": item["details"],
            "source_tool": "route_contract",
            "detector_id": item["evidence_id"],
            "detector_kind": "contract_matcher",
        }
    for item in payload["facts"]["graph_edges"]:
        evidence_index[item["evidence_id"]] = {
            "kind": "graph_edge",
            "file_path": None,
            "start_line": None,
            "end_line": None,
            "code_snippet": None,
        }
    return PackedRepositoryContext(
        text=text,
        digest=digest,
        estimated_tokens=max(1, math.ceil(len(text.encode("utf-8")) / bytes_per_token)),
        included=included,
        available=available,
        truncated=truncated,
        evidence_index=evidence_index,
    )


__all__ = ["PackedRepositoryContext", "pack_repository_context"]
