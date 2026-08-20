"""Deterministic cross-layer route contract matcher."""

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from app.graph.schemas import (
    ContractMatchReport,
    ContractMatchStatus,
    GraphNode,
    NodeKind,
    RouteContractMatch,
)


def normalize_route_path(path: str) -> str:
    """Normalize route path across Express (:id), FastAPI ({id}), Next.js ([id]), and query strings.
    
    Examples:
    - "/api/v1/users/:userId/profile" -> "/api/v1/users/{param}/profile"
    - "/api/v1/users/{user_id}/profile" -> "/api/v1/users/{param}/profile"
    - "/users/[id]" -> "/users/{param}"
    - "/api/items?limit=10&offset=0" -> "/api/items"
    - "http://localhost:8000/api/items/${itemId}" -> "/api/items/{param}"
    """
    if not path or not isinstance(path, str):
        return "/"

    cleaned = path.strip()

    # 1. Strip protocol, host, and port if full URL is supplied
    if cleaned.startswith(("http://", "https://")):
        parsed = urlparse(cleaned)
        cleaned = parsed.path or "/"

    # 2. Strip query parameters and hash fragments
    cleaned = cleaned.split("?")[0].split("#")[0]

    # 3. Handle template literal interpolation ${...} or concatenated + id
    cleaned = re.sub(r"\$\{[^}]+\}", "{param}", cleaned)

    # 4. Normalize Express-style parameter segments (:id, :userId, :item_id) -> {param}
    cleaned = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)", "{param}", cleaned)

    # 5. Normalize FastAPI/OpenAPI-style parameters ({id}, {item_id}) -> {param}
    cleaned = re.sub(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}", "{param}", cleaned)

    # 6. Normalize Next.js dynamic route brackets ([id], [...slug], [[...optional]]) -> {param}
    cleaned = re.sub(r"\[(?:\.\.\.)?[a-zA-Z_][a-zA-Z0-9_]*\]", "{param}", cleaned)

    # 7. Normalize redundant slashes and ensure leading slash
    cleaned = re.sub(r"/+", "/", cleaned)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned

    # 8. Strip trailing slash unless root path
    if len(cleaned) > 1 and cleaned.endswith("/"):
        cleaned = cleaned[:-1]

    return cleaned.lower()


def match_route_contract(
    frontend_requests: List[GraphNode],
    backend_routes: List[GraphNode],
) -> ContractMatchReport:
    """Deterministically match frontend HTTP client requests against backend exposed API routes."""
    report = ContractMatchReport(
        total_frontend_requests=len(frontend_requests),
        total_backend_routes=len(backend_routes),
    )

    # Build backend route lookup structures
    # 1. Exact normalized path -> list of backend route nodes
    routes_by_path: dict[str, List[GraphNode]] = {}
    for r in backend_routes:
        raw_path = r.metadata.get("path") or r.label
        norm_path = normalize_route_path(raw_path)
        routes_by_path.setdefault(norm_path, []).append(r)

    for req in frontend_requests:
        raw_url = req.metadata.get("url") or req.metadata.get("path") or req.label
        norm_req_path = normalize_route_path(raw_url)
        req_method = str(req.metadata.get("http_method", "GET")).upper()
        req_file = req.file_path or "unknown"
        req_line = req.start_line

        # Check candidate route matches by path
        candidate_routes = routes_by_path.get(norm_req_path, [])

        # Fallback: check matching relative sub-path (e.g. frontend uses /items, backend has /api/v1/items or vice-versa)
        if not candidate_routes:
            for b_path, b_routes in routes_by_path.items():
                if b_path.endswith(norm_req_path) or norm_req_path.endswith(b_path):
                    # Only match if segments match at least 1 significant segment
                    if norm_req_path != "/" and b_path != "/":
                        candidate_routes = b_routes
                        break

        if not candidate_routes:
            # Check for path prefix mismatch
            report.unmatched_count += 1
            report.matches.append(
                RouteContractMatch(
                    frontend_request_id=req.id,
                    frontend_method=req_method,
                    frontend_url=raw_url,
                    frontend_file=req_file,
                    frontend_line=req_line,
                    status=ContractMatchStatus.UNMATCHED_FRONTEND_REQUEST,
                    details=f"Frontend request to '{raw_url}' has no corresponding backend route.",
                )
            )
            continue

        # Check HTTP method match among candidates
        exact_method_matches = [
            r for r in candidate_routes
            if str(r.metadata.get("http_method", "GET")).upper() == req_method
        ]

        if len(exact_method_matches) == 1:
            matched_r = exact_method_matches[0]
            report.matched_count += 1
            report.matches.append(
                RouteContractMatch(
                    frontend_request_id=req.id,
                    frontend_method=req_method,
                    frontend_url=raw_url,
                    frontend_file=req_file,
                    frontend_line=req_line,
                    status=ContractMatchStatus.MATCHED,
                    matched_route_ids=[matched_r.id],
                    matched_backend_paths=[matched_r.metadata.get("path", "")],
                    matched_backend_methods=[str(matched_r.metadata.get("http_method", ""))],
                    details=f"Matched backend route {matched_r.metadata.get('http_method', '')} {matched_r.metadata.get('path', '')}",
                )
            )

        elif len(exact_method_matches) > 1:
            report.ambiguous_count += 1
            report.matches.append(
                RouteContractMatch(
                    frontend_request_id=req.id,
                    frontend_method=req_method,
                    frontend_url=raw_url,
                    frontend_file=req_file,
                    frontend_line=req_line,
                    status=ContractMatchStatus.AMBIGUOUS_MATCH,
                    matched_route_ids=[r.id for r in exact_method_matches],
                    matched_backend_paths=[r.metadata.get("path", "") for r in exact_method_matches],
                    matched_backend_methods=[str(r.metadata.get("http_method", "")) for r in exact_method_matches],
                    details=f"Ambiguous match: {len(exact_method_matches)} routes match {req_method} {norm_req_path}",
                )
            )

        else:
            # Method Mismatch: path exists on backend, but method differs
            report.method_mismatch_count += 1
            available_methods = [str(r.metadata.get("http_method", "")) for r in candidate_routes]
            report.matches.append(
                RouteContractMatch(
                    frontend_request_id=req.id,
                    frontend_method=req_method,
                    frontend_url=raw_url,
                    frontend_file=req_file,
                    frontend_line=req_line,
                    status=ContractMatchStatus.METHOD_MISMATCH,
                    matched_route_ids=[r.id for r in candidate_routes],
                    matched_backend_paths=[r.metadata.get("path", "") for r in candidate_routes],
                    matched_backend_methods=available_methods,
                    details=f"Method mismatch: Frontend sends {req_method} to '{raw_url}', but backend only accepts {available_methods}.",
                )
            )

    return report
