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


def _request_body_mismatch(
    request: GraphNode,
    route: GraphNode,
) -> tuple[ContractMatchStatus | None, list[str], dict[str, list[str]], str]:
    """Compare only statically known body structure; unknown shapes remain unknown."""
    shape = request.metadata.get("body_shape")
    schema_fields = route.metadata.get("request_schema_fields") or {}
    if not isinstance(shape, dict) or shape.get("kind") in {None, "unknown"} or not schema_fields:
        return None, [], {}, ""

    required = sorted(
        name for name, field in schema_fields.items()
        if isinstance(field, dict) and field.get("required") is True
    )
    if required and shape.get("kind") != "object":
        return (
            ContractMatchStatus.REQUEST_BODY_TYPE_MISMATCH,
            required,
            {},
            f"Frontend sends a {shape.get('kind')} body, but backend schema "
            f"{route.metadata.get('request_schema')!r} requires an object with fields {required}.",
        )

    frontend_keys = set(shape.get("keys") or [])
    missing = sorted(set(required) - frontend_keys)
    missing_items: dict[str, list[str]] = {}
    properties = shape.get("properties") if isinstance(shape.get("properties"), dict) else {}
    for name, field in schema_fields.items():
        if not isinstance(field, dict) or name not in frontend_keys:
            continue
        item_fields = field.get("item_fields")
        property_shape = properties.get(name)
        if not isinstance(item_fields, dict) or not isinstance(property_shape, dict):
            continue
        item_shape = property_shape.get("item") if property_shape.get("kind") == "array" else None
        if not isinstance(item_shape, dict) or item_shape.get("kind") != "object":
            continue
        item_required = {
            item_name for item_name, item_field in item_fields.items()
            if isinstance(item_field, dict) and item_field.get("required") is True
        }
        absent = sorted(item_required - set(item_shape.get("keys") or []))
        if absent:
            missing_items[name] = absent

    if missing or missing_items:
        details = []
        if missing:
            details.append(f"missing required fields {missing}")
        if missing_items:
            details.append(
                "missing required list-item fields "
                + ", ".join(f"{name}: {fields}" for name, fields in sorted(missing_items.items()))
            )
        return (
            ContractMatchStatus.REQUEST_BODY_MISSING_REQUIRED_FIELDS,
            missing,
            missing_items,
            f"Frontend request body is incompatible with backend schema "
            f"{route.metadata.get('request_schema')!r}: {'; '.join(details)}.",
        )
    return None, [], {}, ""


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

    # A template-literal base URL is not part of the API path. Preserve later
    # path-parameter interpolations while removing a leading static base.
    cleaned = re.sub(r"^\$\{[^}]+\}(?=/)", "", cleaned)

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
            body_status, missing, missing_items, body_details = _request_body_mismatch(req, matched_r)
            if body_status is not None:
                report.payload_mismatch_count += 1
                report.matches.append(
                    RouteContractMatch(
                        frontend_request_id=req.id,
                        frontend_method=req_method,
                        frontend_url=raw_url,
                        frontend_file=req_file,
                        frontend_line=req_line,
                        status=body_status,
                        matched_route_ids=[matched_r.id],
                        matched_backend_paths=[matched_r.metadata.get("path", "")],
                        matched_backend_methods=[str(matched_r.metadata.get("http_method", ""))],
                        backend_file=matched_r.file_path,
                        backend_line=matched_r.start_line,
                        backend_request_schema=matched_r.metadata.get("request_schema"),
                        frontend_body_shape=req.metadata.get("body_shape") or {},
                        missing_required_fields=missing,
                        missing_item_fields=missing_items,
                        details=body_details,
                    )
                )
                continue
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
                    backend_file=matched_r.file_path,
                    backend_line=matched_r.start_line,
                    backend_request_schema=matched_r.metadata.get("request_schema"),
                    frontend_body_shape=req.metadata.get("body_shape") or {},
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
                    backend_file=exact_method_matches[0].file_path,
                    backend_line=exact_method_matches[0].start_line,
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
                    backend_file=candidate_routes[0].file_path,
                    backend_line=candidate_routes[0].start_line,
                    details=f"Method mismatch: Frontend sends {req_method} to '{raw_url}', but backend only accepts {available_methods}.",
                )
            )

    return report
