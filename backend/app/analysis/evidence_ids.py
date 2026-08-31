"""Canonical helpers for creating and parsing deterministic evidence references."""

import re
from typing import Any, Dict, Optional
from uuid import UUID


def normalize_path(path: str) -> str:
    """Normalize file path to use forward slashes and strip leading slashes."""
    return path.replace("\\", "/").lstrip("/")


def make_file_evidence_id(file_path: str) -> str:
    """Construct exact file evidence ID: file:<normalized_path>"""
    return f"file:{normalize_path(file_path)}"


def make_symbol_evidence_id(
    file_path: str,
    kind: str,
    name: str,
    start_line: int,
) -> str:
    """Construct exact symbol evidence ID matching RepositoryGraph node convention:
    symbol:<normalized_path>:<kind>:<name>:<start_line>
    """
    return f"symbol:{normalize_path(file_path)}:{kind}:{name}:{start_line}"


def make_route_evidence_id(method: str, path: str) -> str:
    """Construct exact route evidence ID: route:<METHOD>:<path>"""
    return f"route:{method.upper()}:{path}"


def make_impact_evidence_id(impact_id: UUID | str) -> str:
    """Construct exact impact evidence ID: impact:<uuid>"""
    return f"impact:{str(impact_id).lower()}"


def make_config_evidence_id(file_path: str, key: str) -> str:
    """Construct exact config evidence ID: config:<normalized_path>:<key>"""
    return f"config:{normalize_path(file_path)}:{key}"


def make_dependency_evidence_id(manifest_path: str, package_name: str) -> str:
    """Construct exact dependency evidence ID: dependency:<manifest_path>:<package>"""
    return f"dependency:{normalize_path(manifest_path)}:{package_name}"


def make_edge_evidence_id(edge_kind: str, source_node_id: str, target_node_id: str) -> str:
    """Construct exact edge evidence ID: edge:<EDGE_KIND>:<source_node_id>-><target_node_id>"""
    return f"edge:{edge_kind.upper()}:{source_node_id}->{target_node_id}"


def make_line_evidence_id(file_path: str, start_line: int, end_line: Optional[int] = None) -> str:
    """Construct exact line range evidence ID: line:<normalized_path>:<start_line>-<end_line>"""
    if end_line is not None and end_line != start_line:
        return f"line:{normalize_path(file_path)}:{start_line}-{end_line}"
    return f"line:{normalize_path(file_path)}:{start_line}"


def make_schema_delta_evidence_id(
    file_path: str,
    model_name: str,
    field_name: str,
    change_type: str,
) -> str:
    """Construct exact schema delta evidence ID:
    schema-delta:<normalized_file>:<model>:<field>:<change_type>
    """
    return f"schema-delta:{normalize_path(file_path)}:{model_name}:{field_name}:{change_type}"


def make_route_delta_evidence_id(
    file_path: str,
    base_method: Optional[str],
    base_path: Optional[str],
    head_method: Optional[str],
    head_path: Optional[str],
) -> str:
    """Construct exact route delta evidence ID:
    route-delta:<normalized_file>:<BASE_METHOD>:<BASE_PATH>-><HEAD_METHOD>:<HEAD_PATH>
    (Uses NONE for missing sides)
    """
    b_m = base_method.upper() if base_method else "NONE"
    b_p = base_path if base_path else "NONE"
    h_m = head_method.upper() if head_method else "NONE"
    h_p = head_path if head_path else "NONE"
    return f"route-delta:{normalize_path(file_path)}:{b_m}:{b_p}->{h_m}:{h_p}"

