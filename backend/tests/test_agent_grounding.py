"""Focused tests for the specialist evidence-grounding boundary."""

from dataclasses import FrozenInstanceError

import pytest

from app.agents.grounding import (
    EvidenceGroundingError,
    build_evidence_index,
    ground_model_findings,
)
from app.context.prompt import PackedRepositoryContext


def _packed_context() -> PackedRepositoryContext:
    return PackedRepositoryContext(
        text="{}",
        digest="a" * 64,
        estimated_tokens=1,
        included={"chunks": 1, "graph_edges": 1, "contracts": 0, "static_findings": 1},
        available={"chunks": 1, "graph_edges": 1, "contracts": 0, "static_findings": 1},
        truncated=False,
        evidence_index={
            "chunk:auth": {
                "kind": "chunk",
                "file_path": "app/auth.py",
                "start_line": 10,
                "end_line": 14,
                "code_snippet": "def authenticate(token):\n    return verify(token)",
                "content_hash": "b" * 64,
            },
            "scanner:semgrep:python.jwt:app/auth.py:12": {
                "kind": "static_finding",
                "file_path": "app/auth.py",
                "start_line": 12,
                "end_line": 12,
                "code_snippet": None,
                "tool": "semgrep",
                "rule_id": "python.jwt",
                "title": "JWT verification disabled",
                "description": "The token is decoded without signature verification.",
                "severity": "HIGH",
            },
            "edge:CALLS:auth->verify": {
                "kind": "graph_edge",
                "file_path": None,
                "start_line": None,
                "end_line": None,
                "code_snippet": None,
            },
        },
    )


def test_build_evidence_index_copies_and_freezes_packed_authority():
    packed = _packed_context()
    index = build_evidence_index(packed)

    packed.evidence_index["chunk:auth"]["file_path"] = "tampered.py"

    assert index["chunk:auth"].file_path == "app/auth.py"
    with pytest.raises(TypeError):
        index["new"] = index["chunk:auth"]  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        index["chunk:auth"].file_path = "tampered.py"  # type: ignore[misc]


def test_ground_model_findings_requires_exact_reference_and_overwrites_model_location():
    index = build_evidence_index(_packed_context())
    grounded = ground_model_findings(
        [
            {
                "title": "JWT validation can fail open",
                "description": "Claim chosen by the model",
                "evidence_refs": ["chunk:auth", "chunk:invented", "chunk:auth"],
                "file_path": "invented/admin.py",
                "start_line": 999,
                "end_line": 1005,
                "code_snippet": "os.system(user_input)",
                "source_tool": "model",
                "detector_id": "invented-rule",
                "detector_kind": "guess",
            }
        ],
        index,
    )

    assert len(grounded) == 1
    finding = grounded[0]
    assert finding["evidence_refs"] == ["chunk:auth"]
    assert finding["primary_evidence_ref"] == "chunk:auth"
    assert finding["file_path"] == "app/auth.py"
    assert finding["start_line"] == 10
    assert finding["end_line"] == 14
    assert finding["code_snippet"] == "def authenticate(token):\n    return verify(token)"
    assert finding["source_tool"] == "repository_context"
    assert finding["detector_id"] == "chunk:auth"
    assert finding["detector_kind"] == "retrieved_code"
    assert finding["context_notes"].startswith(
        "Deterministically grounded: evidence_ref=chunk:auth; sha256="
    )


@pytest.mark.parametrize(
    "references",
    [
        [],
        ["chunk:missing"],
        ["CHUNK:auth"],
        [" chunk:auth"],
        ["edge:CALLS:auth->verify"],
    ],
)
def test_ground_model_findings_rejects_missing_fuzzy_and_non_locatable_references(references):
    assert (
        ground_model_findings(
            [{"title": "Unsupported claim", "evidence_refs": references, "file_path": "app/auth.py"}],
            build_evidence_index(_packed_context()),
        )
        == []
    )


def test_ground_model_findings_prefers_authoritative_scanner_provenance():
    grounded = ground_model_findings(
        [
            {
                "title": "Model-invented title",
                "description": "Model-invented mechanism",
                "severity": "LOW",
                "rule_id": "invented-rule",
                "evidence_refs": ["chunk:auth", "scanner:semgrep:python.jwt:app/auth.py:12"],
                "code_snippet": "fabricated snippet",
            }
        ],
        build_evidence_index(_packed_context()),
    )

    assert grounded[0]["primary_evidence_ref"] == "scanner:semgrep:python.jwt:app/auth.py:12"
    assert grounded[0]["start_line"] == 12
    assert grounded[0]["end_line"] == 12
    assert grounded[0]["code_snippet"] is None
    assert grounded[0]["source_tool"] == "semgrep"
    assert grounded[0]["detector_id"] == "python.jwt"
    assert grounded[0]["detector_kind"] == "static_scanner"
    assert grounded[0]["tool"] == "semgrep"
    assert grounded[0]["rule_id"] == "python.jwt"
    assert grounded[0]["title"] == "JWT verification disabled"
    assert grounded[0]["description"] == "The token is decoded without signature verification."
    assert grounded[0]["severity"] == "HIGH"


def test_build_evidence_index_rejects_ambiguous_or_invalid_explicit_authority():
    with pytest.raises(EvidenceGroundingError, match="conflicts with embedded ID"):
        build_evidence_index(
            {
                "chunk:known": {
                    "evidence_id": "chunk:different",
                    "kind": "chunk",
                    "file_path": "app.py",
                    "start_line": 1,
                    "end_line": 1,
                }
            }
        )

    with pytest.raises(EvidenceGroundingError, match="ends before it starts"):
        build_evidence_index(
            {
                "chunk:invalid-lines": {
                    "kind": "chunk",
                    "file_path": "app.py",
                    "start_line": 20,
                    "end_line": 10,
                }
            }
        )
