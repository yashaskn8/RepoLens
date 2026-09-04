"""Publication-boundary tests for deterministic finding grounding."""

import json

from app.services.finding_grounding import (
    GROUNDING_SCHEMA_VERSION,
    canonicalize_repository_evidences,
    is_canonical_confirmed_finding,
    is_deterministically_grounded_evidence,
)


def test_canonicalization_replaces_model_snippet_with_exact_snapshot_bytes(tmp_path):
    source = tmp_path / "src" / "service.py"
    source.parent.mkdir(parents=True)
    source.write_text("def load():\n    return unsafe(value)\n", encoding="utf-8")
    commit_sha = "a" * 40

    evidences = canonicalize_repository_evidences(
        repo_dir=str(tmp_path),
        commit_sha=commit_sha,
        evidences=[
            {
                "file_path": "src/service.py",
                "start_line": 2,
                "end_line": 2,
                "code_snippet": "invented_by_model()",
                "context_notes": "untrusted model explanation",
            }
        ],
    )

    assert len(evidences) == 1
    assert evidences[0].code_snippet == "    return unsafe(value)"
    attestation = json.loads(evidences[0].context_notes)
    assert attestation["schema_version"] == GROUNDING_SCHEMA_VERSION
    assert attestation["commit_sha"] == commit_sha
    assert attestation["file_path"] == "src/service.py"
    assert is_deterministically_grounded_evidence(
        evidences[0],
        expected_commit_sha=commit_sha,
    )


def test_canonicalization_rejects_escape_missing_and_out_of_range_evidence(tmp_path):
    (tmp_path / "inside.py").write_text("value = 1\n", encoding="utf-8")

    evidences = canonicalize_repository_evidences(
        repo_dir=str(tmp_path),
        commit_sha="b" * 40,
        evidences=[
            {"file_path": "../outside.py", "start_line": 1, "end_line": 1},
            {"file_path": "missing.py", "start_line": 1, "end_line": 1},
            {"file_path": "inside.py", "start_line": 4, "end_line": 4},
        ],
    )

    assert evidences == []


def test_canonical_finding_requires_confirmed_verdict_and_attested_evidence(tmp_path):
    source = tmp_path / "main.py"
    source.write_text("dangerous_call()\n", encoding="utf-8")
    commit_sha = "c" * 40
    evidence = canonicalize_repository_evidences(
        repo_dir=str(tmp_path),
        commit_sha=commit_sha,
        evidences=[{"file_path": "main.py", "start_line": 1, "end_line": 1}],
    )[0]

    assert is_canonical_confirmed_finding(
        {"verification_verdict": "CONFIRMED", "evidences": [evidence]},
        expected_commit_sha=commit_sha,
    )
    assert not is_canonical_confirmed_finding(
        {"verification_verdict": "POSSIBLE", "evidences": [evidence]},
        expected_commit_sha=commit_sha,
    )
    assert not is_canonical_confirmed_finding(
        {
            "verification_verdict": "CONFIRMED",
            "evidences": [
                {
                    "file_path": "main.py",
                    "start_line": 1,
                    "end_line": 1,
                    "code_snippet": "dangerous_call()",
                    "context_notes": "not an attestation",
                }
            ],
        },
        expected_commit_sha=commit_sha,
    )


def test_canonicalization_rejects_absolute_path_outside_repository(tmp_path):
    """Absolute model paths must not escape the analyzed repository root."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("SECRET = 'do-not-read'\n", encoding="utf-8")

    evidences = canonicalize_repository_evidences(
        repo_dir=str(repo_dir),
        commit_sha="d" * 40,
        evidences=[{"file_path": str(outside), "start_line": 1, "end_line": 1}],
    )

    assert evidences == []


def test_canonical_finding_rejects_attestation_from_stale_commit(tmp_path):
    """Evidence attested for another commit cannot be exposed as canonical truth."""
    source = tmp_path / "main.py"
    source.write_text("safe_call()\n", encoding="utf-8")
    attested = canonicalize_repository_evidences(
        repo_dir=str(tmp_path),
        commit_sha="e" * 40,
        evidences=[{"file_path": "main.py", "start_line": 1, "end_line": 1}],
    )[0]

    assert not is_canonical_confirmed_finding(
        {"verification_verdict": "CONFIRMED", "evidences": [attested]},
        expected_commit_sha="f" * 40,
    )


def test_grounded_evidence_rejects_tampered_snippet(tmp_path):
    """Changing an attested snippet must invalidate the evidence record."""
    source = tmp_path / "main.py"
    source.write_text("safe_call()\n", encoding="utf-8")
    commit_sha = "1" * 40
    attested = canonicalize_repository_evidences(
        repo_dir=str(tmp_path),
        commit_sha=commit_sha,
        evidences=[{"file_path": "main.py", "start_line": 1, "end_line": 1}],
    )[0]
    tampered = attested.model_copy(update={"code_snippet": "invented_call()"})

    assert not is_deterministically_grounded_evidence(
        tampered,
        expected_commit_sha=commit_sha,
    )
