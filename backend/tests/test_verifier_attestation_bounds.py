from types import SimpleNamespace
import hashlib

from app.agents import verifier
from app.ingestion.schemas import FileEntry, RepositoryManifest


def _manifest(file_path: str, source: bytes, *, commit: str = "a" * 40) -> RepositoryManifest:
    return RepositoryManifest(
        repository_url="https://github.com/example/repo",
        commit_hash=commit,
        commit_sha=commit,
        total_files=1,
        total_size_bytes=len(source),
        files=[
            FileEntry(
                path=file_path,
                size_bytes=len(source),
                content_sha256=hashlib.sha256(source).hexdigest(),
                lines_count=source.count(b"\n") + (1 if source and not source.endswith(b"\n") else 0),
            )
        ],
    )


def test_verifier_attests_only_manifest_authorized_snapshot_source(tmp_path):
    source = b"safe = True\n"
    (tmp_path / "main.py").write_bytes(source)
    manifest = _manifest("main.py", source)

    result, error = verifier._attest_repository_evidence(
        str(tmp_path), "main.py", 1, 1, "a" * 40, manifest
    )

    assert error == ""
    assert result is not None
    assert result.code_snippet == "safe = True\n"


def test_verifier_rejects_unmanifested_file_even_inside_repository(tmp_path):
    (tmp_path / ".git" / "objects" / "pack").mkdir(parents=True)
    (tmp_path / ".git" / "objects" / "pack" / "pack-large").write_bytes(b"x" * 10_000)
    manifest = _manifest("main.py", b"safe = True\n")

    result, error = verifier._attest_repository_evidence(
        str(tmp_path), ".git/objects/pack/pack-large", 1, 1, "a" * 40, manifest
    )

    assert result is None
    assert "not present in the repository manifest" in error


def test_verifier_rejects_file_above_configured_byte_bound(tmp_path, monkeypatch):
    source = b"very large source"
    (tmp_path / "large.py").write_bytes(source)
    monkeypatch.setattr(verifier, "get_settings", lambda: SimpleNamespace(MAX_FILE_SIZE_BYTES=8))

    result, error = verifier._attest_repository_evidence(
        str(tmp_path), "large.py", 1, 1, "a" * 40, _manifest("large.py", source)
    )

    assert result is None
    assert "attestation limit" in error


def test_verifier_rejects_manifest_from_another_snapshot(tmp_path):
    source = b"safe = True\n"
    (tmp_path / "main.py").write_bytes(source)

    result, error = verifier._attest_repository_evidence(
        str(tmp_path), "main.py", 1, 1, "b" * 40, _manifest("main.py", source)
    )

    assert result is None
    assert "does not match the active snapshot" in error


def test_verifier_rejects_same_size_source_drift(tmp_path):
    original = b"safe = True\n"
    (tmp_path / "main.py").write_bytes(original)
    manifest = _manifest("main.py", original)
    (tmp_path / "main.py").write_bytes(b"evil = True\n")

    result, error = verifier._attest_repository_evidence(
        str(tmp_path), "main.py", 1, 1, "a" * 40, manifest
    )

    assert result is None
    assert "no longer matches" in error


def test_verifier_rejects_overwide_evidence_range(tmp_path):
    original = b"x = 1\n" * (verifier.MAX_VERIFIER_EVIDENCE_LINES + 1)
    (tmp_path / "main.py").write_bytes(original)

    result, error = verifier._attest_repository_evidence(
        str(tmp_path),
        "main.py",
        1,
        verifier.MAX_VERIFIER_EVIDENCE_LINES + 1,
        "a" * 40,
        _manifest("main.py", original),
    )

    assert result is None
    assert "line attestation limit" in error
