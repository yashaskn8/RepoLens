"""Unit tests for building repository manifests, directory traversal, and framework detection."""

import json
import hashlib
import os
import tempfile
from types import SimpleNamespace
import builtins
import pytest
from app.ingestion.manifest import build_manifest
from app.ingestion.schemas import SymbolKind


@pytest.fixture
def mock_repo_directory():
    """Create a temporary directory structure representing a multi-language repo."""
    with tempfile.TemporaryDirectory(prefix="test_repo_") as tmp_dir:
        # 1. Root package.json
        pkg_json = {
            "name": "sample-monorepo",
            "dependencies": {
                "next": "^14.0.0",
                "react": "^18.2.0",
                "axios": "^1.6.0"
            }
        }
        with open(os.path.join(tmp_dir, "package.json"), "w", encoding="utf-8") as f:
            json.dump(pkg_json, f)

        # 2. Root requirements.txt
        with open(os.path.join(tmp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("fastapi>=0.110.0\npydantic>=2.0.0\nsqlalchemy>=2.0.0\n")

        # 3. Python file in backend/
        backend_dir = os.path.join(tmp_dir, "backend")
        os.makedirs(backend_dir, exist_ok=True)
        py_code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/health")
def check_health():
    return {"status": "ok"}
"""
        with open(os.path.join(backend_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(py_code)

        # 4. TypeScript file in frontend/
        frontend_dir = os.path.join(tmp_dir, "frontend")
        os.makedirs(frontend_dir, exist_ok=True)
        ts_code = """
export function formatGreeting(name: string): string {
    return `Hello ${name}`;
}
"""
        with open(os.path.join(frontend_dir, "utils.ts"), "w", encoding="utf-8") as f:
            f.write(ts_code)

        # 5. Ignored directory: node_modules
        node_modules_dir = os.path.join(tmp_dir, "node_modules", "some-lib")
        os.makedirs(node_modules_dir, exist_ok=True)
        with open(os.path.join(node_modules_dir, "index.js"), "w", encoding="utf-8") as f:
            f.write("module.exports = {};")

        # 6. Binary file
        with open(os.path.join(tmp_dir, "logo.png"), "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

        yield tmp_dir


def test_build_manifest_structure_and_frameworks(mock_repo_directory):
    """Verify that build_manifest processes files, extracts symbols, detects frameworks, and skips ignored folders."""
    manifest = build_manifest(
        repo_dir=mock_repo_directory,
        repository_url="https://github.com/org/sample-repo.git",
        commit_hash="a1b2c3d4e5f67890123456789012345678901234",
        branch="main",
    )

    assert manifest.repository_url == "https://github.com/org/sample-repo.git"
    assert manifest.commit_hash == "a1b2c3d4e5f67890123456789012345678901234"
    assert manifest.branch == "main"

    for entry in manifest.files:
        if not entry.is_binary and not entry.skipped_reason:
            source_path = os.path.join(mock_repo_directory, *entry.path.split("/"))
            with open(source_path, "rb") as source_file:
                assert entry.content_sha256 == hashlib.sha256(source_file.read()).hexdigest()

    # node_modules must NOT be processed
    paths = [f.path for f in manifest.files]
    assert not any("node_modules" in p for p in paths)

    # Check language counts
    assert manifest.languages.get("python", 0) >= 1
    assert manifest.languages.get("typescript", 0) >= 1
    assert manifest.languages.get("json", 0) >= 1

    # Check framework detections
    framework_names = {fw.name for fw in manifest.frameworks}
    assert "FastAPI" in framework_names
    assert "Next.js" in framework_names
    assert "React" in framework_names
    assert "Axios" in framework_names

    # Check parsed symbols in backend/main.py
    py_entry = next((f for f in manifest.files if f.path == "backend/main.py"), None)
    assert py_entry is not None
    assert py_entry.language == "python"
    assert any(s.kind == SymbolKind.FASTAPI_ROUTE for s in py_entry.symbols)

    # Check binary file handling
    png_entry = next((f for f in manifest.files if f.path == "logo.png"), None)
    assert png_entry is not None
    assert png_entry.is_binary is True
    assert len(png_entry.symbols) == 0


@pytest.mark.parametrize(
    ("filename", "content", "expected_framework"),
    [
        ("package.json", b'{"dependencies":{"react":"1"}}', "React"),
        ("requirements.txt", b"fastapi==0.110.0\n", "FastAPI"),
        ("pyproject.toml", b'[project]\ndependencies=["fastapi"]\n', "FastAPI"),
    ],
)
@pytest.mark.parametrize("size_delta,detected", [(-1, True), (0, True), (1, False)])
def test_framework_manifests_obey_shared_file_size_boundary(
    tmp_path, monkeypatch, filename, content, expected_framework, size_delta, detected
):
    limit = 128
    padding = b" " * max(0, limit + size_delta - len(content))
    payload = (content + padding)[: limit + size_delta]
    (tmp_path / filename).write_bytes(payload)
    settings = SimpleNamespace(
        MAX_REPO_FILES=100,
        MAX_FILE_SIZE_BYTES=limit,
        MAX_TOTAL_SOURCE_BYTES=4096,
    )
    monkeypatch.setattr("app.ingestion.manifest.get_settings", lambda: settings)

    manifest = build_manifest(
        repo_dir=str(tmp_path),
        repository_url="https://github.com/org/bounded-manifest.git",
        commit_hash="b" * 40,
    )

    frameworks = {item.name for item in manifest.frameworks}
    assert (expected_framework in frameworks) is detected
    file_entry = next(item for item in manifest.files if item.path == filename)
    if size_delta > 0:
        assert file_entry.skipped_reason == "exceeds_max_size"
    else:
        assert file_entry.skipped_reason is None


def test_manifest_detector_does_not_reread_admitted_root_manifest(tmp_path, monkeypatch):
    payload = b'{"dependencies":{"react":"1"}}'
    target = tmp_path / "package.json"
    target.write_bytes(payload)
    original_open = builtins.open
    reads = 0

    def counted_open(file, *args, **kwargs):
        nonlocal reads
        if os.fspath(file) == os.fspath(target) and args and args[0] == "rb":
            reads += 1
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counted_open)
    manifest = build_manifest(
        repo_dir=str(tmp_path),
        repository_url="https://github.com/org/single-read.git",
        commit_hash="c" * 40,
    )

    assert any(item.name == "React" for item in manifest.frameworks)
    assert reads == 1


def test_manifest_skips_symlink_file_without_reading_external_target(tmp_path, monkeypatch):
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET_OUTSIDE_REPOSITORY = True\n", encoding="utf-8")
    link = repository / "linked.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        monkeypatch.setattr(
            "app.ingestion.manifest._is_link_or_reparse_point",
            lambda value: os.fspath(value) == os.fspath(link),
        )
    # Windows may omit file symlinks from os.walk's files list depending on
    # privileges/filesystem. Present the directory entry deterministically so
    # this test exercises the manifest's link policy on every platform.
    monkeypatch.setattr(
        "app.ingestion.manifest.os.walk",
        lambda *args, **kwargs: iter([(str(repository), [], ["linked.py"])]),
    )

    manifest = build_manifest(
        repo_dir=str(repository),
        repository_url="https://github.com/org/symlink-fixture.git",
        commit_hash="e" * 40,
    )

    entry = next((item for item in manifest.files if item.path == "linked.py"), None)
    if entry is not None:
        assert entry.skipped_reason == "unsafe_link_or_reparse_entry"
        assert entry.content_sha256 is None
    assert manifest.analysis_scope.truncated is True
    assert manifest.analysis_scope.reason == "unsafe_link_or_reparse_entry"


@pytest.mark.parametrize("payload", [b"\xff\xfe", b"{not-json"])
def test_framework_detector_malformed_metadata_degrades_safely(tmp_path, payload):
    (tmp_path / "package.json").write_bytes(payload)
    manifest = build_manifest(
        repo_dir=str(tmp_path),
        repository_url="https://github.com/org/malformed-manifest.git",
        commit_hash="d" * 40,
    )
    assert manifest.frameworks == []
