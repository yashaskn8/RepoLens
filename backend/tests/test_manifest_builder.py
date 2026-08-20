"""Unit tests for building repository manifests, directory traversal, and framework detection."""

import json
import os
import tempfile
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
