"""Comprehensive tests for Phase 6C: Deterministic Structural Diff Engine."""

import os
import tempfile
from typing import Dict
import pytest

from app.analysis.diff_engine import ChangeDiffEngine, get_diff_engine
from app.schemas.change_analysis import (
    FileChangeType,
    StructuralDiffResult,
    SymbolChangeType,
)


@pytest.fixture
def base_and_head_workspaces():
    """Create realistic base and head workspaces containing all required structural variations."""
    with tempfile.TemporaryDirectory(prefix="base_repo_") as base_dir, \
         tempfile.TemporaryDirectory(prefix="head_repo_") as head_dir:

        # ---------------------------------------------------------------------
        # 1. Function signature change & function deletion: app/services/auth.py
        # ---------------------------------------------------------------------
        base_auth_py = """
def verify_token(token: str) -> bool:
    return len(token) > 0

def deprecated_helper(x: int) -> int:
    return x * 2

def unchanged_func():
    pass
"""
        head_auth_py = """
def verify_token(token: str, issuer: str = "default") -> bool:
    return len(token) > 0 and issuer == "default"

def unchanged_func():
    pass
"""
        os.makedirs(os.path.join(base_dir, "app", "services"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, "app", "services"), exist_ok=True)
        with open(os.path.join(base_dir, "app", "services", "auth.py"), "w", encoding="utf-8") as f:
            f.write(base_auth_py)
        with open(os.path.join(head_dir, "app", "services", "auth.py"), "w", encoding="utf-8") as f:
            f.write(head_auth_py)

        # ---------------------------------------------------------------------
        # 2. Route path change & HTTP method change: app/api/items.py
        # ---------------------------------------------------------------------
        base_items_py = """
from fastapi import APIRouter
router = APIRouter()

@router.get("/items/{item_id}")
def get_item(item_id: int):
    return {"id": item_id}

@router.post("/items/create")
def create_item(data: dict):
    return data
"""
        head_items_py = """
from fastapi import APIRouter
router = APIRouter()

@router.get("/api/v2/items/{item_id}")
def get_item(item_id: int):
    return {"id": item_id}

@router.put("/items/create")
def create_item(data: dict):
    return data
"""
        os.makedirs(os.path.join(base_dir, "app", "api"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, "app", "api"), exist_ok=True)
        with open(os.path.join(base_dir, "app", "api", "items.py"), "w", encoding="utf-8") as f:
            f.write(base_items_py)
        with open(os.path.join(head_dir, "app", "api", "items.py"), "w", encoding="utf-8") as f:
            f.write(head_items_py)

        # ---------------------------------------------------------------------
        # 3. Pydantic field changes: app/schemas/user.py
        # ---------------------------------------------------------------------
        base_user_schema = """
from pydantic import BaseModel

class UserProfile(BaseModel):
    id: int
    username: str
    age: int
"""
        head_user_schema = """
from pydantic import BaseModel

class UserProfile(BaseModel):
    id: int
    username: str
    email: str
    age: float
"""
        os.makedirs(os.path.join(base_dir, "app", "schemas"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, "app", "schemas"), exist_ok=True)
        with open(os.path.join(base_dir, "app", "schemas", "user.py"), "w", encoding="utf-8") as f:
            f.write(base_user_schema)
        with open(os.path.join(head_dir, "app", "schemas", "user.py"), "w", encoding="utf-8") as f:
            f.write(head_user_schema)

        # ---------------------------------------------------------------------
        # 4. Frontend API client mismatch / change: frontend/src/client.ts
        # ---------------------------------------------------------------------
        base_client_ts = """
export async function loadItems() {
    const res = await fetch('/items/123');
    return res.json();
}
"""
        head_client_ts = """
export async function loadItems() {
    const res = await fetch('/api/v2/items/123');
    return res.json();
}
"""
        os.makedirs(os.path.join(base_dir, "frontend", "src"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, "frontend", "src"), exist_ok=True)
        with open(os.path.join(base_dir, "frontend", "src", "client.ts"), "w", encoding="utf-8") as f:
            f.write(base_client_ts)
        with open(os.path.join(head_dir, "frontend", "src", "client.ts"), "w", encoding="utf-8") as f:
            f.write(head_client_ts)

        # ---------------------------------------------------------------------
        # 5. Dependency manifest changes: package.json & requirements.txt
        # ---------------------------------------------------------------------
        base_pkg_json = '{"dependencies": {"react": "18.2.0", "axios": "1.4.0"}}'
        head_pkg_json = '{"dependencies": {"react": "19.0.0", "lucide-react": "0.300.0"}}'
        with open(os.path.join(base_dir, "package.json"), "w", encoding="utf-8") as f:
            f.write(base_pkg_json)
        with open(os.path.join(head_dir, "package.json"), "w", encoding="utf-8") as f:
            f.write(head_pkg_json)

        base_reqs = "fastapi==0.109.0\nuvicorn==0.27.0\n"
        head_reqs = "fastapi==0.115.0\npydantic>=2.7.0\n"
        with open(os.path.join(base_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write(base_reqs)
        with open(os.path.join(head_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write(head_reqs)

        # ---------------------------------------------------------------------
        # 6. Environment & config changes: .env.example
        # ---------------------------------------------------------------------
        base_env = "DATABASE_URL=sqlite:///./dev.db\nPORT=8000\nDEPRECATED_VAR=true\n"
        head_env = "DATABASE_URL=postgresql://user:pass@localhost:5432/app\nPORT=8000\nNEW_FEATURE_FLAG=enabled\n"
        with open(os.path.join(base_dir, ".env.example"), "w", encoding="utf-8") as f:
            f.write(base_env)
        with open(os.path.join(head_dir, ".env.example"), "w", encoding="utf-8") as f:
            f.write(head_env)

        # ---------------------------------------------------------------------
        # 7. File addition, deletion, and rename
        # ---------------------------------------------------------------------
        # New file in head
        with open(os.path.join(head_dir, "app", "services", "billing.py"), "w", encoding="utf-8") as f:
            f.write("def process_payment():\n    pass\n")

        # Deleted file in head (existed in base)
        with open(os.path.join(base_dir, "app", "services", "legacy_cleanup.py"), "w", encoding="utf-8") as f:
            f.write("def do_cleanup():\n    pass\n")

        # Renamed file: utils/old_math.py -> utils/math_ops.py
        os.makedirs(os.path.join(base_dir, "utils"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, "utils"), exist_ok=True)
        math_content = "def add(a: int, b: int) -> int:\n    return a + b\n"
        with open(os.path.join(base_dir, "utils", "old_math.py"), "w", encoding="utf-8") as f:
            f.write(math_content)
        with open(os.path.join(head_dir, "utils", "math_ops.py"), "w", encoding="utf-8") as f:
            f.write(math_content)

        # ---------------------------------------------------------------------
        # 8. Binary file: assets/icon.png
        # ---------------------------------------------------------------------
        os.makedirs(os.path.join(base_dir, "assets"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, "assets"), exist_ok=True)
        with open(os.path.join(base_dir, "assets", "icon.png"), "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"base_data")
        with open(os.path.join(head_dir, "assets", "icon.png"), "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"head_data_modified")

        yield base_dir, head_dir


def test_deterministic_structural_diff_complete(base_and_head_workspaces):
    """Verify that ChangeDiffEngine deterministically extracts all exact structural facts."""
    base_dir, head_dir = base_and_head_workspaces
    engine = ChangeDiffEngine()

    result: StructuralDiffResult = engine.compute_structural_diff(
        base_workspace=base_dir,
        head_workspace=head_dir,
        base_commit_sha="1111111111111111111111111111111111111111",
        head_commit_sha="2222222222222222222222222222222222222222",
        repository_url="https://github.com/fastapi/fastapi",
    )

    assert result.base_commit_sha == "1111111111111111111111111111111111111111"
    assert result.head_commit_sha == "2222222222222222222222222222222222222222"

    # 1. File Changes
    assert "app/services/billing.py" in result.added_files
    assert "app/services/legacy_cleanup.py" in result.deleted_files
    assert ["utils/old_math.py", "utils/math_ops.py"] in result.renamed_files
    assert "app/services/auth.py" in result.modified_files
    assert "app/api/items.py" in result.modified_files
    assert "app/schemas/user.py" in result.modified_files

    # Binary File Fact
    bin_facts = [f for f in result.changed_files if f.file_path == "assets/icon.png"]
    assert len(bin_facts) == 1
    assert bin_facts[0].is_binary is True
    assert bin_facts[0].skipped_reason == "BINARY"

    # Line Range Facts for Modified Text File
    auth_fact = next(f for f in result.changed_files if f.file_path == "app/services/auth.py")
    assert auth_fact.is_binary is False
    assert auth_fact.language == "python"
    assert len(auth_fact.changed_line_ranges) > 0

    # 2. Function Signature Change
    sig_changes = [
        s for s in result.modified_symbols
        if s.file_path == "app/services/auth.py" and s.symbol_name == "verify_token"
    ]
    assert len(sig_changes) == 1
    assert sig_changes[0].change_type == SymbolChangeType.SIGNATURE_CHANGED
    assert "issuer" in sig_changes[0].evidence.get("head_parameters", "")
    assert "issuer" not in sig_changes[0].evidence.get("base_parameters", "")

    # 3. Function Deletion
    del_symbols = [
        s for s in result.deleted_symbols
        if s.symbol_name == "deprecated_helper"
    ]
    assert len(del_symbols) == 1
    assert del_symbols[0].change_type == SymbolChangeType.DELETED

    # 4. Route Changes: Path and HTTP Method
    route_deltas = result.route_deltas
    assert any(
        r.change_type == "PATH_CHANGED" and "/api/v2/items/{item_id}" in (r.head_path or "")
        for r in route_deltas
    )
    assert any(
        r.change_type == "METHOD_CHANGED" and r.head_http_method == "PUT" and r.base_http_method == "POST"
        for r in route_deltas
    )

    # 5. Frontend API Client Change
    assert any(
        r.route_type == "FETCH_CALL" and "/api/v2/items/123" in (r.head_path or "")
        for r in route_deltas
    )

    # 6. Pydantic Model Schema Deltas
    schema_deltas = result.schema_deltas
    assert any(
        s.model_name == "UserProfile" and s.field_name == "email" and s.change_type == "ADDED_FIELD"
        for s in schema_deltas
    )
    assert any(
        s.model_name == "UserProfile" and s.field_name == "age" and s.change_type == "MODIFIED_TYPE"
        for s in schema_deltas
    )

    # 7. Package Dependency Deltas
    dep_deltas = result.dependency_deltas
    # package.json
    assert any(d.package_name == "react" and d.change_type == "UPDATED" and d.head_version == "19.0.0" for d in dep_deltas)
    assert any(d.package_name == "axios" and d.change_type == "REMOVED" for d in dep_deltas)
    assert any(d.package_name == "lucide-react" and d.change_type == "ADDED" for d in dep_deltas)
    # requirements.txt
    assert any(d.package_name == "fastapi" and d.change_type == "UPDATED" for d in dep_deltas)
    assert any(d.package_name == "pydantic" and d.change_type == "ADDED" for d in dep_deltas)
    assert any(d.package_name == "uvicorn" and d.change_type == "REMOVED" for d in dep_deltas)

    # 8. Environment & Config Deltas
    config_deltas = result.config_deltas
    assert any(c.key == "DATABASE_URL" and c.change_type == "MODIFIED" for c in config_deltas)
    assert any(c.key == "NEW_FEATURE_FLAG" and c.change_type == "ADDED" for c in config_deltas)
    assert any(c.key == "DEPRECATED_VAR" and c.change_type == "REMOVED" for c in config_deltas)

    # Summary verification
    assert result.summary["total_files_changed"] >= 8
    assert result.summary["added_files_count"] == 1
    assert result.summary["deleted_files_count"] == 1
    assert result.summary["renamed_files_count"] == 1
    assert result.summary["total_dependencies_changed"] >= 6
    assert result.summary["total_configs_changed"] >= 3
    assert result.summary["total_schemas_changed"] >= 2


def test_unsupported_language_and_binary_file_facts():
    """Verify that unsupported languages and binary files are truthfully marked without inventing facts."""
    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        # Base workspace
        with open(os.path.join(base_dir, "custom.xyz"), "w") as f:
            f.write("custom syntax")
        with open(os.path.join(base_dir, "blob.bin"), "wb") as f:
            f.write(b"\x00\x01\x02\x03\x04")

        # Head workspace: modified custom.xyz and blob.bin
        with open(os.path.join(head_dir, "custom.xyz"), "w") as f:
            f.write("custom syntax updated")
        with open(os.path.join(head_dir, "blob.bin"), "wb") as f:
            f.write(b"\x00\x01\x02\x03\x05")

        engine = ChangeDiffEngine()
        result = engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        xyz_fact = next(f for f in result.changed_files if f.file_path == "custom.xyz")
        assert xyz_fact.is_parsed is False
        assert xyz_fact.skipped_reason == "UNSUPPORTED_LANGUAGE"

        bin_fact = next(f for f in result.changed_files if f.file_path == "blob.bin")
        assert bin_fact.is_binary is True
        assert bin_fact.skipped_reason == "BINARY"


def test_vendor_and_ignored_directories_safety():
    """Verify that vendor and ignored directories (.git, node_modules, .venv) are ignored."""
    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        # Create ignored directories
        os.makedirs(os.path.join(base_dir, "node_modules", "package_a"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, "node_modules", "package_b"), exist_ok=True)
        os.makedirs(os.path.join(base_dir, ".venv", "lib"), exist_ok=True)
        os.makedirs(os.path.join(head_dir, ".venv", "lib"), exist_ok=True)

        with open(os.path.join(base_dir, "node_modules", "package_a", "index.js"), "w") as f:
            f.write("module.exports = {}")
        with open(os.path.join(head_dir, "node_modules", "package_b", "index.js"), "w") as f:
            f.write("module.exports = {}")

        with open(os.path.join(base_dir, "src.py"), "w") as f:
            f.write("x = 1")
        with open(os.path.join(head_dir, "src.py"), "w") as f:
            f.write("x = 2")

        engine = ChangeDiffEngine()
        result = engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        assert not any("node_modules" in f.file_path for f in result.changed_files)
        assert not any(".venv" in f.file_path for f in result.changed_files)
        assert len(result.changed_files) == 1
        assert result.changed_files[0].file_path == "src.py"


def test_pyproject_toml_dependency_deltas():
    """Verify that pyproject.toml dependencies are parsed and compared."""
    base_pyproject = """
[project]
name = "my-app"
version = "0.1.0"

[project.dependencies]
fastapi = ">=0.100.0"
sqlalchemy = "==2.0.0"
"""
    head_pyproject = """
[project]
name = "my-app"
version = "0.1.0"

[project.dependencies]
fastapi = ">=0.110.0"
pydantic = ">=2.0.0"
"""
    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        with open(os.path.join(base_dir, "pyproject.toml"), "w") as f:
            f.write(base_pyproject)
        with open(os.path.join(head_dir, "pyproject.toml"), "w") as f:
            f.write(head_pyproject)

        engine = ChangeDiffEngine()
        result = engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        deltas = result.dependency_deltas
        assert any(d.package_name == "fastapi" and d.change_type == "UPDATED" for d in deltas)
        assert any(d.package_name == "pydantic" and d.change_type == "ADDED" for d in deltas)
        assert any(d.package_name == "sqlalchemy" and d.change_type == "REMOVED" for d in deltas)


def test_identical_workspaces_produce_empty_diff():
    """Verify that identical workspaces produce zero file and symbol changes."""
    with tempfile.TemporaryDirectory() as base_dir, tempfile.TemporaryDirectory() as head_dir:
        with open(os.path.join(base_dir, "main.py"), "w") as f:
            f.write("def main():\n    pass\n")
        with open(os.path.join(head_dir, "main.py"), "w") as f:
            f.write("def main():\n    pass\n")

        engine = ChangeDiffEngine()
        result = engine.compute_structural_diff(
            base_workspace=base_dir,
            head_workspace=head_dir,
            base_commit_sha="1111111111111111111111111111111111111111",
            head_commit_sha="2222222222222222222222222222222222222222",
            repository_url="https://github.com/test/repo",
        )

        assert len(result.changed_files) == 0
        assert len(result.changed_symbols) == 0
        assert len(result.added_files) == 0
        assert len(result.deleted_files) == 0
        assert len(result.modified_files) == 0


def test_singleton_accessor():
    """Verify get_diff_engine returns singleton instance."""
    e1 = get_diff_engine()
    e2 = get_diff_engine()
    assert e1 is e2
    assert isinstance(e1, ChangeDiffEngine)

