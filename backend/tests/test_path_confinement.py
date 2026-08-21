"""Unit tests for strict path containment and workspace confinement."""

import os
import tempfile
import pytest
from pathlib import Path

from app.core.path_confinement import PathTraversalError, resolve_safe_path


def test_resolve_safe_path_valid_subpaths():
    """Verify legitimate subpaths inside workspace resolve cleanly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = tmpdir
        safe_rel = "app/services/core.py"
        resolved = resolve_safe_path(base_dir, safe_rel)
        assert str(resolved).startswith(str(Path(base_dir).resolve()))
        assert resolved.name == "core.py"

        # Nested valid path
        nested = "a/b/c/d/e.txt"
        resolved_nested = resolve_safe_path(base_dir, nested)
        assert str(resolved_nested).startswith(str(Path(base_dir).resolve()))


def test_resolve_safe_path_rejects_parent_traversal():
    """Verify ../ and ../../ directory traversal attempts are strictly rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = tmpdir
        
        traversal_attempts = [
            "../secret.txt",
            "../../etc/passwd",
            "app/../../secret.txt",
            "app/services/../../../escape.py",
            "..",
            "../",
        ]
        
        for attempt in traversal_attempts:
            with pytest.raises(PathTraversalError) as exc_info:
                resolve_safe_path(base_dir, attempt)
            assert "outside" in str(exc_info.value).lower() or "escapes" in str(exc_info.value).lower() or "not permitted" in str(exc_info.value).lower()


def test_resolve_safe_path_rejects_absolute_path_escape():
    """Verify absolute paths pointing outside base directory are strictly rejected."""
    with tempfile.TemporaryDirectory() as tmpdir1, tempfile.TemporaryDirectory() as tmpdir2:
        outside_file = os.path.join(tmpdir2, "unauthorized.txt")
        
        with pytest.raises(PathTraversalError):
            resolve_safe_path(tmpdir1, outside_file)


def test_resolve_safe_path_whitespace_and_slashes():
    """Verify leading/trailing slashes and whitespace are handled safely."""
    with tempfile.TemporaryDirectory() as tmpdir:
        resolved = resolve_safe_path(tmpdir, "  app/models/user.py  ")
        expected = Path(tmpdir).resolve() / "app" / "models" / "user.py"
        assert resolved == expected
