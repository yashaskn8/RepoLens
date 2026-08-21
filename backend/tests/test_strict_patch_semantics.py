"""Unit tests for strict deleted-file and new-file patch semantics."""

import os
import tempfile
import pytest

from app.patching.applier import PatchApplyError, apply_unified_diff_to_directory


def test_delete_file_valid_deletion():
    """Verify deleting a file succeeds when context and deleted lines match existing content."""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = os.path.join(tmpdir, "deprecated.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("def old_function():\n    pass\n")

        diff = (
            "--- a/deprecated.py\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-def old_function():\n"
            "-    pass\n"
        )

        result = apply_unified_diff_to_directory(diff, tmpdir)
        assert "deprecated.py" in result
        assert not os.path.exists(file_path)


def test_delete_file_mismatched_content_rejected():
    """Verify deleting a file fails if hunk content does not match existing content on disk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        file_path = os.path.join(tmpdir, "deprecated.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("def actual_function():\n    return 42\n")

        diff = (
            "--- a/deprecated.py\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-def old_function():\n"
            "-    pass\n"
        )

        with pytest.raises(PatchApplyError) as exc_info:
            apply_unified_diff_to_directory(diff, tmpdir)
        assert "mismatch" in str(exc_info.value).lower()
        # File must remain untouched
        assert os.path.exists(file_path)


def test_new_file_creation_succeeds_when_not_existing():
    """Verify creating a new file from /dev/null succeeds when file does not exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        diff = (
            "--- /dev/null\n"
            "+++ b/new_module.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+def hello():\n"
            "+    return 'world'\n"
        )

        result = apply_unified_diff_to_directory(diff, tmpdir)
        assert "new_module.py" in result
        
        target_path = os.path.join(tmpdir, "new_module.py")
        assert os.path.exists(target_path)
        with open(target_path, "r", encoding="utf-8") as f:
            assert f.read() == "def hello():\n    return 'world'\n"


def test_new_file_creation_rejected_if_already_exists():
    """Verify creating a new file from /dev/null fails if the target file already exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        existing_path = os.path.join(tmpdir, "existing.py")
        with open(existing_path, "w", encoding="utf-8") as f:
            f.write("# existing content\n")

        diff = (
            "--- /dev/null\n"
            "+++ b/existing.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+def hello():\n"
            "+    return 'world'\n"
        )

        with pytest.raises(PatchApplyError) as exc_info:
            apply_unified_diff_to_directory(diff, tmpdir)
        assert "already exists" in str(exc_info.value)
        
        # Verify existing file was not overwritten
        with open(existing_path, "r", encoding="utf-8") as f:
            assert f.read() == "# existing content\n"
