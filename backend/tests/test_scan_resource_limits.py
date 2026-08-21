"""Unit tests for global scan resource boundaries and source budget truncation."""

import os
import tempfile
import pytest

from app.core.config import get_settings
from app.ingestion.manifest import build_manifest


def test_manifest_respects_max_total_source_bytes_budget():
    """Verify build_manifest sets is_truncated and bounds total source size when exceeding budget."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a few large files
        large_content = "x" * 2000
        for i in range(10):
            with open(os.path.join(tmpdir, f"file_{i}.py"), "w", encoding="utf-8") as f:
                f.write(large_content)

        # Build manifest with custom low limit (e.g. 5000 bytes)
        from app.core.config import Settings
        custom_settings = Settings(MAX_TOTAL_SOURCE_BYTES=5000)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("app.ingestion.manifest.get_settings", lambda: custom_settings)
            manifest = build_manifest(tmpdir, "https://github.com/org/repo.git", "abcdef1234567890abcdef1234567890abcdef12")

        assert manifest.analysis_scope is not None
        assert manifest.analysis_scope.is_truncated
        assert manifest.analysis_scope.truncated_file_count > 0
        assert manifest.analysis_scope.total_source_bytes <= 5000 + 2000
