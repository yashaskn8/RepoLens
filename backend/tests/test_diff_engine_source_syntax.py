"""Guard the structural-diff module against source-generation syntax regressions.

This test deliberately avoids importing the module so it can identify malformed
source even when the application itself cannot import.
"""

import ast
from pathlib import Path


def test_structural_diff_module_is_valid_python_source():
    module_path = Path(__file__).resolve().parents[1] / "app" / "analysis" / "diff_engine.py"
    ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
