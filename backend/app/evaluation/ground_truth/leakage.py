"""Architectural evaluation leakage prevention and neutral sandbox isolation."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from typing import Dict, List, Optional

from app.evaluation.ground_truth.schemas import AnalysisInput, BenchmarkCase, RepositoryFixture

FORBIDDEN_LEAKAGE_MARKERS = (
    "BENCHMARK_EXPECTED",
    "GROUND_TRUTH",
    "EXPECTED_FINDING",
    "EXPECT_FINDING",
    "EXPECTED_VERDICT",
    "CASE_ID",
    "MUTATION_",
    "CORRECT_ABSTENTION",
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "RULE_SCOPED",
    "ALL_SUPPORTED",
    "FROZEN_PUBLIC_EVAL",
    "VULNERABILITY_FINDING",
)


class EvaluationLeakageError(ValueError, RuntimeError):
    """Raised immediately when benchmark label leakage is detected in analyzed content."""
    pass


class LeakageDetector:
    """Enforces strict architectural separation between ground truth and analyzed content."""

    @classmethod
    def check_text(cls, text: str, source_context: str = "") -> None:
        """Scan text for forbidden label markers and raise loudly on match."""
        upper_text = text.upper()
        for marker in FORBIDDEN_LEAKAGE_MARKERS:
            if marker in upper_text:
                raise EvaluationLeakageError(
                    f"Forbidden benchmark marker detected in {source_context}: '{marker}'"
                )

    @classmethod
    def check_fixture(cls, fixture: RepositoryFixture, case_id: str = "") -> None:
        """Ensure no repository fixture content contains benchmark labels, case IDs, or markers."""
        all_file_dicts: List[Dict[str, str]] = []
        if fixture.files:
            all_file_dicts.append(fixture.files)
        if fixture.base_files:
            all_file_dicts.append(fixture.base_files)
        if fixture.head_files:
            all_file_dicts.append(fixture.head_files)

        case_id_pattern = re.escape(case_id.upper()) if case_id else None

        for file_dict in all_file_dicts:
            for path, content in file_dict.items():
                cls.check_text(path, source_context=f"file path '{path}'")
                cls.check_text(content, source_context=f"file content of '{path}'")
                if case_id_pattern and re.search(rf"\b{case_id_pattern}\b", content.upper()):
                    raise EvaluationLeakageError(
                        f"Case ID '{case_id}' leaked into fixture file content: '{path}'"
                    )

    @classmethod
    def check_case(cls, case: BenchmarkCase) -> None:
        """Run full pre-flight leakage audit on a benchmark case."""
        cls.check_fixture(case.fixture, case_id=case.case_id)

    @classmethod
    def bifurcate_input(cls, case: BenchmarkCase) -> AnalysisInput:
        """Architecturally strip all annotations, producing pure untrusted AnalysisInput."""
        cls.check_case(case)
        return AnalysisInput(
            case_id=case.case_id,
            target_pipeline=case.target_pipeline,
            fixture=case.fixture,
        )


def create_neutral_sandbox(files: Dict[str, str]) -> str:
    """Create a temporary directory with a neutral name and populate it with repository files.

    Guarantees:
    - Neutral prefix (repolens_eval_) without case ID or finding labels.
    - Files written with relative path safety within the sandbox.
    """
    temp_dir = tempfile.mkdtemp(prefix="repolens_eval_")
    try:
        for rel_path, content in files.items():
            # Normalize path and prevent directory traversal
            clean_rel = rel_path.replace("\\", "/").lstrip("/")
            if ".." in clean_rel:
                raise ValueError(f"Invalid relative path containing traversal: {rel_path}")
            abs_dest = os.path.join(temp_dir, os.path.normpath(clean_rel))
            os.makedirs(os.path.dirname(abs_dest), exist_ok=True)
            with open(abs_dest, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
        return temp_dir
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def cleanup_sandbox(temp_dir: str) -> None:
    """Safely remove the temporary sandbox directory."""
    if temp_dir and os.path.isdir(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
