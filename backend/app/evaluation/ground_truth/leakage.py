"""Architectural evaluation leakage prevention and neutral sandbox isolation."""

from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import tempfile
import unicodedata
import urllib.parse
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
        """Scan text for forbidden label markers and raise loudly on match.

        Applies bounded defense-in-depth:
        1. NFKC Unicode normalization (homoglyph defense)
        2. Direct plaintext inspection
        3. URL decoding inspection
        4. Bounded Base64 decode inspection
        5. Bounded Hexadecimal decode inspection
        """
        # 1. NFKC Unicode Normalization
        norm_text = unicodedata.normalize("NFKC", text)
        upper_text = norm_text.upper()

        for marker in FORBIDDEN_LEAKAGE_MARKERS:
            if marker in upper_text:
                raise EvaluationLeakageError(
                    f"Forbidden benchmark marker detected in {source_context}: '{marker}'"
                )

        # 2. URL decode inspection
        try:
            unquoted = urllib.parse.unquote(norm_text)
            upper_unquoted = unquoted.upper()
            if upper_unquoted != upper_text:
                for marker in FORBIDDEN_LEAKAGE_MARKERS:
                    if marker in upper_unquoted:
                        raise EvaluationLeakageError(
                            f"Forbidden benchmark marker (URL-encoded) detected in {source_context}: '{marker}'"
                        )
        except Exception:
            pass

        # 3. Bounded Base64 detection (chunks 8 to 512 chars)
        b64_candidates = re.findall(r"[A-Za-z0-9+/_-]{8,512}={0,2}", norm_text)
        for cand in b64_candidates[:50]:  # Bound scan count to prevent denial of service
            try:
                # Pad if needed
                pad_len = (4 - len(cand) % 4) % 4
                padded = cand + ("=" * pad_len)
                decoded_bytes = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore").upper()
                for marker in FORBIDDEN_LEAKAGE_MARKERS:
                    if marker in decoded_str:
                        raise EvaluationLeakageError(
                            f"Forbidden benchmark marker (Base64-encoded) detected in {source_context}: '{marker}'"
                        )
            except EvaluationLeakageError:
                raise
            except Exception:
                pass

        # 4. Bounded Hexadecimal detection (even hex strings 8 to 256 chars)
        hex_candidates = re.findall(r"\b[0-9a-fA-F]{8,256}\b", norm_text)
        for cand in hex_candidates[:50]:
            if len(cand) % 2 == 0:
                try:
                    decoded_bytes = binascii.unhexlify(cand)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore").upper()
                    for marker in FORBIDDEN_LEAKAGE_MARKERS:
                        if marker in decoded_str:
                            raise EvaluationLeakageError(
                                f"Forbidden benchmark marker (Hex-encoded) detected in {source_context}: '{marker}'"
                            )
                except EvaluationLeakageError:
                    raise
                except Exception:
                    pass

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
                        f"Forbidden benchmark marker: Case ID '{case_id}' leaked into fixture file content: '{path}'"
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
    - Neutral prefix (repo_workspace_) mimicking ordinary local developer checkouts.
    - Files written with relative path safety within the sandbox.
    """
    temp_dir = tempfile.mkdtemp(prefix="repo_workspace_")
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
