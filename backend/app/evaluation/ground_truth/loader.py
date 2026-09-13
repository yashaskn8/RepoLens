"""Dataset loading, validation, canonical serialization, and split management."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.evaluation.ground_truth.catalog import CapabilityCatalog, load_capability_catalog
from app.evaluation.ground_truth.leakage import LeakageDetector
from app.evaluation.ground_truth.schemas import (
    BenchmarkCase,
    BenchmarkSplit,
)

_DEFAULT_CASES_DIR = (
    Path(__file__).resolve().parents[3]
    / "evaluation_data"
    / "ground_truth"
    / "v1"
    / "cases"
)


def canonicalize_for_hashing(obj: Any) -> Any:
    """Recursively canonicalize an object for RepoLens Canonical Benchmark Serialization v1.

    Guarantees:
    - Excludes runtime host paths, timestamps, or volatile IDs.
    - Normalized dictionary key sorting.
    - Normalized list sorting where order is semantically invariant (e.g. tags).
    - Preserves exact lossless integers, strings, booleans, and nulls.
    """
    if isinstance(obj, dict):
        return {k: canonicalize_for_hashing(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [canonicalize_for_hashing(item) for item in obj]
    elif isinstance(obj, (int, bool, str)) or obj is None:
        return obj
    elif isinstance(obj, float):
        raise ValueError(f"Float value {obj} found in canonical dataset object; dataset must use lossless integers or decimal strings")
    else:
        # Pydantic or custom model
        if hasattr(obj, "model_dump"):
            return canonicalize_for_hashing(obj.model_dump())
        return str(obj)


def compute_canonical_benchmark_hash(cases: List[BenchmarkCase]) -> str:
    """Compute the SHA-256 hash according to RepoLens Canonical Benchmark Serialization v1.

    Rules:
    - Cases sorted lexicographically by case_id.
    - Canonical serialization: UTF-8, sorted keys, compact separators (',', ':'), LF newlines.
    - No machine-specific host paths or run timestamps.
    """
    sorted_cases = sorted(cases, key=lambda c: c.case_id)
    canonical_list = [canonicalize_for_hashing(case.model_dump()) for case in sorted_cases]
    serialized = json.dumps(
        canonical_list,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    # Ensure unix LF newlines in the bytes stream
    serialized_lf = serialized.replace("\r\n", "\n")
    return hashlib.sha256(serialized_lf.encode("utf-8")).hexdigest()


class BenchmarkDatasetLoader:
    """Loads, validates, and partitions the curated benchmark dataset."""

    def __init__(self, catalog: Optional[CapabilityCatalog] = None) -> None:
        self.catalog = catalog or load_capability_catalog()
        self.valid_rule_ids = set(self.catalog.get_rule_map().keys())

    def load_case_file(self, file_path: Path | str) -> BenchmarkCase:
        """Load and validate a single benchmark case JSON file."""
        p = Path(file_path)
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        case = BenchmarkCase.model_validate(data)

        # 1. Pre-flight leakage inspection
        LeakageDetector.check_case(case)

        # 2. Rule catalog validation
        for claim in case.annotation.claims:
            if claim.rule_id not in self.valid_rule_ids:
                raise ValueError(
                    f"Case '{case.case_id}' references unknown rule_id '{claim.rule_id}' not in catalog"
                )
        for target_id in case.annotation.target_rule_ids:
            if target_id not in self.valid_rule_ids:
                raise ValueError(
                    f"Case '{case.case_id}' target_rule_ids contains unknown '{target_id}'"
                )

        return case

    def load_all_cases(self, cases_dir: Optional[Path | str] = None) -> List[BenchmarkCase]:
        """Discover and load all benchmark cases from directory tree."""
        root_dir = Path(cases_dir) if cases_dir else _DEFAULT_CASES_DIR
        if not root_dir.exists():
            raise FileNotFoundError(f"Benchmark cases directory not found at: {root_dir}")

        case_files = sorted(root_dir.glob("**/*.json"))
        cases: List[BenchmarkCase] = []
        seen_ids: Dict[str, str] = {}
        family_splits: Dict[str, BenchmarkSplit] = {}

        for cf in case_files:
            case = self.load_case_file(cf)

            # Check duplicate case_id
            if case.case_id in seen_ids:
                raise ValueError(
                    f"Duplicate case_id '{case.case_id}' found in '{cf}' (previously in '{seen_ids[case.case_id]}')"
                )
            seen_ids[case.case_id] = str(cf)

            # Check strict family split consistency (zero sibling leakage between splits)
            if case.case_family in family_splits:
                if family_splits[case.case_family] != case.split:
                    raise ValueError(
                        f"Case family split conflict: family '{case.case_family}' has cases in both "
                        f"'{family_splits[case.case_family]}' and '{case.split}'! "
                        f"Families must be partitioned strictly into a single split."
                    )
            else:
                family_splits[case.case_family] = case.split

            cases.append(case)

        return cases


def load_benchmark_dataset(
    cases_dir: Optional[Path | str] = None,
    catalog: Optional[CapabilityCatalog] = None,
) -> List[BenchmarkCase]:
    """Convenience helper to load and validate all benchmark cases."""
    loader = BenchmarkDatasetLoader(catalog=catalog)
    return loader.load_all_cases(cases_dir=cases_dir)


def filter_by_split(cases: List[BenchmarkCase], split: BenchmarkSplit) -> List[BenchmarkCase]:
    """Return only cases belonging to the specified split."""
    return [c for c in cases if c.split == split]


def group_by_family(cases: List[BenchmarkCase]) -> Dict[str, List[BenchmarkCase]]:
    """Group benchmark cases by their family identifier."""
    families: Dict[str, List[BenchmarkCase]] = {}
    for c in cases:
        families.setdefault(c.case_family, []).append(c)
    return families
