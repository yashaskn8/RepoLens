"""Cryptographic freeze validation, private holdout governance, and single-use evaluation ledger."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash, load_benchmark_dataset


def canonical_hash(obj: Dict[str, Any]) -> str:
    """Compute canonical deterministic SHA-256 hash over a JSON-serializable dictionary."""
    canonical_json = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_file_sha256(path: str | Path) -> str:
    """Compute standard SHA-256 hash of a file on disk."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Component file not found: {path}")
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class FreezeValidationResult(BaseModel):
    """Validation report for an active freeze manifest."""

    valid: bool
    manifest_type: str
    manifest_id: str
    expected_id: str
    mismatches: List[str] = Field(default_factory=list)


class SingleUseLedgerEntry(BaseModel):
    """Immutable audit entry in the single-use holdout authorization ledger."""

    authorization_id: str
    production_freeze_id: str
    benchmark_contract_id: str
    holdout_id: str
    execution_timestamp: str
    execution_status: str
    consumed: bool = False


class PrivateHoldoutMetadata(BaseModel):
    """Strictly metadata-only container for unseen private holdout.

    Invariant: Contains ZERO fixture source code, expected findings, or annotations.
    """

    holdout_id: str
    schema_version: str = "1.0.0"
    case_count: int
    family_count: int
    capability_distribution: Dict[str, int]
    manifest_hash: str
    independent_review_complete: bool
    rejected_count: int = 0
    seal_status: str = "SEALED"
    fixture_content_accessed: bool = False


class HoldoutAuthorizationContract:
    """Cryptographic authority governing whether execution against a private holdout is permitted."""

    @staticmethod
    def verify_production_freeze(manifest_path: str | Path) -> FreezeValidationResult:
        """Verify that every production component matches its registered SHA-256."""
        p = Path(manifest_path)
        if not p.is_file():
            return FreezeValidationResult(
                valid=False,
                manifest_type="PRODUCTION_ANALYZER",
                manifest_id="UNKNOWN",
                expected_id="UNKNOWN",
                mismatches=[f"Production freeze manifest not found: {p}"],
            )
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        expected_id = data.get("production_freeze_id", "")
        # Compute canonical hash of manifest content excluding the ID itself
        data_to_hash = {k: v for k, v in data.items() if k != "production_freeze_id"}
        actual_id = canonical_hash(data_to_hash)

        mismatches = []
        if actual_id != expected_id:
            mismatches.append(
                f"Production freeze ID mismatch: recorded={expected_id}, computed={actual_id}"
            )

        for comp_path, comp_info in data.get("components", {}).items():
            expected_hash = comp_info.get("sha256")
            try:
                actual_hash = compute_file_sha256(comp_path)
                if actual_hash != expected_hash:
                    mismatches.append(
                        f"Component tampered: {comp_path} (recorded={expected_hash[:12]}..., actual={actual_hash[:12]}...)"
                    )
            except Exception as e:
                mismatches.append(f"Failed to verify component {comp_path}: {e}")

        return FreezeValidationResult(
            valid=len(mismatches) == 0,
            manifest_type="PRODUCTION_ANALYZER",
            manifest_id=actual_id,
            expected_id=expected_id,
            mismatches=mismatches,
        )

    @staticmethod
    def verify_benchmark_contract(
        manifest_path: str | Path,
        cases_dir: Optional[str | Path] = None,
    ) -> FreezeValidationResult:
        """Verify that benchmark runner, matcher, metrics, and dataset match frozen signatures."""
        p = Path(manifest_path)
        if not p.is_file():
            return FreezeValidationResult(
                valid=False,
                manifest_type="BENCHMARK_CONTRACT",
                manifest_id="UNKNOWN",
                expected_id="UNKNOWN",
                mismatches=[f"Benchmark contract manifest not found: {p}"],
            )
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        expected_id = data.get("benchmark_contract_id", "")
        data_to_hash = {k: v for k, v in data.items() if k != "benchmark_contract_id"}
        actual_id = canonical_hash(data_to_hash)

        mismatches = []
        if actual_id != expected_id:
            mismatches.append(
                f"Benchmark contract ID mismatch: recorded={expected_id}, computed={actual_id}"
            )

        # Verify dataset hash if directory provided
        if cases_dir:
            try:
                cases = load_benchmark_dataset(cases_dir=str(cases_dir))
                actual_ds_hash = compute_canonical_benchmark_hash(cases)
                if actual_ds_hash != data.get("canonical_dataset_hash"):
                    mismatches.append(
                        f"Canonical dataset hash mismatch: recorded={data.get('canonical_dataset_hash')}, actual={actual_ds_hash}"
                    )
            except Exception as e:
                mismatches.append(f"Failed to verify dataset at {cases_dir}: {e}")

        # Verify benchmark component files
        for comp_path, comp_info in data.get("components", {}).items():
            expected_hash = comp_info.get("sha256")
            try:
                actual_hash = compute_file_sha256(comp_path)
                if actual_hash != expected_hash:
                    mismatches.append(
                        f"Benchmark component tampered: {comp_path} (recorded={expected_hash[:12]}..., actual={actual_hash[:12]}...)"
                    )
            except Exception as e:
                mismatches.append(f"Failed to verify benchmark component {comp_path}: {e}")

        return FreezeValidationResult(
            valid=len(mismatches) == 0,
            manifest_type="BENCHMARK_CONTRACT",
            manifest_id=actual_id,
            expected_id=expected_id,
            mismatches=mismatches,
        )

    @classmethod
    def check_authorization(
        cls,
        production_manifest_path: str | Path,
        benchmark_manifest_path: str | Path,
        holdout_metadata: Optional[PrivateHoldoutMetadata],
        ledger: SingleUseLedger,
        cases_dir: Optional[str | Path] = None,
    ) -> Tuple[bool, List[str]]:
        """Evaluate full authorization gate for executing unseen private holdout.

        Returns:
            (is_authorized: bool, failure_reasons: List[str])
        """
        reasons: List[str] = []

        # 1. Verify Production Freeze
        prod_val = cls.verify_production_freeze(production_manifest_path)
        if not prod_val.valid:
            reasons.extend(prod_val.mismatches)

        # 2. Verify Benchmark Contract Freeze
        bench_val = cls.verify_benchmark_contract(benchmark_manifest_path, cases_dir=cases_dir)
        if not bench_val.valid:
            reasons.extend(bench_val.mismatches)

        # 3. Check Holdout Existence and Integrity
        if holdout_metadata is None:
            reasons.append(
                "PRIVATE_FINAL_HOLDOUT does not exist. Independent curation is required before execution."
            )
            return False, reasons

        if not holdout_metadata.independent_review_complete:
            reasons.append("Private holdout independent review is not complete.")

        if holdout_metadata.seal_status != "SEALED":
            reasons.append(f"Private holdout is not SEALED (status: {holdout_metadata.seal_status}).")

        if holdout_metadata.fixture_content_accessed:
            reasons.append("Private holdout content was accessed by development agent prior to execution.")

        # 4. Check Single-Use Ledger
        if ledger.is_consumed(holdout_metadata.holdout_id):
            reasons.append(
                f"Private holdout {holdout_metadata.holdout_id} has already been consumed in the single-use ledger."
            )

        is_authorized = len(reasons) == 0
        return is_authorized, reasons


class SingleUseLedger:
    """Ledger preventing repeated evaluation or iterative tuning against sealed holdouts."""

    def __init__(self, ledger_file: str | Path) -> None:
        self.ledger_file = Path(ledger_file)
        self.entries: List[SingleUseLedgerEntry] = []
        self._load()

    def _load(self) -> None:
        if self.ledger_file.is_file():
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.entries = [SingleUseLedgerEntry.model_validate(e) for e in data.get("entries", [])]

    def _save(self) -> None:
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "schema_version": "1.0.0",
                    "ledger_type": "SINGLE_USE_EVALUATION_LEDGER",
                    "entries": [e.model_dump() for e in self.entries],
                },
                f,
                indent=2,
            )

    def is_consumed(self, holdout_id: str) -> bool:
        """Return True if holdout_id has already been executed and consumed."""
        return any(e.holdout_id == holdout_id and e.consumed for e in self.entries)

    def record_execution(
        self,
        authorization_id: str,
        production_freeze_id: str,
        benchmark_contract_id: str,
        holdout_id: str,
        execution_timestamp: str,
        execution_status: str,
    ) -> None:
        """Record an execution and seal the holdout against subsequent use."""
        if self.is_consumed(holdout_id):
            raise ValueError(f"Holdout {holdout_id} is already consumed; re-execution forbidden.")
        entry = SingleUseLedgerEntry(
            authorization_id=authorization_id,
            production_freeze_id=production_freeze_id,
            benchmark_contract_id=benchmark_contract_id,
            holdout_id=holdout_id,
            execution_timestamp=execution_timestamp,
            execution_status=execution_status,
            consumed=True,
        )
        self.entries.append(entry)
        self._save()
