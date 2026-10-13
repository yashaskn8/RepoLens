"""Cryptographic freeze validation, private holdout governance, and single-use evaluation ledger."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from pydantic import BaseModel, Field

from app.evaluation.ground_truth.loader import compute_canonical_benchmark_hash, load_benchmark_dataset
from app.evaluation.ground_truth.authority import (
    BENCHMARK_CASES_DIR,
    BENCHMARK_CONTRACT_COMPONENTS,
    PRODUCTION_FREEZE_COMPONENTS,
    REPO_ROOT,
    TRUSTED_BENCHMARK_CATALOG_SHA256,
    TRUSTED_BENCHMARK_CONTRACT_ID,
    TRUSTED_BENCHMARK_DATASET_SHA256,
    TRUSTED_PRODUCTION_FREEZE_ID,
)


_LEDGER_LOCK_TIMEOUT_SECONDS = 10.0
_LEDGER_LOCK_POLL_SECONDS = 0.025


def _safe_resolve(path: str | Path) -> Path | None:
    """Resolve an untrusted path without allowing symlink loops to escape fail-closed handling."""
    try:
        return Path(path).resolve()
    except (OSError, RuntimeError):
        return None


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
    """Verify pinned public freezes and fail closed for unconfigured private execution."""

    @staticmethod
    def verify_production_freeze(
        manifest_path: str | Path,
        root_dir: Optional[str | Path] = None,
    ) -> FreezeValidationResult:
        """Verify that every production component matches its registered SHA-256.

        Args:
            manifest_path: Path to the production freeze manifest JSON.
            root_dir: Optional root assertion. It must resolve to RepoLens's canonical root.
        """
        p = Path(manifest_path)
        if not p.is_file():
            return FreezeValidationResult(
                valid=False,
                manifest_type="PRODUCTION_ANALYZER",
                manifest_id="UNKNOWN",
                expected_id="UNKNOWN",
                mismatches=[f"Production freeze manifest not found: {p}"],
            )
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return FreezeValidationResult(
                valid=False,
                manifest_type="PRODUCTION_ANALYZER",
                manifest_id="UNKNOWN",
                expected_id=TRUSTED_PRODUCTION_FREEZE_ID,
                mismatches=[f"Production freeze manifest is unreadable: {type(exc).__name__}"],
            )
        if not isinstance(data, dict):
            return FreezeValidationResult(
                valid=False,
                manifest_type="PRODUCTION_ANALYZER",
                manifest_id="UNKNOWN",
                expected_id=TRUSTED_PRODUCTION_FREEZE_ID,
                mismatches=["Production freeze manifest must be a JSON object."],
            )

        recorded_id = data.get("production_freeze_id")
        expected_id = recorded_id if isinstance(recorded_id, str) else ""
        # Compute canonical hash of manifest content excluding the ID itself
        data_to_hash = {k: v for k, v in data.items() if k != "production_freeze_id"}
        actual_id = canonical_hash(data_to_hash)

        mismatches = []
        if actual_id != expected_id:
            mismatches.append(
                f"Production freeze ID mismatch: recorded={expected_id}, computed={actual_id}"
            )
        if expected_id != TRUSTED_PRODUCTION_FREEZE_ID:
            mismatches.append("Production freeze does not match the repository-pinned trust anchor.")

        components = data.get("components")
        if not isinstance(components, dict) or set(components) != PRODUCTION_FREEZE_COMPONENTS:
            mismatches.append("Production freeze component inventory differs from the pinned inventory.")

        canonical_root = REPO_ROOT.resolve()
        supplied_root = _safe_resolve(root_dir) if root_dir is not None else canonical_root
        if supplied_root != canonical_root:
            mismatches.append("Production freeze verification is restricted to the canonical repository root.")

        for comp_path in sorted(PRODUCTION_FREEZE_COMPONENTS if isinstance(components, dict) else ()):
            comp_info = components.get(comp_path)
            expected_hash = comp_info.get("sha256") if isinstance(comp_info, dict) else None
            if supplied_root != canonical_root:
                continue
            resolved_path = _safe_resolve(canonical_root / comp_path)
            if resolved_path is None:
                mismatches.append(f"Production component path is not safely resolvable: {comp_path}")
                continue
            if not resolved_path.is_relative_to(canonical_root):
                mismatches.append(f"Production component escapes the canonical repository: {comp_path}")
                continue
            try:
                if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                    raise ValueError("component digest is malformed")
                actual_hash = compute_file_sha256(resolved_path)
                if actual_hash != expected_hash:
                    mismatches.append(
                        f"Component tampered: {comp_path} (recorded={expected_hash[:12]}..., actual={actual_hash[:12]}...)"
                    )
            except Exception as e:
                mismatches.append(f"Failed to verify production component {comp_path}: {type(e).__name__}")

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
        root_dir: Optional[str | Path] = None,
    ) -> FreezeValidationResult:
        """Verify that benchmark runner, matcher, metrics, and dataset match frozen signatures.

        Args:
            manifest_path: Path to the benchmark contract manifest JSON.
            cases_dir: Directory containing benchmark case files.
            root_dir: Optional root assertion. It must resolve to RepoLens's canonical root.
        """
        p = Path(manifest_path)
        if not p.is_file():
            return FreezeValidationResult(
                valid=False,
                manifest_type="BENCHMARK_CONTRACT",
                manifest_id="UNKNOWN",
                expected_id="UNKNOWN",
                mismatches=[f"Benchmark contract manifest not found: {p}"],
            )
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return FreezeValidationResult(
                valid=False,
                manifest_type="BENCHMARK_CONTRACT",
                manifest_id="UNKNOWN",
                expected_id=TRUSTED_BENCHMARK_CONTRACT_ID,
                mismatches=[f"Benchmark contract manifest is unreadable: {type(exc).__name__}"],
            )
        if not isinstance(data, dict):
            return FreezeValidationResult(
                valid=False,
                manifest_type="BENCHMARK_CONTRACT",
                manifest_id="UNKNOWN",
                expected_id=TRUSTED_BENCHMARK_CONTRACT_ID,
                mismatches=["Benchmark contract manifest must be a JSON object."],
            )

        recorded_id = data.get("benchmark_contract_id")
        expected_id = recorded_id if isinstance(recorded_id, str) else ""
        data_to_hash = {k: v for k, v in data.items() if k != "benchmark_contract_id"}
        actual_id = canonical_hash(data_to_hash)

        mismatches = []
        if actual_id != expected_id:
            mismatches.append(
                f"Benchmark contract ID mismatch: recorded={expected_id}, computed={actual_id}"
            )
        if expected_id != TRUSTED_BENCHMARK_CONTRACT_ID:
            mismatches.append("Benchmark contract does not match the repository-pinned trust anchor.")

        components = data.get("components")
        if not isinstance(components, dict) or set(components) != BENCHMARK_CONTRACT_COMPONENTS:
            mismatches.append("Benchmark component inventory differs from the pinned inventory.")

        canonical_root = REPO_ROOT.resolve()
        supplied_root = _safe_resolve(root_dir) if root_dir is not None else canonical_root
        if supplied_root != canonical_root:
            mismatches.append("Benchmark verification is restricted to the canonical repository root.")

        canonical_cases = BENCHMARK_CASES_DIR.resolve()
        supplied_cases = _safe_resolve(cases_dir) if cases_dir is not None else canonical_cases
        if supplied_cases != canonical_cases:
            mismatches.append("Benchmark dataset verification is restricted to the canonical public corpus.")

        if supplied_root == canonical_root and supplied_cases == canonical_cases:
            try:
                cases = load_benchmark_dataset(cases_dir=str(canonical_cases))
                actual_ds_hash = compute_canonical_benchmark_hash(cases)
                if actual_ds_hash != TRUSTED_BENCHMARK_DATASET_SHA256:
                    mismatches.append("Canonical public dataset differs from the repository-pinned trust anchor.")
                if actual_ds_hash != data.get("canonical_dataset_hash"):
                    mismatches.append(
                        "Canonical dataset hash mismatch: manifest does not match the loaded public corpus."
                    )
            except Exception as e:
                mismatches.append(f"Failed to verify canonical public dataset: {type(e).__name__}")
        if data.get("canonical_dataset_hash") != TRUSTED_BENCHMARK_DATASET_SHA256:
            mismatches.append("Benchmark manifest dataset hash differs from the repository-pinned trust anchor.")
        if data.get("catalog_hash") != TRUSTED_BENCHMARK_CATALOG_SHA256:
            mismatches.append("Benchmark manifest catalog hash differs from the repository-pinned trust anchor.")

        # Verify benchmark component files
        for comp_path in sorted(BENCHMARK_CONTRACT_COMPONENTS if isinstance(components, dict) else ()):
            comp_info = components.get(comp_path)
            expected_hash = comp_info.get("sha256") if isinstance(comp_info, dict) else None
            if supplied_root != canonical_root:
                continue
            resolved_path = _safe_resolve(canonical_root / comp_path)
            if resolved_path is None:
                mismatches.append(f"Benchmark component path is not safely resolvable: {comp_path}")
                continue
            if not resolved_path.is_relative_to(canonical_root):
                mismatches.append(f"Benchmark component escapes the canonical repository: {comp_path}")
                continue
            try:
                if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                    raise ValueError("component digest is malformed")
                actual_hash = compute_file_sha256(resolved_path)
                if actual_hash != expected_hash:
                    mismatches.append(
                        f"Benchmark component tampered: {comp_path} (recorded={expected_hash[:12]}..., actual={actual_hash[:12]}...)"
                    )
            except Exception as e:
                mismatches.append(f"Failed to verify benchmark component {comp_path}: {type(e).__name__}")

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
        root_dir: Optional[str | Path] = None,
    ) -> Tuple[bool, List[str]]:
        """Deny private holdout execution until a trusted execution authority exists.

        Returns:
            (is_authorized: bool, failure_reasons: List[str])
        """
        # No private fixture artifact, authenticated operator authority,
        # independently trusted holdout manifest, or transactional deployment
        # claim service is configured. In particular, do not open caller paths
        # or claim a local ledger on the strength of caller-constructed metadata.
        return False, [
            "PRIVATE_FINAL_HOLDOUT execution is NOT_CONFIGURED: trusted holdout artifacts, authenticated operator authorization, and an authoritative claim service are unavailable."
        ]


class SingleUseLedger:
    """Single-host, cross-process ledger preventing repeated holdout use.

    Claims are serialized with an OS file lock and committed by atomic replace.
    This is suitable only when all claimants share a local filesystem with
    working advisory/byte-range locks; it is not a distributed multi-host
    authorization service. The application currently has no official holdout
    execution path wired to this utility.
    """

    def __init__(self, ledger_file: str | Path) -> None:
        self.ledger_file = Path(ledger_file)
        self.entries: List[SingleUseLedgerEntry] = []
        self._load()

    def _load(self) -> None:
        with self._exclusive_lock():
            self._load_unlocked()

    def _load_unlocked(self) -> None:
        if self.ledger_file.is_file():
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.entries = [SingleUseLedgerEntry.model_validate(e) for e in data.get("entries", [])]

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        """Serialize local process claims; fail closed if a bounded lock wait expires."""
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.ledger_file.with_name(self.ledger_file.name + ".lock")
        with open(lock_path, "a+b") as lock_file:
            if os.name == "nt":
                import msvcrt

                lock_file.seek(0, os.SEEK_END)
                if lock_file.tell() == 0:
                    lock_file.write(b"\0")
                    lock_file.flush()
                deadline = time.monotonic() + _LEDGER_LOCK_TIMEOUT_SECONDS
                while True:
                    try:
                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("single-use ledger lock timed out") from exc
                        time.sleep(_LEDGER_LOCK_POLL_SECONDS)
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                deadline = time.monotonic() + _LEDGER_LOCK_TIMEOUT_SECONDS
                while True:
                    try:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError as exc:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("single-use ledger lock timed out") from exc
                        time.sleep(_LEDGER_LOCK_POLL_SECONDS)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _save_unlocked(self) -> None:
        payload = {
            "schema_version": "1.0.0",
            "ledger_type": "SINGLE_USE_EVALUATION_LEDGER",
            "entries": [entry.model_dump() for entry in self.entries],
        }
        temp_path: Path | None = None
        try:
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{self.ledger_file.name}.",
                suffix=".tmp",
                dir=self.ledger_file.parent,
            )
            temp_path = Path(temp_name)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.ledger_file)
            if os.name != "nt":
                directory_fd = os.open(self.ledger_file.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def is_consumed(self, holdout_id: str) -> bool:
        """Return True if holdout_id has already been executed and consumed."""
        with self._exclusive_lock():
            self._load_unlocked()
            return any(e.holdout_id == holdout_id and e.consumed for e in self.entries)

    def claim_execution(
        self,
        authorization_id: str,
        production_freeze_id: str,
        benchmark_contract_id: str,
        holdout_id: str,
        execution_timestamp: str,
        execution_status: str = "CLAIMED",
    ) -> None:
        """Atomically consume a holdout before its one authorized execution."""
        with self._exclusive_lock():
            self._load_unlocked()
            if any(e.holdout_id == holdout_id and e.consumed for e in self.entries):
                raise ValueError(f"Holdout {holdout_id} is already consumed; re-execution forbidden.")
            self.entries.append(SingleUseLedgerEntry(
                authorization_id=authorization_id,
                production_freeze_id=production_freeze_id,
                benchmark_contract_id=benchmark_contract_id,
                holdout_id=holdout_id,
                execution_timestamp=execution_timestamp,
                execution_status=execution_status,
                consumed=True,
            ))
            self._save_unlocked()

    def record_execution(
        self,
        authorization_id: str,
        production_freeze_id: str,
        benchmark_contract_id: str,
        holdout_id: str,
        execution_timestamp: str,
        execution_status: str,
    ) -> None:
        """Backward-compatible alias; new callers should claim before execution."""
        self.claim_execution(
            authorization_id=authorization_id,
            production_freeze_id=production_freeze_id,
            benchmark_contract_id=benchmark_contract_id,
            holdout_id=holdout_id,
            execution_timestamp=execution_timestamp,
            execution_status=execution_status,
        )
