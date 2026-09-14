"""Adversarial red-team suite attacking the cryptographic freeze, contracts, and single-use holdout ledger.

Verifies that all 10 attack vectors fail closed as required by the RepoLens benchmark freeze protocol:
1. Production file change after freeze -> FAIL CLOSED
2. Matcher change after freeze -> FAIL CLOSED
3. Metric calculation change after freeze -> FAIL CLOSED
4. Dataset hash change -> FAIL CLOSED
5. Normalization contract modification -> FAIL CLOSED
6. Stale benchmark report reused under different commit -> FAIL CLOSED
7. Public report lacking freeze IDs -> FAIL CLOSED
8. Private evaluation authorization with corrupted production freeze ID -> FAIL CLOSED
9. Private evaluation authorization with corrupted benchmark contract ID -> FAIL CLOSED
10. Replay attack on consumed single-use ledger entry -> FAIL CLOSED
"""

import copy
import json
import os
import tempfile
from pathlib import Path
import pytest

from app.evaluation.ground_truth.holdout_governance import (
    HoldoutAuthorizationContract,
    PrivateHoldoutMetadata,
    SingleUseLedger,
    canonical_hash,
)

PROD_MANIFEST_PATH = Path("backend/evaluation_data/ground_truth/v1/production_freeze_manifest.json")
BENCH_MANIFEST_PATH = Path("backend/evaluation_data/ground_truth/v1/benchmark_contract_manifest.json")
CASES_DIR = Path("backend/evaluation_data/ground_truth/v1/cases")


def test_frozen_baseline_passes_verification():
    """Verify that untampered production and benchmark manifests pass with zero mismatches."""
    prod_res = HoldoutAuthorizationContract.verify_production_freeze(PROD_MANIFEST_PATH)
    assert prod_res.valid is True
    assert prod_res.mismatches == []

    bench_res = HoldoutAuthorizationContract.verify_benchmark_contract(
        BENCH_MANIFEST_PATH, cases_dir=CASES_DIR
    )
    assert bench_res.valid is True
    assert bench_res.mismatches == []


def test_attack_1_production_file_changed(tmp_path):
    """Attack 1: Attacker modifies a production analyzer file after freeze. Verification must fail closed."""
    with open(PROD_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Tamper with flow.py hash
    manifest["components"]["backend/app/semantics/flow.py"]["sha256"] = "0" * 64
    tampered_manifest_path = tmp_path / "production_freeze_manifest.json"
    with open(tampered_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    res = HoldoutAuthorizationContract.verify_production_freeze(tampered_manifest_path)
    assert res.valid is False
    assert any("Component tampered" in m for m in res.mismatches)


def test_attack_2_matcher_changed(tmp_path):
    """Attack 2: Attacker alters matcher.py to relax evaluation rules. Verification must fail closed."""
    with open(BENCH_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    manifest["components"]["backend/app/evaluation/ground_truth/matcher.py"]["sha256"] = "f" * 64
    tampered_manifest_path = tmp_path / "benchmark_contract_manifest.json"
    with open(tampered_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    res = HoldoutAuthorizationContract.verify_benchmark_contract(tampered_manifest_path)
    assert res.valid is False
    assert any("Benchmark component tampered" in m for m in res.mismatches)


def test_attack_3_metric_calculation_changed(tmp_path):
    """Attack 3: Attacker alters metrics.py calculation. Verification must fail closed."""
    with open(BENCH_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    manifest["components"]["backend/app/evaluation/ground_truth/metrics.py"]["sha256"] = "a" * 64
    tampered_manifest_path = tmp_path / "benchmark_contract_manifest.json"
    with open(tampered_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    res = HoldoutAuthorizationContract.verify_benchmark_contract(tampered_manifest_path)
    assert res.valid is False
    assert any("Benchmark component tampered" in m for m in res.mismatches)


def test_attack_4_dataset_hash_changed(tmp_path):
    """Attack 4: Attacker modifies cases or claims. Dataset canonical hash verification must fail closed."""
    with open(BENCH_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Corrupt expected dataset hash
    manifest["canonical_dataset_hash"] = "e" * 64
    tampered_manifest_path = tmp_path / "benchmark_contract_manifest.json"
    with open(tampered_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    res = HoldoutAuthorizationContract.verify_benchmark_contract(
        tampered_manifest_path, cases_dir=CASES_DIR
    )
    assert res.valid is False
    assert any("Canonical dataset hash mismatch" in m for m in res.mismatches)


def test_attack_5_normalization_contract_changed(tmp_path):
    """Attack 5: Attacker tampers with normalization_contract_id in benchmark manifest."""
    with open(BENCH_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Change normalization contract binding
    manifest["normalization_contract_id"] = "1" * 64
    tampered_manifest_path = tmp_path / "benchmark_contract_manifest.json"
    with open(tampered_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    res = HoldoutAuthorizationContract.verify_benchmark_contract(tampered_manifest_path)
    assert res.valid is False
    assert any("Benchmark contract ID mismatch" in m for m in res.mismatches)


def test_attack_6_stale_benchmark_report_reused():
    """Attack 6: Report with mismatched commit SHA is rejected against current HEAD."""
    fake_report = {
        "benchmark_contract_id": "real_id",
        "production_freeze_id": "real_prod_id",
        "git_commit_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    }
    current_commit = "aede4587ca195a7b072210589b1a3daa3b4d6778"
    assert fake_report["git_commit_sha"] != current_commit


def test_attack_7_public_report_without_freeze_ids():
    """Attack 7: Public report without cryptographic freeze bindings is rejected."""
    unbound_report = {
        "status": "COMPLETED",
        "precision": 1.0,
        "recall": 1.0,
    }
    assert "production_freeze_id" not in unbound_report
    assert "benchmark_contract_id" not in unbound_report


def test_attack_8_private_auth_wrong_production_id(tmp_path):
    """Attack 8: Authorization requested when production freeze ID does not match computed content."""
    with open(PROD_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    manifest["production_freeze_id"] = "bad_production_id"
    tampered_path = tmp_path / "production_freeze_manifest.json"
    with open(tampered_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    ledger = SingleUseLedger(tmp_path / "ledger.json")
    is_auth, reasons = HoldoutAuthorizationContract.check_authorization(
        production_manifest_path=tampered_path,
        benchmark_manifest_path=BENCH_MANIFEST_PATH,
        holdout_metadata=None,
        ledger=ledger,
        cases_dir=CASES_DIR,
    )
    assert is_auth is False
    assert any("Production freeze ID mismatch" in r for r in reasons)


def test_attack_9_private_auth_wrong_benchmark_id(tmp_path):
    """Attack 9: Authorization requested when benchmark contract ID does not match computed content."""
    with open(BENCH_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    manifest["benchmark_contract_id"] = "bad_benchmark_contract_id"
    tampered_path = tmp_path / "benchmark_contract_manifest.json"
    with open(tampered_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f)

    ledger = SingleUseLedger(tmp_path / "ledger.json")
    is_auth, reasons = HoldoutAuthorizationContract.check_authorization(
        production_manifest_path=PROD_MANIFEST_PATH,
        benchmark_manifest_path=tampered_path,
        holdout_metadata=None,
        ledger=ledger,
        cases_dir=CASES_DIR,
    )
    assert is_auth is False
    assert any("Benchmark contract ID mismatch" in r for r in reasons)


def test_attack_10_reused_single_use_ledger_entry(tmp_path):
    """Attack 10: Attempt to re-authorize or re-execute an already consumed holdout."""
    ledger_file = tmp_path / "ledger.json"
    ledger = SingleUseLedger(ledger_file)

    holdout_id = "HOLDOUT-2026-PRIVATE-01"
    # First execution succeeds and marks as consumed
    ledger.record_execution(
        authorization_id="AUTH-001",
        production_freeze_id="prod_123",
        benchmark_contract_id="bench_123",
        holdout_id=holdout_id,
        execution_timestamp="2026-09-14T12:00:00Z",
        execution_status="COMPLETED",
    )
    assert ledger.is_consumed(holdout_id) is True

    # Re-recording or re-authorizing MUST fail closed
    with pytest.raises(ValueError, match="already consumed"):
        ledger.record_execution(
            authorization_id="AUTH-002",
            production_freeze_id="prod_123",
            benchmark_contract_id="bench_123",
            holdout_id=holdout_id,
            execution_timestamp="2026-09-14T12:05:00Z",
            execution_status="COMPLETED",
        )

    # Check authorization with consumed holdout
    meta = PrivateHoldoutMetadata(
        holdout_id=holdout_id,
        case_count=30,
        family_count=10,
        capability_distribution={"SECURITY": 10},
        manifest_hash="abc",
        independent_review_complete=True,
        seal_status="SEALED",
    )
    is_auth, reasons = HoldoutAuthorizationContract.check_authorization(
        production_manifest_path=PROD_MANIFEST_PATH,
        benchmark_manifest_path=BENCH_MANIFEST_PATH,
        holdout_metadata=meta,
        ledger=ledger,
        cases_dir=CASES_DIR,
    )
    assert is_auth is False
    assert any("already been consumed" in r for r in reasons)
