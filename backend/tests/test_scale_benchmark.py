"""Small proofs for the manual extreme-scale benchmark harness."""

import json

from app.benchmarks.scale import ai_work_envelope, assert_inventory_independent_ai_work, run_scale_benchmark


def test_ai_work_envelope_depends_on_unique_candidates_not_inventory_size():
    candidates = ["candidate:a", "candidate:b", "candidate:a"]
    proof = assert_inventory_independent_ai_work(100_000, 1_000_000, candidates)
    assert proof["envelope"] == ai_work_envelope(candidates)
    assert proof["envelope"]["unresolved_candidates"] == 2


def test_small_passive_scale_run_emits_truthful_machine_metrics():
    report = run_scale_benchmark(file_count=24, symbols_per_file=2, vendor_ratio=0.25,
                                 fanout=4, scc_size=3, workspace_depth=2)
    assert report["requested_files"] == 24
    assert report["inventory"]["vendor_files"] == 6
    assert report["discovery"]["complete"]
    assert report["discovery"]["materialized_change_records"] == 1
    assert report["cold_index"]["parsed_files"] > 0
    assert report["unchanged_warm_index"]["parsed_files"] == 0
    assert report["warm_index"] == report["unchanged_warm_index"]
    assert report["tiny_change_index"]["parsed_files"] == 1
    assert report["tiny_change_index"]["reused_files"] > 0
    assert report["recovery"] == {
        "status": "EXECUTED", "interrupted_complete": False,
        "interrupted_stop_reason": "inventory_file_budget", "resume_complete": True,
        "resume_reused_files": report["tiny_change_index"]["reused_files"],
        "false_complete": False,
    }
    assert report["stress_graph"]["verified"]
    assert report["stress_graph"]["observed_fanout_edges"] == 4
    assert report["stress_graph"]["observed_cycle_edges"] == 3
    assert report["retrieval_ms"]["samples"] == 21
    assert report["model_admission"]["status"] == "EVALUATED"
    assert report["model_execution"] == {"status": "NOT_EXECUTED", "calls": None, "tokens": None}
    assert report["verifier_execution"] == {"status": "NOT_EXECUTED", "attempts": None}
    json.dumps(report)
