"""Repository-pinned identities for the public ground-truth benchmark.

These values are trust anchors for the public benchmark contract. They are
intentionally not loaded from the manifest being verified: a manifest cannot
authorize itself by recomputing its own checksum. Changes require reviewed
updates to this module and the corresponding frozen manifest.
"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
BACKEND_ROOT = REPO_ROOT / "backend"
BENCHMARK_MANIFEST_PATH = (
    BACKEND_ROOT / "evaluation_data" / "ground_truth" / "v1" / "benchmark_contract_manifest.json"
)
BENCHMARK_CASES_DIR = (
    BACKEND_ROOT / "evaluation_data" / "ground_truth" / "v1" / "cases"
)
PRODUCTION_FREEZE_MANIFEST_PATH = (
    BACKEND_ROOT / "evaluation_data" / "ground_truth" / "v1" / "production_freeze_manifest.json"
)
# Root-of-trust values. Update only alongside a reviewed benchmark freeze.
TRUSTED_PRODUCTION_FREEZE_ID = "e54409eb0ea30e70cde4ff9abe3143c8a775e04c2b0c330db6819e6a57d1a516"
TRUSTED_BENCHMARK_CONTRACT_ID = "ce789690aae268a55c3c9b3bbe6d34cc2b8d56927af0745b353186fd6bccc85b"
TRUSTED_BENCHMARK_DATASET_SHA256 = "1611efec9c34421b19d862427241fde5061170d7268602103fd5585e66b317bf"
TRUSTED_BENCHMARK_CATALOG_SHA256 = "835c22b4f9355738413b0c390c29e6f78b4b082c6a76151161388256b3d1b1ab"
TRUSTED_BENCHMARK_VERSION = "1.3.0"
TRUSTED_BENCHMARK_DATASET_VERSION = "1.0.0"
TRUSTED_BENCHMARK_MATCHER_VERSION = "1.0.1"
TRUSTED_BENCHMARK_METRICS_VERSION = "1.0.1"
TRUSTED_BENCHMARK_CASE_COUNT = 90
TRUSTED_BENCHMARK_BOOTSTRAP_ITERATIONS = 1000
TRUSTED_BENCHMARK_BOOTSTRAP_SEED = 42

# Digests cover sorted [case_id, family, split, category, difficulty,
# evaluation_stage, expected_verdict, evaluation_scope] tuples. Official report
# validation requires the complete corresponding inventory, not a caller-chosen
# subset. These pins let report validation avoid loading benchmark fixtures.
TRUSTED_OFFICIAL_CASE_INVENTORIES = {
    "OFFICIAL_FULL_DIAGNOSTIC": (
        90,
        "e8dbf1fd8f0545e489cfc9a4fc00f0ee59d300f10d67b4111bf674a8a1b83ffe",
    ),
    "OFFICIAL_DEV": (
        68,
        "481bbb30c3679d9321faf7321fc0bf76808f48d9b9d1c012b763c44b1f8affb7",
    ),
    "OFFICIAL_PUBLIC_EVAL": (
        22,
        "53450d976d847d6ff3924bac91327bfe002dc59fb1821211a2c540fe099a0953",
    ),
}

PRODUCTION_FREEZE_COMPONENTS = frozenset(
    {
        "backend/app/semantics/flow.py",
        "backend/app/semantics/builder.py",
        "backend/app/semantics/schemas.py",
        "backend/app/analysis/diff_engine.py",
        "backend/app/analysis/impact_engine.py",
        "backend/app/analysis/core.py",
        "backend/app/specialist_candidates.py",
        "backend/app/graph/builder.py",
        "backend/app/graph/repository_graph.py",
        "backend/app/graph/schemas.py",
        "backend/app/ingestion/manifest.py",
        "backend/app/indexing/chunker.py",
    }
)
BENCHMARK_CONTRACT_COMPONENTS = frozenset(
    {
        "backend/app/evaluation/ground_truth/catalog.py",
        "backend/app/evaluation/ground_truth/loader.py",
        "backend/app/evaluation/ground_truth/runner.py",
        "backend/app/evaluation/ground_truth/matcher.py",
        "backend/app/evaluation/ground_truth/metrics.py",
        "backend/app/evaluation/ground_truth/schemas.py",
        "backend/app/evaluation/ground_truth/report.py",
        "backend/app/evaluation/ground_truth/leakage.py",
        "backend/app/evaluation/ground_truth/holdout_governance.py",
        "backend/evaluation_data/ground_truth/v1/catalog.json",
    }
)
