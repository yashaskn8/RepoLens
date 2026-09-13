"""CLI entry point for executing RepoLens ground-truth evaluation benchmark."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.evaluation.ground_truth.runner import BenchmarkRunner
from app.evaluation.ground_truth.report import save_json_report, save_markdown_report
from app.evaluation.ground_truth.schemas import BenchmarkSplit, ExecutionStatus


def main() -> int:
    parser = argparse.ArgumentParser(description="RepoLens Ground-Truth Evaluation Benchmark Runner")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="output/benchmark",
        help="Directory to save benchmark_report.json and BENCHMARK_REPORT.md",
    )
    parser.add_argument(
        "--split",
        type=str,
        choices=["DEV", "FROZEN_PUBLIC_EVAL", "ALL"],
        default="ALL",
        help="Evaluation split to execute (default: ALL)",
    )
    parser.add_argument(
        "--cases-dir",
        type=str,
        default=None,
        help="Custom path to benchmark cases directory",
    )

    args = parser.parse_args()
    split = None if args.split == "ALL" else BenchmarkSplit(args.split)

    print(f"=== RepoLens Ground-Truth Benchmark Runner ===")
    print(f"Split: {args.split}")
    print(f"Output directory: {args.output_dir}")

    runner = BenchmarkRunner()
    try:
        report = runner.run_benchmark(split=split, cases_dir=args.cases_dir)
    except Exception as exc:
        print(f"FATAL: Benchmark run failed: {exc}", file=sys.stderr)
        return 1

    out_dir = Path(args.output_dir)
    json_path = out_dir / "benchmark_report.json"
    md_path = out_dir / "BENCHMARK_REPORT.md"

    save_json_report(report, json_path)
    save_markdown_report(report, md_path)

    print(f"\nExecution Status: {report.execution_status.value}")
    print(f"Executed: {report.executed_cases}/{report.eligible_cases} cases in {report.duration_seconds}s")
    print(f"Canonical Dataset Hash: {report.canonical_dataset_hash}")
    print(f"Raw Confusion: {report.aggregate_metrics.raw_confusion}")
    print(f"Overall Precision: {report.aggregate_metrics.precision}")
    print(f"Overall Recall:    {report.aggregate_metrics.recall}")
    print(f"Overall F1:        {report.aggregate_metrics.f1}")
    print(f"Clean Specificity: {report.aggregate_metrics.clean_cases.clean_case_specificity}")
    print(f"Abstention Rate:   {report.aggregate_metrics.abstentions.correct_abstention_rate}")
    print(f"\nArtifacts saved to:\n  - {json_path}\n  - {md_path}")

    if report.execution_status != ExecutionStatus.COMPLETED:
        print(f"ERROR: Benchmark execution status is {report.execution_status.value}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
