"""Machine-readable JSON serialization and scientific Markdown failure analysis reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from app.evaluation.ground_truth.runner import BenchmarkRunReport


def format_markdown_report(report: BenchmarkRunReport) -> str:
    """Generate an objective, scientific Markdown report from a benchmark run artifact."""
    agg = report.aggregate_metrics
    clean = agg.clean_cases
    abst = agg.abstentions

    md: list[str] = [
        "# RepoLens Ground-Truth Evaluation Benchmark Report",
        "",
        f"- **Benchmark Version**: `{report.benchmark_version}`",
        f"- **Dataset Version**: `{report.dataset_version}`",
        f"- **Canonical Dataset Hash**: `{report.canonical_dataset_hash}`",
        f"- **Git Commit SHA**: `{report.git_commit_sha}`",
        f"- **Mode**: `{report.mode}`",
        f"- **Live Model Execution**: `{report.live_model_provider}`",
        f"- **Execution Status**: `{report.execution_status.value}` (Completion: {report.completion_fraction * 100:.1f}%)",
        f"- **Cases Executed**: {report.executed_cases} of {report.eligible_cases} eligible ({report.total_cases} total in dataset)",
        f"- **Platform**: `{report.platform}` | Python `{report.python_version}`",
        f"- **Timestamp**: `{report.timestamp}` (Duration: `{report.duration_seconds}s`)",
        "",
        "---",
        "",
        "## 1. Executive Metric Summary",
        "",
        "### Raw Confusion Matrix (Finding-Level)",
        "```json",
        json.dumps(agg.raw_confusion, indent=2),
        "```",
        "",
        "### Headline Metrics",
        f"- **Precision**: `{agg.precision if agg.precision is not None else 'N/A'}`",
        f"- **Recall**: `{agg.recall if agg.recall is not None else 'N/A'}`",
        f"- **F1 Score**: `{agg.f1 if agg.f1 is not None else 'N/A'}`",
        f"- **File Localization Accuracy**: `{agg.file_localization_accuracy if agg.file_localization_accuracy is not None else 'N/A'}`",
        f"- **Symbol Localization Accuracy**: `{agg.symbol_localization_accuracy if agg.symbol_localization_accuracy is not None else 'N/A'}`",
        f"- **Unsupported Published Finding Rate**: `{agg.unsupported_published_rate if agg.unsupported_published_rate is not None else 'N/A'}` ({agg.unsupported_finding_count} total unsupported findings)",
        "",
        "---",
        "",
        "## 2. Layer-Separated Performance",
        "",
        "| Evaluation Layer | Native Stage | Status | Precision | Recall | F1 | Duplicate FP | Invalid Refs |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for stage_name, layer in agg.layer_metrics.items():
        if layer.status == "NOT_EXECUTED":
            md.append(f"| **{stage_name}** | `{layer.stage.value}` | `NOT_EXECUTED` | `N/A` | `N/A` | `N/A` | - | - |")
        else:
            p_str = f"{layer.precision * 100:.1f}%" if layer.precision is not None else "N/A"
            r_str = f"{layer.recall * 100:.1f}%" if layer.recall is not None else "N/A"
            f1_str = f"{layer.f1:.4f}" if layer.f1 is not None else "N/A"
            md.append(
                f"| **{stage_name}** | `{layer.stage.value}` | `{layer.status}` | `{p_str}` | `{r_str}` | `{f1_str}` | {layer.duplicate_fp} | {layer.invalid_reference_count} |"
            )

    md.extend([
        "",
        "---",
        "",
        "## 3. Case-Level Clean Evaluation (True Negatives)",
        "",
        f"- **Total Clean Cases Evaluated**: {clean.clean_cases_total}",
        f"- **Clean Cases without False Positives (Case-Level TN)**: {clean.clean_cases_without_fp}",
        f"- **Clean Cases with False Positives (Case-Level FP)**: {clean.clean_cases_with_any_fp}",
        f"- **Clean Case False Positive Rate**: `{clean.clean_case_false_positive_rate if clean.clean_case_false_positive_rate is not None else 'N/A'}`",
        f"- **Clean Case Specificity**: `{clean.clean_case_specificity if clean.clean_case_specificity is not None else 'N/A'}`",
    ])
    if clean.specificity_wilson_ci:
        md.append(f"- **Specificity 95% Wilson CI**: `[{clean.specificity_wilson_ci[0]}, {clean.specificity_wilson_ci[1]}]`")

    md.extend([
        "",
        "---",
        "",
        "## 4. Abstention Behavior on UNKNOWN Cases",
        "",
        f"- **Total UNKNOWN Cases Evaluated**: {abst.unknown_cases_total}",
        f"- **Explicit Correct Abstentions**: {abst.explicit_correct_abstentions}",
        f"- **No Positive Publications (Silent)**: {abst.no_positive_publications}",
        f"- **Incorrect Confident Positives**: {abst.incorrect_confident_positives}",
        f"- **Incorrect Confident Negatives**: {abst.incorrect_confident_negatives}",
        f"- **Pipeline Not Evaluable (Errors)**: {abst.pipeline_not_evaluable}",
        f"- **Correct Abstention Rate**: `{abst.correct_abstention_rate if abst.correct_abstention_rate is not None else 'N/A'}`",
    ])
    if abst.abstention_rate_wilson_ci:
        md.append(f"- **Abstention Rate 95% Wilson CI**: `[{abst.abstention_rate_wilson_ci[0]}, {abst.abstention_rate_wilson_ci[1]}]`")

    md.extend([
        "",
        "---",
        "",
        "## 5. Statistical Uncertainty (Family Cluster Bootstrap)",
        "",
        "Resampled $B = 1,000$ whole case families with replacement. Replicates with mathematically undefined denominators are excluded from percentile distributions.",
        "",
        "| Metric | Point Estimate | 95% Bootstrap CI | Valid Replicates |",
        "|---|---|---|---|",
    ])

    for metric_key, ci in agg.confidence_intervals.items():
        pe = f"{ci.point_estimate:.4f}" if ci.point_estimate is not None else "N/A"
        ci_str = f"[{ci.lower:.4f}, {ci.upper:.4f}]" if ci.lower is not None and ci.upper is not None else "N/A"
        md.append(f"| **{metric_key}** | `{pe}` | `{ci_str}` | {ci.valid_replicates}/{ci.total_replicates} |")

    md.extend([
        "",
        "---",
        "",
        "## 6. Granular Failure Analysis",
        "",
        "| Case ID | Family | Split | Stage | Expected | Emitted | FP | FN | Mismatch Classification / Rationale |",
        "|---|---|---|---|---|---|---|---|---|",
    ])

    failed_or_mismatched = [r for r in report.per_case_results if r.fp > 0 or r.fn > 0 or r.mismatch_reasons]
    if not failed_or_mismatched:
        md.append("| *(None)* | - | - | - | - | - | 0 | 0 | All executed benchmark assertions passed perfectly. |")
    else:
        for r in failed_or_mismatched:
            reasons = "; ".join(r.mismatch_reasons) if r.mismatch_reasons else "Clean"
            emitted_str = f"{len(r.emitted_findings)} items"
            md.append(
                f"| `{r.case_id}` | `{r.case_family}` | `{r.split}` | `{r.evaluation_stage.value}` | `{r.expected_verdict.value}` | {emitted_str} | {r.fp} | {r.fn} | {reasons} |"
            )

    md.extend([
        "",
        "---",
        "",
        "## 7. Known Scientific Limitations",
        "",
        "1. **Public Holdout Boundary**: The `FROZEN_PUBLIC_EVAL` split prevents accidental case-family overlap and post-hoc dataset modification, but because its annotations are publicly available in this repository, it should not be interpreted as a permanently blind test set.",
        "2. **Layer Boundary**: The deterministic benchmark evaluates static findings, semantic flow candidates, structural diff facts, and blast radius impacts. End-to-end multi-agent published review findings require the live-model harness.",
        "3. **Bounded Static Semantics**: RepoLens's interprocedural taint analysis enforces conservative bounded call depths (depth 2, max 64 flow nodes) and does not perform dynamic runtime execution.",
        "",
        "---",
        "",
        "## 8. Reproduction Command",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe -m app.cli.run_benchmark",
        "```",
    ])

    return "\n".join(md)


def save_json_report(report: BenchmarkRunReport, output_path: Path | str) -> None:
    """Save machine-readable JSON artifact with compact formatting."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report.model_dump(), f, indent=2, ensure_ascii=False)


def save_markdown_report(report: BenchmarkRunReport, output_path: Path | str) -> None:
    """Generate and write Markdown summary report."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    content = format_markdown_report(report)
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
