"""Deterministic evaluation metric calculation without hardcoded estimates."""

from typing import Any, Dict, List, Optional, Set

from app.evaluation.schemas import FindingEvaluationResult, GroundTruthIssue
from app.schemas.finding import Finding


def compute_recall_at_k(
    retrieved_chunk_ids: List[str],
    expected_chunk_ids: List[str],
    k: int = 5,
) -> float:
    """Compute Recall@K for a single query.
    
    Recall@K = |Retrieved@K ∩ Expected| / |Expected|
    """
    valid_expected = [cid for cid in expected_chunk_ids if cid]
    if not valid_expected or k <= 0:
        return 1.0

    top_k_retrieved = set(retrieved_chunk_ids[:k])
    hits = sum(1 for cid in valid_expected if cid in top_k_retrieved)
    return float(hits) / float(len(valid_expected))


def compute_mrr(
    retrieved_chunk_ids: List[str],
    expected_chunk_ids: List[str],
) -> float:
    """Compute Mean Reciprocal Rank (MRR) for a single query.
    
    MRR = 1 / first_rank_of_relevant_chunk (or 0.0 if not retrieved)
    """
    valid_expected = set(cid for cid in expected_chunk_ids if cid)
    if not valid_expected:
        return 1.0

    for rank_idx, chunk_id in enumerate(retrieved_chunk_ids, start=1):
        if chunk_id in valid_expected:
            return 1.0 / float(rank_idx)

    return 0.0


def compute_finding_metrics(
    verified_findings: List[Finding],
    candidate_findings: List[Finding],
    ground_truth_issues: List[GroundTruthIssue],
    rejected_findings: Optional[List[Dict[str, Any]]] = None,
    line_tolerance: int = 5,
    model_call_count: int = 0,
) -> FindingEvaluationResult:
    """Deterministically calculate precision, recall, FPR, and localization accuracy against ground truth."""
    rejected = rejected_findings or []
    total_gt = len(ground_truth_issues)

    if total_gt == 0:
        return FindingEvaluationResult(
            total_ground_truth=0,
            detected_candidates=len(candidate_findings),
            confirmed_findings=len(verified_findings),
            rejected_findings=len(rejected),
            precision=1.0,
            recall=1.0,
            false_positive_rate=0.0,
            evidence_localization_accuracy=1.0,
            verifier_rejection_rate=0.0,
            model_call_count=model_call_count,
        )

    matched_gt_ids: Set[str] = set()
    true_positives = 0
    false_positives = 0
    correctly_localized_count = 0

    for finding in verified_findings:
        evidence = finding.evidences[0] if finding.evidences else None
        f_path = evidence.file_path.replace("\\", "/").lstrip("/") if evidence and evidence.file_path else ""
        f_start = evidence.start_line if evidence else None

        finding_matched = False
        for gt in ground_truth_issues:
            gt_file = gt.expected_file.replace("\\", "/").lstrip("/")
            if f_path == gt_file:
                # Line range overlap with tolerance
                if f_start is not None:
                    if (gt.expected_start_line - line_tolerance) <= f_start <= (gt.expected_end_line + line_tolerance):
                        finding_matched = True
                        matched_gt_ids.add(gt.issue_id)
                        correctly_localized_count += 1
                        break
                else:
                    # File-level match
                    finding_matched = True
                    matched_gt_ids.add(gt.issue_id)
                    break

        if finding_matched:
            true_positives += 1
        else:
            false_positives += 1

    total_confirmed = len(verified_findings)
    precision = float(true_positives) / float(total_confirmed) if total_confirmed > 0 else 0.0
    recall = float(len(matched_gt_ids)) / float(total_gt)
    fpr = float(false_positives) / float(total_confirmed) if total_confirmed > 0 else 0.0
    loc_acc = float(correctly_localized_count) / float(true_positives) if true_positives > 0 else 0.0

    total_candidates = len(candidate_findings) if candidate_findings else (len(verified_findings) + len(rejected))
    rejection_rate = float(len(rejected)) / float(total_candidates) if total_candidates > 0 else 0.0

    return FindingEvaluationResult(
        total_ground_truth=total_gt,
        detected_candidates=total_candidates,
        confirmed_findings=len(verified_findings),
        rejected_findings=len(rejected),
        precision=precision,
        recall=recall,
        false_positive_rate=fpr,
        evidence_localization_accuracy=loc_acc,
        verifier_rejection_rate=rejection_rate,
        model_call_count=model_call_count,
    )
