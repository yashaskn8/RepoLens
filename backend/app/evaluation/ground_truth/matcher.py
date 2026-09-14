"""Independent ground-truth adjudication, 1-to-1 matching, and duplicate accounting."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.evaluation.ground_truth.catalog import CapabilityCatalog, load_capability_catalog
from app.evaluation.ground_truth.schemas import (
    AbstentionOutcome,
    BenchmarkCase,
    EvaluationAnnotation,
    EvaluationScope,
    EvaluationStage,
    ExpectedVerdict,
    FindingClaimSpec,
    RuleType,
)


def normalize_repo_path(path: str) -> str:
    """Normalize file paths to lowercase, forward-slash, without leading slashes."""
    if not path:
        return ""
    clean = path.replace("\\", "/").strip().lstrip("/")
    return clean.lower()


def normalize_symbol(symbol: Optional[str]) -> Optional[str]:
    """Normalize qualified symbol paths (e.g. 'app/services/auth.py:login:10') to bare symbol names."""
    if not symbol:
        return None
    sym = symbol.strip()
    if ":" in sym:
        parts = [p for p in sym.split(":") if p]
        if parts and parts[-1].isdigit():
            parts = parts[:-1]
        if parts:
            sym = parts[-1]
    if "." in sym and not ("/" in sym or "\\" in sym):
        sym = sym.split(".")[-1]
    return sym.strip()


class EvaluatedFinding(BaseModel):
    """Normalized internal representation of an emitted fact, candidate, or finding."""

    rule_id: str
    file_path: str
    symbol: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    stage: EvaluationStage
    structural_facts: Dict[str, Any] = Field(default_factory=dict)
    raw_title: Optional[str] = None
    raw_details: Optional[Dict[str, Any]] = None


class CaseEvaluationResult(BaseModel):
    """Auditable result of evaluating a single benchmark case."""

    case_id: str
    case_family: str
    split: str
    category: str
    difficulty: str
    evaluation_stage: EvaluationStage
    expected_verdict: ExpectedVerdict
    evaluation_scope: EvaluationScope

    # Finding-level confusion counts
    tp: int = 0
    fp: int = 0
    fn: int = 0
    duplicate_fp: int = 0
    invalid_reference_count: int = 0
    unsupported_claim_count: int = 0

    # Localization counts for TPs
    file_localized_tp: int = 0
    symbol_localized_tp: int = 0

    # Structured impact metrics
    impact_node_tp: int = 0
    impact_node_fp: int = 0
    impact_node_fn: int = 0
    impact_edge_tp: int = 0
    impact_edge_fp: int = 0
    impact_edge_fn: int = 0

    # Case-level outcomes
    is_clean_case: bool = False
    clean_case_tn: bool = False
    clean_case_fp: bool = False

    # Abstention outcome for UNKNOWN cases
    is_unknown_case: bool = False
    abstention_outcome: Optional[AbstentionOutcome] = None

    # Granular records for failure analysis
    matched_claim_ids: List[str] = Field(default_factory=list)
    unmatched_claim_ids: List[str] = Field(default_factory=list)
    emitted_findings: List[EvaluatedFinding] = Field(default_factory=list)
    false_positive_findings: List[EvaluatedFinding] = Field(default_factory=list)
    mismatch_reasons: List[str] = Field(default_factory=list)


class IndependentBenchmarkJudge:
    """Deterministic ground-truth judge evaluating RepoLens predictions against curated annotations.

    Invariants:
    - Never invokes RepoLens's internal verifier as the judge.
    - Evaluates 1-to-1 matching (at most 1 TP per ground-truth claim).
    - Extra unmatched predictions count as raw FPs.
    - Explicitly evaluates invalid_reference and unsupported_claim.
    """

    def __init__(
        self,
        catalog: Optional[CapabilityCatalog] = None,
        line_tolerance: int = 5,
    ) -> None:
        self.catalog = catalog or load_capability_catalog()
        self.rule_map = self.catalog.get_rule_map()
        self.line_tolerance = line_tolerance

    def _check_reference_validity(
        self,
        finding: EvaluatedFinding,
        manifest_files: Set[str],
        file_line_counts: Dict[str, int],
    ) -> bool:
        """Return True if referenced file exists and line range is within file bounds."""
        norm_file = normalize_repo_path(finding.file_path)
        if norm_file not in manifest_files:
            return False
        if finding.start_line is not None:
            max_lines = file_line_counts.get(norm_file, 100_000)
            if finding.start_line < 1 or finding.start_line > max_lines + 10:
                return False
        return True

    def _matches_claim(
        self,
        finding: EvaluatedFinding,
        claim: FindingClaimSpec,
    ) -> Tuple[bool, bool, bool, Optional[str]]:
        """Evaluate if finding matches claim.

        Returns:
            (matches, file_localized, symbol_localized, mismatch_reason)
        """
        # 1. Rule ID match
        if finding.rule_id != claim.rule_id:
            return False, False, False, f"rule_id mismatch: pred={finding.rule_id} != expected={claim.rule_id}"

        # 2. File localization match
        norm_pred_file = normalize_repo_path(finding.file_path)
        norm_permitted = [normalize_repo_path(f) for f in claim.permitted_files]
        file_matched = norm_pred_file in norm_permitted
        if not file_matched:
            return False, False, False, f"file mismatch: pred={norm_pred_file} not in {norm_permitted}"

        # 3. Symbol match if expected
        symbol_matched = False
        if claim.permitted_symbols:
            norm_claim_symbols = {normalize_symbol(s) for s in claim.permitted_symbols if s}
            norm_pred_symbol = normalize_symbol(finding.symbol)
            if norm_pred_symbol and norm_pred_symbol in norm_claim_symbols:
                symbol_matched = True
            elif not finding.symbol:
                # Prediction did not specify symbol, check if span matches
                pass
            else:
                return False, True, False, f"symbol mismatch: pred={finding.symbol} not in {claim.permitted_symbols}"
        else:
            symbol_matched = True

        # 4. Span / Line range match if spans provided
        span_matched = False
        if claim.permitted_spans:
            if finding.start_line is not None:
                for span in claim.permitted_spans:
                    span_start, span_end = span[0], span[1]
                    if (
                        (span_start - self.line_tolerance)
                        <= finding.start_line
                        <= (span_end + self.line_tolerance)
                    ):
                        span_matched = True
                        break
                if not span_matched:
                    return False, True, symbol_matched, f"span mismatch (out of tolerance): pred line {finding.start_line} not in {claim.permitted_spans}"
            else:
                # If finding has no start_line, require symbol match
                if not symbol_matched:
                    return False, True, False, "span mismatch: missing line numbers and symbol did not match permitted symbols"

        # 5. Structural facts check (Forbidden and Required)
        structural_errors = []
        for forb_key, forb_val in claim.forbidden_structural_facts.items():
            pred_val = finding.structural_facts.get(forb_key)
            if pred_val == forb_val:
                structural_errors.append(f"forbidden structural fact {forb_key}={forb_val} was present")

        for req_key, req_val in claim.required_structural_facts.items():
            pred_val = finding.structural_facts.get(req_key)
            if pred_val != req_val:
                structural_errors.append(f"required structural fact {req_key}={req_val} but got {pred_val}")

        if structural_errors:
            return False, True, symbol_matched, f"unsupported_claim: {'; '.join(structural_errors)}"

        return True, file_matched, symbol_matched, None

    def evaluate_case(
        self,
        case: BenchmarkCase,
        emitted_findings: List[EvaluatedFinding],
        manifest_files: Set[str],
        file_line_counts: Dict[str, int],
        explicit_abstention: bool = False,
        pipeline_error: Optional[str] = None,
    ) -> CaseEvaluationResult:
        """Deterministically evaluate emitted findings for a single benchmark case."""
        norm_manifest = {normalize_repo_path(f) for f in manifest_files}
        res = CaseEvaluationResult(
            case_id=case.case_id,
            case_family=case.case_family,
            split=case.split.value,
            category=case.category.value,
            difficulty=case.difficulty.value,
            evaluation_stage=case.evaluation_stage,
            expected_verdict=case.annotation.expected_verdict,
            evaluation_scope=case.annotation.evaluation_scope,
            emitted_findings=emitted_findings,
        )

        if pipeline_error:
            res.mismatch_reasons.append(f"Pipeline error: {pipeline_error}")
            if case.annotation.expected_verdict == ExpectedVerdict.UNKNOWN:
                res.abstention_outcome = AbstentionOutcome.PIPELINE_NOT_EVALUABLE
            return res

        # -------------------------------------------------------------
        # 1. EVALUATION FOR UNKNOWN / INSUFFICIENT EVIDENCE CASES
        # -------------------------------------------------------------
        if case.annotation.expected_verdict == ExpectedVerdict.UNKNOWN:
            res.is_unknown_case = True
            relevant_findings = [
                f for f in emitted_findings
                if not case.annotation.target_rule_ids or f.rule_id in case.annotation.target_rule_ids
            ]
            if explicit_abstention:
                res.abstention_outcome = AbstentionOutcome.EXPLICIT_CORRECT_ABSTENTION
            elif len(relevant_findings) == 0:
                res.abstention_outcome = AbstentionOutcome.NO_POSITIVE_PUBLICATION
            else:
                res.abstention_outcome = AbstentionOutcome.INCORRECT_CONFIDENT_POSITIVE
                res.fp += len(relevant_findings)
                res.false_positive_findings.extend(relevant_findings)
                res.mismatch_reasons.append(
                    f"Confidently emitted {len(relevant_findings)} findings on UNKNOWN case"
                )
            return res

        # -------------------------------------------------------------
        # 2. EVALUATION FOR CLEAN CASES (TRUE NEGATIVES)
        # -------------------------------------------------------------
        if case.annotation.expected_verdict == ExpectedVerdict.CLEAN:
            res.is_clean_case = True
            false_positives: List[EvaluatedFinding] = []

            for f in emitted_findings:
                # Check reference validity
                if not self._check_reference_validity(f, norm_manifest, file_line_counts):
                    res.invalid_reference_count += 1

                # Apply scope
                if case.annotation.evaluation_scope == EvaluationScope.RULE_SCOPED:
                    if f.rule_id in case.annotation.target_rule_ids:
                        false_positives.append(f)
                elif case.annotation.evaluation_scope == EvaluationScope.ALL_SUPPORTED:
                    # In all-supported clean scope, any ISSUE_SIGNAL finding is a false positive
                    rule_def = self.rule_map.get(f.rule_id)
                    if rule_def and rule_def.rule_type == RuleType.ISSUE_SIGNAL:
                        false_positives.append(f)
                    elif not rule_def:
                        # Unknown rule emitted
                        false_positives.append(f)

            res.fp = len(false_positives)
            res.false_positive_findings = false_positives
            if res.fp == 0:
                res.clean_case_tn = True
            else:
                res.clean_case_fp = True
                res.mismatch_reasons.append(f"Emitted {res.fp} false positive findings on CLEAN case")
            return res

        # -------------------------------------------------------------
        # 3. EVALUATION FOR ISSUE CASES (POSITIVE BUGS / FACTS)
        # -------------------------------------------------------------
        expected_claims = case.annotation.claims
        unmatched_claims: Dict[int, FindingClaimSpec] = {idx: claim for idx, claim in enumerate(expected_claims)}
        matched_claim_indices: Set[int] = set()

        for f in emitted_findings:
            # Check reference validity
            is_valid_ref = self._check_reference_validity(f, norm_manifest, file_line_counts)
            if not is_valid_ref:
                res.invalid_reference_count += 1
                res.fp += 1
                res.false_positive_findings.append(f)
                res.mismatch_reasons.append(f"Invalid reference in finding: {f.file_path}:{f.start_line}")
                continue

            # Check if this finding matches any remaining unmatched claim
            matched_claim_idx: Optional[int] = None
            candidate_mismatch_reasons: List[str] = []
            is_unsupported = False

            for idx, claim in unmatched_claims.items():
                is_match, file_loc, sym_loc, mismatch_reason = self._matches_claim(f, claim)
                if is_match:
                    matched_claim_idx = idx
                    res.tp += 1
                    if file_loc:
                        res.file_localized_tp += 1
                    if sym_loc:
                        res.symbol_localized_tp += 1
                    res.matched_claim_ids.append(f"{claim.rule_id}@{claim.permitted_files[0]}")
                    break
                else:
                    if f.rule_id == claim.rule_id and mismatch_reason:
                        candidate_mismatch_reasons.append(mismatch_reason)
                        if mismatch_reason.startswith("unsupported_claim"):
                            is_unsupported = True

            if matched_claim_idx is not None:
                del unmatched_claims[matched_claim_idx]
                matched_claim_indices.add(matched_claim_idx)
            else:
                # Finding did not match any UNMATCHED claim
                # Check if it matches an ALREADY matched claim (Duplicate prediction)
                is_duplicate = False
                for idx in matched_claim_indices:
                    claim = expected_claims[idx]
                    is_match, _, _, _ = self._matches_claim(f, claim)
                    if is_match:
                        is_duplicate = True
                        break

                if is_duplicate:
                    res.duplicate_fp += 1
                    res.fp += 1  # 1-to-1 matching rule: duplicates are retained in raw FP
                    res.false_positive_findings.append(f)
                    res.mismatch_reasons.append(f"Duplicate prediction for already-matched claim {claim.rule_id}")
                else:
                    # Unmatched finding
                    res.fp += 1
                    if is_unsupported:
                        res.unsupported_claim_count += 1
                    res.false_positive_findings.append(f)
                    if candidate_mismatch_reasons:
                        reasons_str = "; ".join(candidate_mismatch_reasons)
                        res.mismatch_reasons.append(
                            f"Unmatched finding: {f.rule_id} at {f.file_path} ({reasons_str})"
                        )
                    else:
                        res.mismatch_reasons.append(f"Unmatched published finding: {f.rule_id} at {f.file_path}")

        # Any expected claims not matched by findings are False Negatives (FN)
        for idx, claim in unmatched_claims.items():
            res.fn += 1
            claim_id = f"{claim.rule_id}@{claim.permitted_files[0]}"
            res.unmatched_claim_ids.append(claim_id)
            res.mismatch_reasons.append(f"False negative: expected claim {claim_id} was not detected")

        # Evaluate expected impact count assertion if defined
        if case.annotation.expected_impact_count is not None:
            # We verify that the number of impact facts matches expected_impact_count
            actual_impact_count = sum(
                1 for f in emitted_findings if f.stage == EvaluationStage.IMPACT_FACT
            )
            if actual_impact_count != case.annotation.expected_impact_count:
                res.mismatch_reasons.append(
                    f"Impact count mismatch: expected {case.annotation.expected_impact_count}, got {actual_impact_count}"
                )

        return res
