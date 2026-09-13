# RepoLens Ground-Truth Evaluation Benchmark: Methodology and Specification

- **Benchmark Version**: `1.0.0`
- **Dataset Version**: `1.0.0`
- **Canonical Dataset Hash**: `1611efec9c34421b19d862427241fde5061170d7268602103fd5585e66b317bf`
- **Evaluation Harness**: `backend/app/evaluation/ground_truth/`
- **Cases Directory**: `backend/evaluation_data/ground_truth/v1/cases/`
- **CLI Runner**: `python -m app.cli.run_benchmark`

---

## 1. Executive Summary & Purpose

The RepoLens Ground-Truth Evaluation Benchmark provides an objective, scientific, reproducible evaluation framework for measuring RepoLens's static code analysis, semantic hypothesis generation, contract diffing, and blast-radius impact analysis capabilities.

Prior to this benchmark, evaluation was demonstrated qualitatively through individual unit tests or synthetic smoke-checks. This benchmark establishes:
1. **Reproducible Quantification**: Every metric is mathematically defined with exact 1-to-1 matching and confidence intervals.
2. **Untrusted Sandboxing**: Target fixtures are treated as hostile, untrusted inputs. They are never executed, compiled, imported, or executed in Docker.
3. **Independent Adjudication**: The evaluation harness never invokes `ChangeReviewVerifier` or RepoLens's internal verifier to grade its own output.
4. **Architectural Leakage Prevention**: Ground-truth labels, case IDs, and markers are strictly isolated from analysis inputs.
5. **Two-Level Metrics**: Evaluates finding-level precision/recall/F1 as well as case-level specificity on CLEAN true negative cases.
6. **Zero-Key CI Support**: The entire deterministic baseline executes in ~1.5s in standard CI environments without requiring network access, API keys, or GPU resources.

---

## 2. Benchmark Architecture & Workflow

The benchmark operates through a clean pipeline with strict separation of concerns:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       Curated Benchmark Cases                           │
│                 (90 JSON files across 24 families)                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     Pre-Flight Leakage Detector                         │
│   • Scans fixture paths and code for forbidden label markers            │
│   • Verifies case IDs do not leak into source files                     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
┌─────────────────────────────────┐   ┌───────────────────────────────────┐
│         Analysis Input          │   │        Ground Truth Spec          │
│ • Neutral sandbox directory     │   │ • Expected verdict & scope        │
│ • Pure repository files         │   │ • Target rule IDs                 │
│ • No labels, case IDs, or hints │   │ • FindingClaimSpecs               │
└────────────────┬────────────────┘   └─────────────────┬─────────────────┘
                 │                                      │
                 ▼                                      │
┌─────────────────────────────────┐                     │
│        Target Pipeline          │                     │
│ • REPOSITORY_SCAN               │                     │
│ • CHANGE_ANALYSIS               │                     │
│ • IMPACT_ANALYSIS               │                     │
└────────────────┬────────────────┘                     │
                 │                                      │
                 ▼                                      │
┌─────────────────────────────────┐                     │
│        Emitted Findings         │                     │
│  (Normalized EvaluatedFinding)  │                     │
└────────────────┬────────────────┘                     │
                 │                                      │
                 └───────────────────┬──────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Independent Benchmark Judge                          │
│ • Reference validity check (file in manifest, line in bounds)           │
│ • 1-to-1 matching (at most 1 TP per ground-truth claim)                 │
│ • Structural fact exact entailment & forbidden fact validation          │
│ • Duplicate penalty (excess predictions count as raw FPs)               │
│ • Abstention accounting for UNKNOWN / insufficient evidence cases       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Metric Aggregator                               │
│ • Precision, Recall, F1 with Wilson score 95% CIs                       │
│ • Clean case specificity with Wilson score 95% CIs                      │
│ • Family cluster bootstrap resampling (B=1,000) for macro uncertainty   │
│ • Layer-separated metrics (STATIC, CANDIDATE, CHANGE, IMPACT)           │
│ • Granular failure breakdown & mismatch classification                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Capability Catalog & Output Layers

RepoLens produces signals at distinct architectural stages. To avoid misleading aggregations, every rule in `catalog.json` is assigned an explicit `evaluation_stage`:

| Stage | Pipeline | Native Output Object | Description |
|---|---|---|---|
| `STATIC_FINDING` | `REPOSITORY_SCAN` | `Finding` | Fully confirmed deterministic static findings from regex/AST scanners. |
| `ANALYSIS_CANDIDATE` | `REPOSITORY_SCAN` | `AnalysisCandidate` | Bounded hypotheses/candidates awaiting multi-step verification. |
| `CHANGE_FACT` | `CHANGE_ANALYSIS` | `RouteContractDelta` / `SchemaModelDelta` | Deterministic structural contract differences between base and head. |
| `IMPACT_FACT` | `IMPACT_ANALYSIS` | `ChangeImpact` | Deterministic blast-radius impacts on downstream consumers/callers. |
| `PUBLISHED_FINDING` | Full Agent | `ReviewComment` | Reserved for fully published, verifier-gated comments in production reviews. |

### Capability Rules Summary

1. `HARDCODED_CREDENTIAL` (`STATIC_FINDING`): Regex pattern scanning for high-entropy tokens and API keys in config files (`.tf`, `.yaml`, `.toml`, `.conf`, `.sh`).
2. `CLIENT_CONTROLLED_AUTH_HEADER` (`STATIC_FINDING`): Insecure reliance on client-supplied headers (e.g. `X-User-Id`, `X-Forwarded-User`) for identity without server-side validation.
3. `ASYNC_BLOCKING_CALL` (`ANALYSIS_CANDIDATE`): Blocking I/O calls (`time.sleep()`, synchronous network/disk reads) within async function bodies in Python.
4. `BROAD_EXCEPTION_SWALLOW` (`ANALYSIS_CANDIDATE`): Silent `except Exception: pass` or unlogged generic catch blocks in Python.
5. `UNAWAITED_ASYNC_CALL` (`ANALYSIS_CANDIDATE`): Calling coroutines without `await` inside async contexts.
6. `SQL_INJECTION_RISK` (`ANALYSIS_CANDIDATE`): Unparameterized string formatting/concatenation passed into database execute calls.
7. `COMMAND_INJECTION_RISK` (`ANALYSIS_CANDIDATE`): Untrusted inputs passed directly into system shell calls (`subprocess(shell=True)`, `os.system()`).
8. `PATH_TRAVERSAL_RISK` (`ANALYSIS_CANDIDATE`): Unconfined file path joining without `os.path.commonpath` or path sanitization.
9. `ROUTE_PATH_MISMATCH` (`CHANGE_FACT`): Modified API endpoint route URL paths between revisions.
10. `ROUTE_METHOD_MISMATCH` (`CHANGE_FACT`): Added or modified HTTP methods on existing route definitions.
11. `SCHEMA_FIELD_ADDED` (`CHANGE_FACT`): Added fields in data transfer models.
12. `SCHEMA_FIELD_REMOVED` (`CHANGE_FACT`): Removed fields from models (breaking change for consumers).
13. `SCHEMA_FIELD_TYPE_CHANGED` (`CHANGE_FACT`): Field type changes between revisions (breaking change).
14. `DELETED_SYMBOL_WITH_CALLERS` (`IMPACT_FACT`): Deletion of symbols that have remaining active callers in unchanged files.
15. `SIGNATURE_BREAK_CALLERS` (`IMPACT_FACT`): Changes to parameter counts or required arguments breaking caller call sites.
16. `API_CONTRACT_IMPACT` (`IMPACT_FACT`): Downstream API endpoints impacted by modified dependencies.
17. `SCHEMA_IMPACT` (`IMPACT_FACT`): Consumer services impacted by upstream schema model modifications.

---

## 4. Dataset Specification & Splits

The dataset comprises **90 carefully curated benchmark cases** organized into **24 case families**:

- **Category Partition**:
  - `SECURITY`: 10 families, 38 cases
  - `CORRECTNESS`: 4 families, 16 cases
  - `CONTRACT`: 5 families, 18 cases
  - `IMPACT`: 5 families, 18 cases
- **Verdict Distribution**:
  - `ISSUE`: 23 cases (positive ground-truth defects/facts)
  - `CLEAN`: 55 cases (true negatives for specificity evaluation)
  - `UNKNOWN`: 12 cases (insufficient evidence / indeterminate cases for abstention testing)

### Frozen Family-Level Split Policy

To ensure complete statistical separation and prevent data leakage:
1. **Partition Unit**: Entire families are assigned to either `DEV` or `FROZEN_PUBLIC_EVAL`.
2. **Zero Sibling Leakage**: Sibling cases within a family are **never** split across `DEV` and `FROZEN_PUBLIC_EVAL`.
3. **Partition Counts**:
   - `DEV`: 18 families (68 cases, 75.6% of dataset)
   - `FROZEN_PUBLIC_EVAL`: 6 families (22 cases, 24.4% of dataset)

Holdout families (`FROZEN_PUBLIC_EVAL`):
- `SEC-CRED-02`: Hardcoded credential variants
- `SEC-AUTH-02`: Client auth header variants
- `BUG-EXCEPT-02`: Exception swallow variants
- `BUG-BLOCK-02`: Blocking async call variants
- `CONTRACT-SCHEMA-TYPE-01`: Schema type modification variants
- `IMPACT-SCHEMA-01`: Schema consumer impact variants

---

## 5. Independent Adjudication & Matching Methodology

### 1-to-1 Matching Principle
To prevent "duplicate spam" attacks where models emit multiple identical findings to inflate true positives:
- Each ground-truth claim in `case.annotation.claims` can match **at most one** emitted finding.
- Once a claim is matched, subsequent identical findings are recorded as `duplicate_fp` and counted in `raw_confusion.fp`.

### Entailment Criteria (`_matches_claim`)
A finding matches a ground-truth claim if and only if all of the following hold:
1. **Rule ID**: `finding.rule_id == claim.rule_id`
2. **File Localization**: `normalize(finding.file_path) in [normalize(p) for p in claim.permitted_files]`
3. **Symbol Localization**: If `claim.permitted_symbols` is specified, `finding.symbol in claim.permitted_symbols`
4. **Span Localization**: If `claim.permitted_spans` is specified:
   $$\text{span\_start} - 5 \le \text{finding.start\_line} \le \text{span\_end} + 5$$
   (with `line_tolerance = 5`). If line number is omitted, symbol match is required.
5. **Required Structural Facts**: All key-value pairs in `claim.required_structural_facts` must match `finding.structural_facts`.
6. **Forbidden Structural Facts**: No key-value pairs in `claim.forbidden_structural_facts` may be present in `finding.structural_facts`.

### Unsupported Claim Tracking
If a finding matches rule ID and file but fails on structural facts (e.g. claims a breaking schema change when the change was backwards-compatible), it is classified as an **unsupported claim**, incrementing `res.unsupported_claim_count` and counting as an empirical FP.

### Reference Validity Checks
Every emitted finding is validated against repository files:
- The referenced file must exist in the repository manifest.
- The referenced start line must be $\ge 1$ and within the file's line count $+ 10$.
Findings with invalid file or line references increment `invalid_reference_count` and count as FPs.

---

## 6. Two-Level Metrics & Statistical Rigor

### Level 1: Finding-Level Confusion Matrix
- $\text{TP}$: Emitted findings matching an expected claim 1-to-1.
- $\text{FP}$: Excess findings, duplicate findings, invalid references, unsupported claims, or findings on CLEAN/UNKNOWN cases.
- $\text{FN}$: Expected claims that were not matched by any finding.

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}, \quad \text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}, \quad \text{F}_1 = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

### Level 2: Case-Level Clean Specificity
Evaluated over CLEAN cases (cases where no defect exists):
- $\text{Case-Level TN}$: Clean case with exactly zero false positive findings.
- $\text{Case-Level FP}$: Clean case where one or more false positive findings were emitted.

$$\text{Clean Case Specificity} = \frac{\text{Case-Level TN}}{\text{Total Clean Cases}}$$

### Wilson Score Confidence Intervals
For all single-run binomial proportions ($p$), two-sided 95% Wilson score confidence intervals are computed:

$$w = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}} \quad (z = 1.95996)$$

### Family Cluster Bootstrap Resampling
To quantify macro-level uncertainty across heterogeneous case families:
1. Resample $B = 1,000$ whole case families with replacement.
2. Pool all cases from selected families.
3. Compute metrics on the bootstrap replicate.
4. Replicates where denominators are zero (e.g. zero positive predictions for precision) are mathematically excluded from percentile ranks rather than assigned arbitrary default values.
5. The 2.5th and 97.5th percentiles of valid replicates define the 95% bootstrap CI.

### Abstention & UNKNOWN Handling
For UNKNOWN cases (cases with insufficient evidence to establish defect or safety):
- `EXPLICIT_CORRECT_ABSTENTION`: Analysis returned an explicit abstention signal.
- `NO_POSITIVE_PUBLICATION`: Analysis emitted zero positive findings on the case.
- `INCORRECT_CONFIDENT_POSITIVE`: Analysis erroneously emitted positive findings on the UNKNOWN case (penalized as empirical FP).

---

## 7. Baseline Performance (v1.0.0 Frozen Baseline)

The following baseline metrics were measured on commit `087fe71ea0766da4e3968457a0fdb23d02ea148d` under deterministic-only mode (no LLM, zero-key):

### Executive Summary

| Metric | Measured Value | 95% Wilson CI / Bootstrap CI |
|---|---|---|
| **Precision** | `0.5217` (12 / 23) | Bootstrap: `[0.3636, 0.7000]` |
| **Recall** | `0.5217` (12 / 23) | Bootstrap: `[0.3333, 0.7273]` |
| **F1 Score** | `0.5217` | Bootstrap: `[0.3478, 0.6957]` |
| **Clean Case Specificity** | `0.9455` (52 / 55) | Wilson: `[0.8515, 0.9813]` |
| **Clean Case FP Rate** | `0.0545` (3 / 55) | - |
| **File Localization Accuracy** | `1.0000` (12 / 12) | Wilson: `[0.7575, 1.0000]` |
| **Symbol Localization Accuracy** | `0.5000` (6 / 12) | Wilson: `[0.2538, 0.7462]` |
| **Unsupported Published Finding Rate** | `0.0000` (0 total) | - |
| **Execution Duration** | `1.47s` (90 cases) | - |

### Layer Breakdown

| Evaluation Stage | Executed | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| `STATIC_FINDING` | 24 | 3 | 1 | 1 | **0.7500** | **0.7500** | **0.7500** |
| `ANALYSIS_CANDIDATE` | 30 | 1 | 7 | 7 | **0.1250** | **0.1250** | **0.1250** |
| `CHANGE_FACT` | 18 | 5 | 1 | 0 | **0.8333** | **1.0000** | **0.9091** |
| `IMPACT_FACT` | 18 | 3 | 2 | 3 | **0.6000** | **0.5000** | **0.5455** |

### Key Observations & Failure Modes

1. **High Clean Specificity (94.5%)**: Deterministic scanners show strong resistance to false alarms on negative samples.
2. **Contract Diffs Excel (F1 = 0.909)**: Route and schema contract diffing is highly accurate and deterministic.
3. **Symbol Formatting Discrepancy in Candidates**: Several candidates (`BUG-EXCEPT-01A`, `BUG-EXCEPT-02A`, `BUG-UNAWAITED-01A`) emitted symbols in the format `file:symbol:line` instead of the bare symbol name, causing symbol localization mismatches.
4. **Indeterminate Schema Delta on UNKNOWN**: Case `CONTRACT-SCHEMA-TYPE-01D` emitted a delta when evidence was ambiguous, illustrating the need for stricter abstention boundaries.

---

## 8. Adversarial Red-Team Test Suite

The benchmark includes a dedicated adversarial test suite (`tests/test_ground_truth_benchmark_redteam.py`) simulating 11 active cheating strategies:

1. **Solution Leakage in Comments**: Fixtures with `# BENCHMARK: EXPECT_FINDING ...` are rejected at pre-flight.
2. **Keyword Leakage in Filenames**: Fixtures with `/vulnerability_finding_sqli.py` are rejected at pre-flight.
3. **Duplicate Prediction Spam**: Spamming 5 identical predictions yields TP=1, FP=4, not TP=5.
4. **Lucky Keyword Guessing (Wrong File)**: Predicting the correct rule in the wrong file yields TP=0, FP=1, FN=1.
5. **Hallucinated Line Range**: Predicting the correct rule and file at line 999 yields TP=0, FP=1, FN=1 with a span mismatch.
6. **Trivial "Everything is a Bug" Predictor**: Emitting findings on every case collapses Clean Specificity to 0.0%.
7. **Trivial "Everything is Safe" Predictor**: Emitting zero findings yields Recall=0.0 and undefined Precision.
8. **Guessing on UNKNOWN**: Emitting confident predictions on UNKNOWN cases is penalized as `INCORRECT_CONFIDENT_POSITIVE` (FP=1).
9. **Partial-Run Gaming**: Running fewer than eligible cases is flagged in `execution_status` and percentage calculations.
10. **Zero-Division Resilience**: All calculations with zero denominators safely return `None` rather than raising `ZeroDivisionError`.
11. **Fixture Mutation Isolation**: Mutating repository files does not modify ground-truth annotations.

---

## 9. Contribution & Curation Guide

### Case File Schema Template

To add a new benchmark case, create a JSON file in `backend/evaluation_data/ground_truth/v1/cases/<category>/<CASE-ID>.json`:

```json
{
  "case_id": "SEC-NEW-01A",
  "benchmark_version": "1.0.0",
  "case_family": "SEC-NEW-01",
  "category": "SECURITY",
  "difficulty": "MEDIUM",
  "split": "DEV",
  "target_pipeline": "REPOSITORY_SCAN",
  "evaluation_stage": "STATIC_FINDING",
  "benchmark_languages": ["python"],
  "fixture": {
    "files": {
      "app/config.py": "API_SECRET = 'super_secret_token_12345'\n"
    },
    "description": "Hardcoded secret token in configuration module"
  },
  "annotation": {
    "expected_verdict": "ISSUE",
    "evaluation_scope": "RULE_SCOPED",
    "target_rule_ids": ["HARDCODED_CREDENTIAL"],
    "claims": [
      {
        "rule_id": "HARDCODED_CREDENTIAL",
        "permitted_files": ["app/config.py"],
        "permitted_spans": [[1, 1]],
        "required_structural_facts": {},
        "forbidden_structural_facts": {}
      }
    ],
    "how_established": "synthetic",
    "fixture_source": "unit_test",
    "human_authored_explanation": "Direct credential string literal assigned in top-level constant."
  }
}
```

### Validation Checklist for New Cases

1. **Verify Catalog Consistency**: The `target_rule_ids` and `claims[].rule_id` must match entries in `catalog.json`.
2. **Assign to Family**: Choose a distinct `case_family`. If the family is in `DEV`, all cases in that family must have `"split": "DEV"`.
3. **Run Leakage Audit**: Ensure no file paths or contents contain forbidden words (`BENCHMARK_EXPECTED`, `GROUND_TRUTH`, `CASE_ID`, etc.).
4. **Re-compute Canonical Hash**:
   ```python
   from app.evaluation.ground_truth.loader import load_benchmark_dataset, compute_canonical_benchmark_hash
   cases = load_benchmark_dataset()
   print("New Hash:", compute_canonical_benchmark_hash(cases))
   ```
5. **Run Integrity & Red-Team Tests**:
   ```powershell
   .\.venv\Scripts\python.exe -m pytest tests/test_ground_truth_benchmark_integrity.py tests/test_ground_truth_benchmark_redteam.py -v
   ```
