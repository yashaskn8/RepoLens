# RepoLens Private Final Holdout Governance Protocol

## 1. Overview & Purpose

RepoLens has achieved `1.0000` precision, recall, F1, specificity, and localization on the frozen 90-case public regression suite. Because iterative bug fixes and performance tuning occurred while public case annotations were accessible in the repository, this score represents a **regression benchmark** rather than an **unseen generalization evaluation**.

To scientifically measure true unseen generalization, an independent **PRIVATE_FINAL_HOLDOUT** suite must be evaluated under strict cryptographic quarantine.

---

## 2. Invariants & Independence Mandates

### Mandate 1: Zero Development-Agent Access
No AI coding assistant, model prompt, development engineer, or automated CI tool working on the RepoLens analyzer may view, parse, index, search, or access the private holdout test cases, fixtures, annotations, or expected findings before execution.

### Mandate 2: Independent Curation & Novelty
- **No Direct Copies or Paraphrases**: Private cases must not be syntactic renames or simple permutations of the public 90 cases.
- **Novel Identifiers & Architectures**: Fixtures must employ novel package hierarchies, naming conventions, and control/data flow patterns.
- **Novel Impact Topologies**: Change analysis and impact graph fixtures must construct fresh dependency graphs not present in public cases.
- **Hard Negatives & Ambiguities**: Must include difficult clean negatives (e.g. valid sanitizers, dynamic dispatch, decorator-wrapped endpoints) and `UNKNOWN` cases requiring abstention.

### Mandate 3: Metadata-Only Development Boundary
Development tooling and reports may receive only top-level summary metadata:
- `holdout_id`: Unique cryptographic identifier.
- `schema_version`: Must conform to canonical `BenchmarkCase` schema.
- `case_count`: Number of cases (target: 30–50).
- `family_count`: Number of disjoint families (target: 10–15).
- `capability_distribution`: High-level count per subsystem.
- `manifest_hash`: SHA-256 over canonical dataset serialization.
- `seal_status`: Must be `SEALED`.

Development tooling must **NEVER** receive before final execution:
- Raw fixture source code.
- Ground-truth claims or expected findings.
- Per-case failure logs or diffs.

---

## 3. Cryptographic Authorization Gate

Execution against the private holdout is blocked by default (`PRIVATE_FINAL_EVALUATION_AUTHORIZED = false`). Authorization is granted only when all of the following conditions are simultaneously met:

1. **Production Freeze Valid**: All 12 production analyzer files match their registered SHA-256 hashes in `production_freeze_manifest.json` (`production_freeze_id: e54409eb0ea30e70cde4ff9abe3143c8a775e04c2b0c330db6819e6a57d1a516`).
2. **Benchmark Contract Freeze Valid**: Runner, matcher, loader, metrics, and schema files match `benchmark_contract_manifest.json` (`benchmark_contract_id: 9685a5e2d0eff38659552a42c894e4f2db2c23031e77a376734b5a8fed2f76a8`).
3. **Canonical Dataset Intact**: Public 90-case dataset hash equals `1611efec9c34421b19d862427241fde5061170d7268602103fd5585e66b317bf`.
4. **Adversarial Audit Passed**: 0 critical/high findings in the hostile evaluation audit.
5. **Private Holdout Sealed**: Independent curator has cryptographically sealed the holdout manifest.
6. **Single-Use Ledger Available**: Holdout has not been executed previously.

---

## 4. Single-Use Evaluation Ledger

To prevent iterative tuning against the private holdout:
1. Each private holdout may be executed **exactly once** as an official evaluation.
2. The execution is immutably recorded in `single_use_ledger.json` with timestamp, commit SHA, and authorization ID.
3. Once executed, `consumed = True`. Re-execution against the same holdout is strictly forbidden.
4. If RepoLens code is modified based on post-evaluation error analysis, the holdout is automatically downgraded to regression data and cannot serve as an unseen generalization benchmark.

---

## 5. Current Authority Status

```json
{
  "production_freeze_id": "e54409eb0ea30e70cde4ff9abe3143c8a775e04c2b0c330db6819e6a57d1a516",
  "benchmark_contract_id": "9685a5e2d0eff38659552a42c894e4f2db2c23031e77a376734b5a8fed2f76a8",
  "private_holdout_content_accessed": false,
  "private_final_holdout_exists": false,
  "private_final_evaluation_authorized": false,
  "unseen_generalization_score": "NOT_MEASURED"
}
```
