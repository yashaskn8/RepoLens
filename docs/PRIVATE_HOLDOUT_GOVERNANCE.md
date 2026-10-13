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

## 3. Current Execution Authority

Private holdout execution is **NOT CONFIGURED**. There is no trusted private fixture manifest, authenticated operator authorization path, or authoritative transactional claim service in this repository. `HoldoutAuthorizationContract.check_authorization()` therefore denies execution before opening caller-supplied paths or claiming the local ledger. The local `SingleUseLedger` remains a utility and is not an official execution authority.

The public benchmark contract is source-pinned and binds its exact component inventory, evaluator files, catalog, and canonical dataset. Any evaluator change invalidates that contract until a reviewed manifest and matching source pin are updated. This repository pin is not a cryptographic signature or proof of an external review. Official execution scope is minted only by the verified in-process runner; serialized report JSON is untrusted and cannot recreate that authority.

The production analyzer freeze remains stale whenever its registered source digests do not match. That validation is separate from public benchmark identity and does not authorize private evaluation.

---

## 4. Local Single-Use Ledger Utility

The local file ledger supports single-host concurrency tests and records utility entries. It is not a distributed or multi-host authorization service and is not called by an official private-holdout execution path. A future official evaluator must use a trusted holdout identity, authenticated operator authorization, claim-before-fixture-access semantics, and durable transactional uniqueness before private fixtures are made available.

---

## 5. Current Authority Status

```json
{
  "production_freeze_id": "e54409eb0ea30e70cde4ff9abe3143c8a775e04c2b0c330db6819e6a57d1a516",
  "benchmark_contract_id": "ce789690aae268a55c3c9b3bbe6d34cc2b8d56927af0745b353186fd6bccc85b",
  "private_holdout_content_accessed": false,
  "private_final_holdout_exists": false,
  "private_final_evaluation_authorized": false,
  "private_final_evaluation_status": "NOT_CONFIGURED",
  "unseen_generalization_score": "NOT_MEASURED"
}
```
