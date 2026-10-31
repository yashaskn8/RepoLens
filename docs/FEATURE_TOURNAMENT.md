# RepoLens: 100 feature candidates, modeled engineering review, and architecture decision

Research review: **2026-10-31**. Repository: [RepoLens](https://github.com/yashaskn8/RepoLens). This is an **ideation catalog**, not evidence that 100 separate existing products were independently validated. Candidates are synthesized from the official online sources below and the existing RepoLens feature inventory in `docs/phase9/product-capability-matrix.md`; some overlap with current or partially delivered capabilities and require deduplication before new implementation.

## Online research inputs

- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [GitHub SARIF upload integration](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review)
- [GitHub code scanning / autofix](https://docs.github.com/en/code-security/responsible-use/security-and-quality-ai-features)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [OWASP DevSecOps Guideline](https://owasp.org/projects/devsecops-guideline)

The source set motivates code scanning interoperability, secure CI, dependency analysis, vulnerability prioritization, evidence integrity, supply chain controls, and reviewable automation. It does **not** verify each proposed item individually.

## 100 candidates

### 1. Evidence integrity & triage

001. Evidence attestation inspector
002. Cross-scan evidence deduplication
003. Finding confidence audit trail
004. Source-line drift detection
005. Evidence freshness badge
006. Cross-detector correlation graph
007. Reproducibility metadata explorer
008. Finding provenance timeline
009. Verified-only finding digest
010. Ambiguous-location quarantine dashboard

### 2. Pull requests & CI

011. PR security budget gate
012. API compatibility regression gate
013. Change-risk trend charts
014. Ownership-aware review routing
015. Breaking-contract summary comment
016. PR dependency update delta
017. Changed-file exposure diff
018. Preview-only branch policy checks
019. Incremental critical-path scan
020. Merge-base consistency monitor

### 3. Dependencies & supply chain

021. SBOM CycloneDX export
022. SBOM change comparison
023. Known-exploited vulnerability triage
024. Transitive dependency route mapping
025. Unmaintained dependency signals
026. Package provenance audit
027. Dependency license delta
028. Build action pinning report
029. Typosquat suspicion queue
030. Lockfile integrity anomaly report

### 4. Remediation lifecycle

031. Patch side-effect checklist
032. Risk-ranked fix queue
033. Fix verification evidence bundle
034. Remediation rollback template
035. Patch acceptance criteria generator
036. Safe autofix candidate preview
037. Non-executing patch syntax diagnostics
038. Fix ownership reminders
039. Fix plan dependency ordering
040. Post-fix finding recurrence detection

### 5. Developer experience

041. One-click evidence permalink
042. Finding keyboard navigation
043. Saved finding search filters
044. Diff-to-finding jump links
045. Architecture explainer minimap
046. Incremental scan progress chart
047. Repository onboarding checklist
048. Contextual risk glossary
049. Accessibility-focused evidence UI
050. Finding history activity feed

### 6. Reporting & interoperability

051. SARIF 2.1.0 verified findings export
052. JSON Lines finding export
053. CycloneDX VEX status mapping
054. SPDX finding correlation
055. Signed report manifest
056. Auditor-ready finding packet
057. Policy-exception expiry export
058. CSV triage snapshot
059. Machine-readable coverage report
060. Report-to-commit verification link

### 7. Governance & policy

061. Time-boxed risk acceptance record
062. Suppression expiry workflow
063. Severity policy version history
064. Tenant-local rule exceptions
065. Release evidence approval checklist
066. Change-approval decision log
067. Rule ownership matrix
068. Policy drift comparison
069. Immutable evidence retention policy
070. Delegated audit report access

### 8. Performance & scale

071. Streaming result pagination
072. Bounded graph hotspot profiler
073. Incremental exact-commit cache
074. Large-repository cost simulator
075. Memory ceiling regression gate
076. Index hit-rate benchmark panel
077. Expensive query trace sampler
078. Scan queue capacity estimator
079. Performance baseline comparator
080. Partial coverage reason explorer

### 9. AI quality & trust

081. Model claim citation audit
082. False-positive review feedback
083. Provider disagreement disclosure
084. Prompt injection attempt trend
085. AI recommendation fallback tracker
086. Hallucination regression fixture generator
087. Evidence-grounding failure taxonomy
088. LLM cost/per-finding telemetry
089. Deterministic-vs-model decision explainer
090. Evaluation set contamination monitor

### 10. Operations & security monitoring

091. Hourly release regression monitoring
092. Failed CI incident deduplication
093. Annual feature discovery tournament
094. API error budget dashboard
095. Background lease-failure alerts
096. Migration compatibility warning
097. Tokenless health readiness check
098. Security release checklist automation
099. Feature rollout kill-switch review
100. Read-only production smoke timeline

## Modeled senior engineering panel

The panel below is a **structured simulation of review perspectives**, not real engineers hired or interviewed. Roles: Senior Backend Engineer (data contracts and architecture), Application Security Engineer (tenant isolation and truthfulness), SRE/Platform Engineer (resource safety and operations), and Senior Frontend Engineer (discoverability and user value). Scoring is subjective, on a 1–5 scale (5 best). It is not customer validation or production performance evidence.

### Shortlist: multi-criterion trade-off

| Candidate | Impact 25% | Safety 25% | Existing architecture fit 20% | Delivery simplicity 20% | Operations 10% | Score / 5 |
|---|---:|---:|---:|---:|---:|---:|
| SARIF verified-only export | 5 | 5 | 5 | 4 | 5 | 4.80 |
| Coverage report export | 4 | 4 | 4 | 4 | 5 | 4.10 |
| Evidence attestation inspector | 4 | 5 | 4 | 3 | 4 | 4.05 |
| PR security budget gate | 5 | 4 | 3 | 3 | 4 | 3.85 |
| SBOM diff dashboard | 5 | 4 | 3 | 3 | 3 | 3.75 |
| Suppression expiry workflow | 4 | 4 | 3 | 3 | 4 | 3.60 |
| Cross-scan recurrence detection | 4 | 4 | 3 | 3 | 4 | 3.60 |
| AI citation audit | 4 | 5 | 3 | 2 | 3 | 3.55 |
| Provenance audit | 4 | 5 | 3 | 2 | 3 | 3.55 |
| Policy drift comparison | 4 | 4 | 3 | 3 | 3 | 3.50 |

### Contestant challenges / review objections

- **SARIF:** Backend: use existing canonical findings, avoid inventing another finding store. Security: prove evidence is confirmed and commit-grounded; never expose source snippets. SRE: cap size and fail explicitly, not silently. UX: download from the existing scan report toolbar. **Wins** on low-risk interoperability and minimal surface area.
- **SBOM diff:** high user value, but requires a new dependency completeness contract before it is safe to declare differences authoritative.
- **PR security budget gate:** compelling CI value but policy/version semantics and fail-open/fail-closed decisions need explicit ownership.
- **Suppression expiry:** meaningful governance, but needs persistence migration and permission model.
- **AI citation audit:** attractive, but user trust requires an independently labeled deterministic verifier and evaluation dataset.

### Architecture tournament for SARIF

| Architecture | Security & correctness | Maintainability | Change surface | Decision |
|---|---|---|---|---|
| A: all logic in scan endpoint | Can reuse authorization; easy to mix validation and presentation | Low | Small | Rejected: creates a large, brittle handler |
| **B: pure SARIF projection + thin authenticated scan route** | **Reuses canonical evidence grounding; bounded read-only export** | **High** | **Small** | **Selected** |
| C: durable async artifact generation with new persistence | Good at very large scale, but needs lifecycle/migrations | Medium | Large | Defer until proven necessary |
| D: browser-only conversion from paginated JSON | Risks incomplete pagination and duplicated trust logic | Low | Medium | Rejected |

### Selected feature acceptance criteria

- Export only **OPEN**, **CONFIRMED**, canonically grounded findings of the signed-in user's **COMPLETED** scan at an immutable source commit.
- Use SARIF **2.1.0**, stable rule IDs and `primaryLocationLineHash` fingerprints, URI-safe source paths, and consistent severity levels.
- Do not return raw code snippets or secrets; set no-store and attachment headers.
- Reject oversized results with explicit **413** rather than represent silently truncated output as complete.
- Expose `GET /api/v1/scans/{scan_id}/sarif` and a Download SARIF button after scan completion.
- Cover ownership, negative verdicts, suppressed findings, grounding, determinism, response format, and bounds with tests. CI success is evidence only for the exact tested revision.

## Operating cadence (after merge to default branch)

- **Hourly** at minute 23 UTC: focused SARIF regression tests and Python compilation. A failed run opens one deduplicated investigation issue if none is already open. Human maintainers reproduce and fix on a reviewed PR; there is **no** autonomous code writing, deployment, auto-approval, or merge.
- **Yearly** on October 31 at 10:17 UTC: one deduplicated issue requesting refreshed current-source discovery of 100 ideas, an engineering/architecture comparison, and an isolated implementation PR.
- Workflow also supports explicit manual dispatch for both cadences. GitHub scheduled events run from **default branch only**, may be delayed, and do not run just because this branch contains the workflow.
- Human release decision includes successful CI, AppSec authorization review, manual production validation and rollback plan. No green check alone proves production-readiness.

## Limitations and follow-on improvements

The export represents **verified open findings**, not exhaustive absence of vulnerabilities, complete scanner coverage, or a CI release gate. The current policy caps results at **5,000** and output at **10 MB**. If real workloads exceed bounds, add a versioned multi-run export design and compatibility fixtures, not silent truncation. GitHub code scanning ingestion is **not** automatically enabled; users must explicitly upload SARIF through an appropriately authorized workflow or API. Every external upload needs source repository/commit consistency checks and least-privilege credentials.

Sources for implementation contract: [SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) and [uploading SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).
