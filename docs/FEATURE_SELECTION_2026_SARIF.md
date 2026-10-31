# RepoLens 2026 feature tournament and architecture decision

**Date:** 2026-10-31
**Branch:** `feature/verified-sarif-export-2026`
**Method:** Online product-pattern research + a **simulated** (not convened human) senior engineering panel. This is a prioritization exercise, **not** 100 independent external feature endorsements or a professional security audit.

## Online research inputs

- [GitHub code security capabilities](https://docs.github.com/en/code-security/getting-started/github-security-features): dependency review, code scanning, triage and vulnerability response.
- [GitHub dependency review workflow](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/reviewing-dependency-changes-in-a-pull-request): change-focused dependency insight.
- [Semgrep Supply Chain](https://semgrep.dev/products/semgrep-supply-chain/): reachability, dependency intelligence and upgrade guidance.
- [OpenSSF Scorecard](https://scorecard.dev/): repository hygiene and automated security posture checks.

The catalog below contains 100 **proposed RepoLens feature ideas synthesized** from these product capability areas and RepoLens's existing architecture. They are candidates, not statements that the external products support each item.

## 100 candidate features

### 1. Interoperability
001. Verified findings SARIF 2.1 export
002. CycloneDX SBOM export
003. SPDX SBOM export
004. OpenTelemetry findings correlation
005. VS Code diagnostics feed
006. IDE deep links to findings
007. JSON Lines streaming export
008. Webhook read-only finding notifications
009. Security dashboard CSV export
010. Security findings signed attestation

### 2. Repository analysis
011. Cross-language taint path overlay
012. Dynamic import uncertainty visualization
013. Dead dependency detector
014. Unused API endpoint detector
015. Configuration drift summary
016. Generated code trust markers
017. Source ownership mapping
018. Public API breakage hints
019. Large-file analysis coverage map
020. Reachability-confidence labels

### 3. Pull requests
021. Risk-delta baseline comparator
022. Verified new-issues-only PR gate
023. PR test gap estimator
024. Change hotspot timeline
025. Security-specific changed-code lens
026. Review rationale evidence bundle
027. Ownership-aware reviewer suggestions
028. Risk-based review checklist
029. Historical risky-change patterns
030. Semantically grouped PR findings

### 4. Supply chain
031. Dependency upgrade impact preview
032. License policy diff
033. Typosquat signal explorer
034. Compromised package advisory feed
035. Transitive dependency change graph
036. Package provenance indicator
037. Dependency reachability estimate
038. Vulnerability suppressions audit
039. SBOM freshness indicator
040. Lockfile mismatch analyzer

### 5. Security checks
041. CI action least-privilege audit
042. GitHub workflow injection detector
043. Hardcoded endpoint inventory
044. Security configuration posture scan
045. Auth surface summary
046. Access-control route map
047. Threat model asset inventory
048. Secret detection false-positive feedback
049. Unsafe serialization cross-language match
050. CWE-aligned finding taxonomy

### 6. Operations
051. Scan execution cost dashboard
052. Scanner latency budget breakdown
053. Per-stage cancellation trace
054. Backpressure threshold alerts
055. Artifact retention preview
056. Scan retry reason explorer
057. Quota exhaustion forecast
058. Provider fallbacks visualizer
059. Reliability SLO scorecard
060. Readiness blocker dashboard

### 7. Collaboration
061. Finding owner assignment
062. Team triage queues
063. Finding lifecycle comments
064. Audit log timeline
065. Remediation review checklists
066. Review evidence share links
067. Risk acceptance expiration dates
068. Team-level RBAC permissions
069. Approval policy preview
070. Saved security review templates

### 8. Developer experience
071. Single-click evidence permalink
072. Keyboard-driven finding navigation
073. Accessible graph table alternative
074. Side-by-side scan compare view
075. Finding grouping by component
076. Code search from verified evidence
077. Saved scan filters
078. Portable Markdown review bundle
079. Onboarding demo data
080. Localized finding explanations

### 9. Performance
081. Index progress transparency
082. Incremental graph cache metrics
083. Cross-repo monorepo scope filter
084. Server-side finding pagination cursors
085. Large-scan export limits indicator
086. Storage cost impact estimator
087. Scanner budget policy presets
088. Concurrent job fairness metrics
089. Cache provenance inspector
090. Query latency profiling

### 10. Governance
091. Policy-as-code read-only dry run
092. Org evidence retention policies
093. Export PII minimization report
094. Security audit export checksums
095. Verifiability scoring rubric
096. Compliance evidence mapping
097. Data residency disclosure
098. False-positive calibration dataset
099. Release gate evidence portal
100. Annual feature review decision log

## Simulated senior engineering review

Review perspectives were modeled from five roles: staff backend engineer (domain fit and maintainability), principal application-security engineer (trust and data exposure), staff frontend engineer (discoverability and accessibility), SRE (resource budgets and reliability), and software architect (integration boundaries). These are **reasoning lenses**, not people who attended a meeting or gave approval.

Hard disqualifiers: executes uploaded repository code; bypasses attestation/tenant scoping; writes to default branches or self-merges; relies on LLM output as security truth; disables fail-closed production readiness.

| Finalist | User value / 5 | Existing-fit / 5 | Safety / 5 | Delivery feasibility / 5 | Weighted score / 100 | Review verdict |
|---|---:|---:|---:|---:|---:|---|
| Verified findings SARIF export | 5 | 5 | 5 | 5 | **100** | **Select** |
| Verified new-issues-only PR gate | 5 | 4 | 4 | 2 | 79 | Needs strict baseline authority |
| Risk-delta baseline comparator | 5 | 4 | 4 | 3 | 84 | Follow-up candidate |
| Dependency upgrade impact preview | 4 | 3 | 3 | 2 | 61 | Requires package metadata boundary |
| Ownership-aware reviewer suggestion | 3 | 3 | 4 | 3 | 64 | Lower current priority |
| Security posture visualization | 4 | 4 | 5 | 4 | 83 | Useful but less interoperable |

**Scoring rubric:** value 30%, architectural fit 25%, safety 25%, implementation feasibility 20%. Scores are illustrative comparative judgments; actual benefits need telemetry and user validation. No model voting or automated security verdicts.

### Architecture tournament

| Design | Fit | Security | Operations | Choice |
|---|---|---|---|---|
| **A. Read-only stateless SARIF projector within existing FastAPI report route** | Reuses verified FindingModel and tenant checks | No new privileges or network writes | Bounded synchronous export; zero migration | **Selected** |
| B. Dedicated asynchronous SARIF export job and artifact store | Matches report artifact pattern | More lifecycle and access surface | Extra migrations, leases, storage | Reject for bounded v1 |
| C. External SaaS SARIF converter | Weak fit | New data egress and trust | Vendor dependency | Reject |

## Selected implementation: verified SARIF 2.1.0

- New GET `/api/v1/scans/{scan_id}/report/sarif`, attached to the existing reports router; authenticated owner only.
- Completed scan with recorded immutable commit required; only `OPEN` + `CONFIRMED` findings whose **every** evidence item passes the existing canonical SHA/snippet attestation are eligible.
- Read-only SQL query with eager evidence loading; no untrusted repository code execution, no model calls, no external write, no database migration.
- Deterministic rule IDs, severity mapping, line locations, and partial fingerprints. Repository-relative paths are checked and percent-encoded.
- Descriptions/titles are secret-redacted. **No raw code snippets or model provenance metadata** are exported.
- Bounded at 2,000 candidate findings and 10,000 accepted evidence locations. Limit excess causes a clear 413 instead of producing a deceptively incomplete result.
- Frontend adds an `Export SARIF` button next to the PDF action for completed scans.
- No automatic upload to GitHub code scanning: publishing is a separate, permission-sensitive operator workflow.

### Risks, limitations and follow-ups

- SHA-based evidence attestation proves consistency with stored evidence, **not** a new re-read of source bytes; it inherits the canonical ingestion authority.
- Fingerprints are based on rule, location and line; line moves may change identifiers. A future revision could use a stable semantic symbol identity.
- Rules without line-anchored canonical evidence, resolved/suppressed findings and scans above the export budget are intentionally excluded or refused.
- The export complements, but does not replace, existing production release blockers; a green CI result must not be advertised as host-safe production readiness.
- Tests must be run by repository CI and reviewed before merge.

## Scheduled improvement policy

**Hourly:** inspect the feature branch/PR and its CI, propose or commit minimal scoped fixes only after reproducing failures and adding regression coverage, create/update a reviewable PR, and report results. Do **not** auto-merge, deploy, disable tests or release gates, or fabricate passing checks. If no meaningful defect or improvement is supported, record no change.

**Annually:** resurvey public feature patterns, regenerate at least 100 candidates, run a new simulated multi-role architectural review, and propose a single feature with a branch/PR and tests. This is a decision process; it is not continuous autonomous production deployment.

**Promotion authority:** human code review and the repository's existing test, security and production-readiness gates remain mandatory.
