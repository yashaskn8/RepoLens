# RepoLens feature tournament — 2026-10-31

## Research provenance

This is a curated **100-candidate design backlog**, not a claim that 100 distinct online products were independently verified. Ideas were generated from RepoLens's existing architecture and current public feature patterns documented by GitHub Code Security, Semgrep, SonarQube-style quality gates, OpenSSF Scorecard, and SARIF integration guidance. The references below support *patterns*, not every brainstormed item.

Online references reviewed:
- GitHub [supported SARIF properties](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) and [uploading SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
- GitHub [code security features](https://docs.github.com/en/code-security/getting-started/github-security-features)
- Semgrep [AppSec platform](https://semgrep.dev/products/semgrep-appsec-platform/) and [security workflows](https://semgrep.dev/docs/workflows/overview)
- OpenSSF [Scorecard](https://openssf.org/projects/scorecard/)
- SonarQube-style [quality gates overview](https://docs.digital.gov.krd/devsecops/06-sonarqube.html)

## The 100 candidates

### Finding triage

- **F001** Evidence-backed priority queues
- **F002** Finding deduplication across scans
- **F003** Security debt age dashboard
- **F004** SLA countdown for open findings
- **F005** False-positive feedback memory
- **F006** Finding ownership suggestions
- **F007** Verified findings search DSL
- **F008** Triage reason audit trail
- **F009** Severity trend snapshots
- **F010** Finding suppression expiry

### Pull-request safety

- **F011** Deterministic PR quality gates
- **F012** PR regression-only alert view
- **F013** Changed-line SARIF export
- **F014** Coverage-aware PR review summary
- **F015** Critical-path change labels
- **F016** Route contract drift notifications
- **F017** Breaking API schema comparison
- **F018** Affected owner notifications
- **F019** Review workload estimation
- **F020** PR change evidence bundles

### Interoperability

- **F021** SARIF 2.1.0 export of verified findings
- **F022** CycloneDX SBOM export
- **F023** SPDX SBOM export
- **F024** JUnit test-style report adapter
- **F025** GitLab code quality adapter
- **F026** Bitbucket review export
- **F027** OpenTelemetry trace context export
- **F028** JSONL evidence streaming
- **F029** Issue tracker export bundle
- **F030** IDE diagnostics protocol output

### Supply-chain intelligence

- **F031** New dependency risk diffs
- **F032** Package provenance explanation
- **F033** Transitive dependency impact map
- **F034** License obligation alerts
- **F035** Unpinned action drift alerts
- **F036** Known-exploited CVE prioritization
- **F037** Dependency upgrade what-if analysis
- **F038** Maintainer churn signals
- **F039** Lockfile integrity discrepancy checks
- **F040** Dependency policy exceptions

### Evidence and trust

- **F041** Evidence provenance diff between scans
- **F042** Snapshot attestation audit viewer
- **F043** Coverage gap explainability
- **F044** Reasoning claim to AST trail
- **F045** Tamper-evident report manifests
- **F046** Evidence freshness indicators
- **F047** Stale evidence revocation warnings
- **F048** Cross-scanner agreement map
- **F049** Counterevidence collection
- **F050** Verified vs inferred claim overlay

### Developer experience

- **F051** VS Code findings extension
- **F052** CLI one-command SARIF download
- **F053** Inline source evidence viewer
- **F054** Scan compare timeline
- **F055** Saved filters and shared views
- **F056** Repository onboarding checklist
- **F057** Keyboard-first triage
- **F058** Accessible graph navigation
- **F059** One-click finding deep links
- **F060** Localized report templates

### Operations

- **F061** Scan queue ETA estimates
- **F062** Job lease health dashboard
- **F063** Partial scanner outage alerts
- **F064** Quota utilization forecast
- **F065** Scan cost accounting
- **F066** Analysis cache savings panel
- **F067** Worker saturation metrics
- **F068** Artifact retention forecast
- **F069** Automated failure taxonomy dashboard
- **F070** Multi-tenant load shedding metrics

### Remediation

- **F071** Patch precondition explanation
- **F072** Safe rollback instructions bundle
- **F073** Remediation owner routing
- **F074** Fix plan dependency ordering
- **F075** Patch conflict early warning
- **F076** Fix effort estimates
- **F077** Verified fix regression comparison
- **F078** Approval expiry reminders
- **F079** PR delivery dry-run preview
- **F080** Change risk before-after diff

### Governance

- **F081** Repository policy as code
- **F082** Compliance evidence export
- **F083** Audit log immutable receipt
- **F084** Approval matrix templates
- **F085** Risk acceptance expiration
- **F086** Exception-review workflow
- **F087** Evidence retention policy viewer
- **F088** Tenant policy inheritance
- **F089** Human reviewer acknowledgement
- **F090** Policy drift reporting

### Research and insights

- **F091** Annual competitive feature review
- **F092** Rule precision benchmark board
- **F093** False-positive cohort analysis
- **F094** Security trend forecasting
- **F095** Developer feedback pulse
- **F096** Opportunity scoring notebook
- **F097** Architecture decision record generator
- **F098** Differential scanner evaluation
- **F099** Incident postmortem evidence package
- **F100** Repository health score explanation

## Simulated senior-engineering review (not an actual human panel)

The following five *lenses* were simulated: staff application-security engineer, principal backend architect, staff SRE, senior frontend developer, and product-minded tech lead. Scores are editorial assessments, not empirical research or independent human votes.

Score each criterion from 1–5, weighted **value 30%, differentiation 20%, existing-architecture fit 20%, safety 20%, shipability 10%**. Prioritize safe reuse of the current evidence verifier rather than adding an agent or another source of truth.

| Finalist | Value | Differentiation | Fit | Safety | Shipability | Weighted / 5 |
|---|---:|---:|---:|---:|---:|---:|
| **F021 Verified SARIF export** | 5 | 4 | 5 | 5 | 5 | **4.8** |
| F081 Repository policy as code | 5 | 5 | 3 | 4 | 3 | 4.2 |
| F011 Deterministic PR quality gate | 5 | 4 | 4 | 4 | 4 | 4.3 |
| F041 Evidence provenance diff | 4 | 5 | 3 | 4 | 3 | 3.9 |
| F031 New dependency risk diffs | 4 | 4 | 3 | 3 | 3 | 3.5 |
| F051 VS Code findings extension | 4 | 3 | 2 | 4 | 2 | 3.1 |

Decision: F021. A portable export lets users consume the verified evidence already produced by RepoLens in other tools, without giving the exporter GitHub write authority or executing hostile repository code.

### Five review challenges and resolution

1. **AppSec:** Never publish speculative or non-canonical results as security alerts. **Resolution:** gate on CONFIRMED evidence with the current immutable commit attestation; skip suppression/resolution.
2. **Backend:** No extra database or asynchronous worker. **Resolution:** a deterministic SARIF projection behind the existing authenticated owned-scan query.
3. **SRE:** Large exports can exhaust resources or silently truncate. **Resolution:** bounded 5,000 results and 100 related locations, fail with explicit 413.
4. **Frontend:** Users need discoverability without a new workflow. **Resolution:** an Export SARIF link beside Markdown/JSON exports.
5. **Tech lead:** Do not weaken the product's zero-execution guarantees. **Resolution:** server-side serialization only; no model calls, writes to analyzed repositories, code execution, or credential expansion.

## Architecture battle

| Alternative | Advantages | Risks | Decision |
|---|---|---|---|
| **A. In-process deterministic formatter + owned GET route** | Reuses FastAPI auth, SQLAlchemy, canonical attestation, no new runtime | Large response memory requires bounds | **Winner** |
| B. Separate report microservice and queue | Independently scalable | Duplicates authentication, operational overhead, freshness races | Reject for first version |
| C. Model-generated SARIF transformer | Flexible prose | Hallucinated locators, nondeterminism, model cost, exposure risk | Reject |
| D. Browser-side transformation of finding JSON | No backend projection | Pagination omissions, weaker uniform evidence gate, potential snippet exposure | Reject |

### Selected data flow

`Authenticated GET /api/v1/scans/{scan_id}/sarif` → `get_owned_scan_or_404` → `require COMPLETED + exact commit` → `stream OPEN CONFIRMED rows in bounded batches` → `canonical evidence attestation check` → `safe relative path + stable rule/fingerprint` → `SARIF 2.1.0 response (no-store)`.

**Truthfulness:** A zero-alert SARIF file does *not* prove a repository has no vulnerabilities. Only the completed scan's canonically confirmed open findings are exported. Omitted candidates, partial scanner coverage, and suppressed findings must never be misrepresented as complete coverage.

**Limitations:** The first version is a download, not an automatic upload to GitHub code scanning. No new GitHub write permission is required. We deliberately avoid changing existing remediation or verifier authority.

## Definition of done and continued evolution

- Deterministic unit cases: ordering/fingerprints, no raw code snippets, exclude unverified, malformed paths, stale commit, suppressed findings, bound failures.
- API regression cases: authenticated access, 404 for a different owner, 409 for incomplete scan or missing commit, proper download headers.
- Existing frontend type-check/lint/build and backend suite pass in PR CI before merging.
- Main branch is not modified without human review. No autonomous untested fixes, auto-merges, or dangerous execution of repository-supplied scripts.
- Re-run the annual feature tournament with fresh vendor documentation, 100 candidates, scored tradeoffs, an ADR, and a reviewed implementation PR.
- Hourly maintenance should inspect existing CI/test failures and create limited fixes on a review branch only when independently reproducible; otherwise report a diagnostic issue. Do not claim production-readiness without validated checks and deployment evidence.
