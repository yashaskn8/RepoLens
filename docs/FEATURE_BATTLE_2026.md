# RepoLens Feature Battle — 31 October 2026

> A **simulated** senior-software-engineer decision panel; no human engineers were interviewed or employed. These are 100 distinct feature *ideas* synthesized from public engineering guidance and RepoLens's current code. They are **not** 100 vendor features individually verified or 100 working prototypes. The numerical ratings are subjective engineering estimates, not empirical benchmarks.

## Grounding and current project constraints

- [OpenSSF Scorecard](https://scorecard.dev/) explicitly evaluates dangerous workflows, pinned dependencies, and token permissions.
- [GitHub script-injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections) documents risks of untrusted workflow contexts.
- [GitHub dependency review](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review) covers vulnerable package changes.
- [GitHub security features](https://docs.github.com/en/code-security/getting-started/github-security-features) details alerts, code scanning, and artifact attestations.
- [OWASP CI/CD Top 10](https://owasp.org/projects/top-10-cicd-security-risks) covers pipeline permissions, supply chain abuse, and artifact integrity.
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) recommends controlled change management and limiting CI privileges.
- Repository constraints: `AGENTS.md`, `backend/app/analysis/service.py`, `backend/app/analysis/core.py`, and the existing release gate. Never execute untrusted source, never bypass required approval or production release blockers.

## Panel scoring model

Five simulated senior engineering perspectives independently score 1 (weak) to 5 (strong):
**Product**: differentiated user value; **Backend**: practical reuse of mature components; **Frontend**: usable delivery path; **Security**: safe and evidence-grounded; **SRE**: cheap, testable, operationally contained.
Score is the sum, maximum 25. Close scores are not statistically significant; final selection uses risk and deliverability tie-breakers.

## All 100 candidates (round 1)

| # | Candidate feature | Area | Product | Backend | Frontend | Security | SRE | /25 |
|---:|---|---|---:|---:|---:|---:|---:|---:|
| 1 | Workflow Supply-Chain Lens | CI/CD hardening | 5 | 5 | 5 | 5 | 4 | **24** |
| 2 | GitHub token least-privilege graph | CI/CD hardening | 5 | 4 | 5 | 4 | 4 | **22** |
| 3 | Reusable workflow trust audit | CI/CD hardening | 4 | 4 | 5 | 4 | 4 | **21** |
| 4 | Runner hardening hints | CI/CD hardening | 4 | 4 | 5 | 4 | 4 | **21** |
| 5 | Artifact provenance audit | CI/CD hardening | 4 | 4 | 5 | 4 | 4 | **21** |
| 6 | Permission-reduction patch suggestions | CI/CD hardening | 5 | 3 | 5 | 3 | 4 | **20** |
| 7 | Workflow matrix explosion warning | CI/CD hardening | 3 | 5 | 3 | 5 | 4 | **20** |
| 8 | Action release freshness | CI/CD hardening | 3 | 4 | 4 | 4 | 4 | **19** |
| 9 | OIDC trust boundary reviewer | CI/CD hardening | 4 | 3 | 5 | 3 | 4 | **19** |
| 10 | Script-injection evidence tracker | CI/CD hardening | 5 | 4 | 5 | 4 | 4 | **22** |
| 11 | Transitive dependency exposure map | Dependency intelligence | 5 | 3 | 5 | 4 | 4 | **21** |
| 12 | Dependency upgrade impact simulator | Dependency intelligence | 4 | 3 | 4 | 4 | 4 | **19** |
| 13 | SBOM inventory diff | Dependency intelligence | 4 | 4 | 4 | 4 | 4 | **20** |
| 14 | License change detector | Dependency intelligence | 3 | 4 | 3 | 4 | 4 | **18** |
| 15 | Malicious-package advisory watch | Dependency intelligence | 4 | 3 | 5 | 3 | 4 | **19** |
| 16 | Package maintainer change signal | Dependency intelligence | 3 | 3 | 4 | 3 | 4 | **17** |
| 17 | Lockfile drift detector | Dependency intelligence | 4 | 5 | 4 | 5 | 4 | **22** |
| 18 | Dependency pinning confidence | Dependency intelligence | 4 | 4 | 4 | 4 | 4 | **20** |
| 19 | Exploitability evidence triage | Dependency intelligence | 5 | 2 | 5 | 3 | 3 | **18** |
| 20 | Dependency freshness trends | Dependency intelligence | 3 | 4 | 3 | 4 | 4 | **18** |
| 21 | PR risk explanation timeline | Pull-request intelligence | 5 | 4 | 4 | 4 | 4 | **21** |
| 22 | Review comment deduplicator | Pull-request intelligence | 4 | 4 | 4 | 5 | 4 | **21** |
| 23 | Cross-PR semantic conflict detector | Pull-request intelligence | 4 | 2 | 4 | 3 | 3 | **16** |
| 24 | Breaking API contract review | Pull-request intelligence | 5 | 4 | 5 | 4 | 4 | **22** |
| 25 | Changed secret-handling boundary finder | Pull-request intelligence | 4 | 4 | 5 | 4 | 4 | **21** |
| 26 | Missing test evidence guide | Pull-request intelligence | 4 | 4 | 4 | 4 | 4 | **20** |
| 27 | Deployment configuration diff review | Pull-request intelligence | 4 | 4 | 5 | 4 | 4 | **21** |
| 28 | Ownership-aware change triage | Pull-request intelligence | 3 | 4 | 3 | 4 | 4 | **18** |
| 29 | PR regression hypothesis builder | Pull-request intelligence | 4 | 3 | 4 | 4 | 3 | **18** |
| 30 | Risk heatmap for changed files | Pull-request intelligence | 4 | 4 | 4 | 4 | 4 | **20** |
| 31 | Service boundary dependency viewer | Architecture insights | 4 | 3 | 4 | 4 | 4 | **19** |
| 32 | Circular dependency evolution | Architecture insights | 4 | 4 | 4 | 4 | 4 | **20** |
| 33 | Architectural drift alerts | Architecture insights | 5 | 4 | 4 | 4 | 4 | **21** |
| 34 | Dead integration route signal | Architecture insights | 4 | 3 | 4 | 4 | 4 | **19** |
| 35 | Graph search saved queries | Architecture insights | 4 | 5 | 3 | 5 | 4 | **21** |
| 36 | API version lifecycle map | Architecture insights | 4 | 4 | 4 | 4 | 4 | **20** |
| 37 | Schema compatibility report | Architecture insights | 5 | 3 | 4 | 4 | 4 | **20** |
| 38 | Change hotspot topology | Architecture insights | 4 | 4 | 4 | 4 | 4 | **20** |
| 39 | Layering policy violations | Architecture insights | 4 | 4 | 4 | 4 | 4 | **20** |
| 40 | Repository design debt score | Architecture insights | 3 | 4 | 3 | 3 | 4 | **17** |
| 41 | Readiness blocker dashboard | Reliability and operations | 5 | 5 | 4 | 5 | 4 | **23** |
| 42 | Long-running scan stall detector | Reliability and operations | 5 | 4 | 5 | 5 | 4 | **23** |
| 43 | Job queue health timeline | Reliability and operations | 4 | 4 | 4 | 4 | 4 | **20** |
| 44 | SLO error-budget explainer | Reliability and operations | 4 | 4 | 4 | 4 | 4 | **20** |
| 45 | Replay-safe recovery console | Reliability and operations | 5 | 3 | 5 | 4 | 4 | **21** |
| 46 | Resource-quota forecasting | Reliability and operations | 4 | 4 | 5 | 4 | 4 | **21** |
| 47 | Backpressure diagnostics | Reliability and operations | 4 | 4 | 5 | 4 | 4 | **21** |
| 48 | Read-only failure trend digest | Reliability and operations | 4 | 5 | 4 | 5 | 4 | **22** |
| 49 | Operator incident report export | Reliability and operations | 4 | 4 | 4 | 4 | 4 | **20** |
| 50 | Dependency outage degradation map | Reliability and operations | 4 | 3 | 4 | 4 | 4 | **19** |
| 51 | Authentication trust-boundary map | Security and trust | 5 | 3 | 5 | 4 | 4 | **21** |
| 52 | Secret exposure risk contextualization | Security and trust | 5 | 3 | 5 | 4 | 4 | **21** |
| 53 | Tenant-isolation regression matrix | Security and trust | 5 | 4 | 5 | 4 | 4 | **22** |
| 54 | Untrusted input taint path explorer | Security and trust | 5 | 2 | 5 | 3 | 3 | **18** |
| 55 | MCP tool trust policy audit | Security and trust | 4 | 4 | 5 | 4 | 4 | **21** |
| 56 | Unsafe deserialization signature catalog | Security and trust | 4 | 4 | 5 | 4 | 4 | **21** |
| 57 | Data egress destination inventory | Security and trust | 5 | 3 | 5 | 4 | 4 | **21** |
| 58 | Risky infrastructure configuration lint | Security and trust | 5 | 4 | 5 | 4 | 4 | **22** |
| 59 | Secret-redaction coverage check | Security and trust | 5 | 3 | 5 | 5 | 4 | **22** |
| 60 | Finding provenance drift detector | Security and trust | 5 | 4 | 5 | 4 | 4 | **22** |
| 61 | One-click evidence navigation | Developer experience | 5 | 4 | 3 | 5 | 4 | **21** |
| 62 | Findings keyboard workflow | Developer experience | 4 | 5 | 3 | 5 | 4 | **21** |
| 63 | Remediation comparison view | Developer experience | 5 | 4 | 4 | 5 | 4 | **22** |
| 64 | Saved analysis presets | Developer experience | 4 | 5 | 3 | 5 | 4 | **21** |
| 65 | Finding suppression request workflow | Developer experience | 4 | 4 | 4 | 4 | 4 | **20** |
| 66 | Report diff between scans | Developer experience | 5 | 4 | 4 | 5 | 4 | **22** |
| 67 | Role-specific dashboard layouts | Developer experience | 4 | 4 | 3 | 4 | 4 | **19** |
| 68 | Shareable redacted finding snapshot | Developer experience | 4 | 4 | 5 | 4 | 4 | **21** |
| 69 | Offline read-only report bundle | Developer experience | 4 | 4 | 5 | 4 | 4 | **21** |
| 70 | A11y contrast and navigation audit | Developer experience | 5 | 5 | 4 | 5 | 4 | **23** |
| 71 | Confidence calibration dashboard | Evaluation quality | 5 | 4 | 5 | 5 | 4 | **23** |
| 72 | Evidence-grounding failure cases | Evaluation quality | 5 | 4 | 5 | 5 | 4 | **23** |
| 73 | False-positive feedback loop | Evaluation quality | 5 | 3 | 5 | 4 | 4 | **21** |
| 74 | Holdout dataset leakage checker | Evaluation quality | 4 | 4 | 5 | 4 | 4 | **21** |
| 75 | Detector regression corpus manager | Evaluation quality | 5 | 4 | 5 | 5 | 4 | **23** |
| 76 | Prompt-version comparison view | Evaluation quality | 4 | 4 | 4 | 4 | 4 | **20** |
| 77 | Evaluation cost observability | Evaluation quality | 4 | 4 | 4 | 4 | 4 | **20** |
| 78 | Deterministic-vs-LLM agreement audit | Evaluation quality | 4 | 4 | 5 | 4 | 4 | **21** |
| 79 | Reviewer disagreement tracker | Evaluation quality | 4 | 3 | 4 | 4 | 4 | **19** |
| 80 | Source-line citation stability score | Evaluation quality | 5 | 4 | 5 | 4 | 4 | **22** |
| 81 | Branch drift verification dashboard | Governance and delivery | 5 | 4 | 5 | 5 | 4 | **23** |
| 82 | Approval expiry reminders | Governance and delivery | 4 | 5 | 5 | 5 | 4 | **23** |
| 83 | Audit log export with redaction | Governance and delivery | 5 | 4 | 5 | 4 | 4 | **22** |
| 84 | Review gating reason explorer | Governance and delivery | 5 | 4 | 5 | 5 | 4 | **23** |
| 85 | Draft-only remediation queue | Governance and delivery | 5 | 4 | 5 | 5 | 4 | **23** |
| 86 | Change control policy preview | Governance and delivery | 4 | 4 | 5 | 4 | 4 | **21** |
| 87 | Security exception expiration | Governance and delivery | 4 | 4 | 4 | 5 | 4 | **21** |
| 88 | Release gate comparison | Governance and delivery | 5 | 4 | 5 | 4 | 4 | **22** |
| 89 | Approval history visualizer | Governance and delivery | 4 | 4 | 4 | 4 | 4 | **20** |
| 90 | Human override explanation log | Governance and delivery | 4 | 4 | 5 | 5 | 4 | **22** |
| 91 | SARIF report compatibility | Ecosystem and reporting | 5 | 4 | 4 | 4 | 4 | **21** |
| 92 | GitLab merge-request reader | Ecosystem and reporting | 4 | 2 | 3 | 3 | 3 | **15** |
| 93 | Bitbucket pull-request reader | Ecosystem and reporting | 3 | 2 | 3 | 3 | 3 | **14** |
| 94 | Jira issue linkage | Ecosystem and reporting | 3 | 3 | 3 | 4 | 3 | **16** |
| 95 | Webhook event digest | Ecosystem and reporting | 4 | 4 | 4 | 4 | 4 | **20** |
| 96 | Markdown security scorecard | Ecosystem and reporting | 4 | 5 | 4 | 5 | 4 | **22** |
| 97 | Repository trend comparisons | Ecosystem and reporting | 4 | 4 | 4 | 4 | 4 | **20** |
| 98 | Policy-as-code export | Ecosystem and reporting | 5 | 3 | 5 | 4 | 3 | **20** |
| 99 | Software attestations evidence export | Ecosystem and reporting | 4 | 3 | 5 | 4 | 3 | **19** |
| 100 | Public API for findings retrieval | Ecosystem and reporting | 4 | 4 | 4 | 4 | 4 | **20** |

## Top 12 (round 2)

| Rank | Candidate | Score /25 | Outcome |
|---:|---|---:|---|
| 1 | Workflow Supply-Chain Lens | 24 | WINNER |
| 2 | Readiness blocker dashboard | 23 | SHORTLIST |
| 3 | Long-running scan stall detector | 23 | SHORTLIST |
| 4 | A11y contrast and navigation audit | 23 | SHORTLIST |
| 5 | Confidence calibration dashboard | 23 | SHORTLIST |
| 6 | Evidence-grounding failure cases | 23 | SHORTLIST |
| 7 | Detector regression corpus manager | 23 | SHORTLIST |
| 8 | Branch drift verification dashboard | 23 | SHORTLIST |
| 9 | Approval expiry reminders | 23 | SHORTLIST |
| 10 | Review gating reason explorer | 23 | SHORTLIST |
| 11 | Draft-only remediation queue | 23 | SHORTLIST |
| 12 | GitHub token least-privilege graph | 22 | SHORTLIST |

Tie-breakers: prefer capabilities that can be implemented without new credentials, cloud calls, external executables, untrusted-code execution, or migrations; penalize duplicate current features and irreversible write-side effects. Existing capabilities (for example, readiness gates and detector evaluation) can score highly but are less novel.

**Winner: Workflow Supply-Chain Lens (24/25)**. It adds a practical type of evidence to normal repository scans without deploying a separate service or altering approval gates.

## Architecture battle (round 3)

| Design | Correctness /5 | Existing integration /5 | Security /5 | Operations /5 | Evolvability /5 | Total |
|---|---:|---:|---:|---:|---:|---:|
| Built-in deterministic read-only scanner | 4 | 5 | 5 | 5 | 4 | **23** |
| External containerized scanner microservice | 4 | 2 | 3 | 2 | 4 | 15 |
| Hosted LLM-only workflow review | 2 | 3 | 2 | 2 | 3 | 12 |
| Standalone GitHub Actions job with no RepoLens integration | 3 | 1 | 3 | 4 | 3 | 14 |

**Chosen architecture:** `.github/workflows/*.yml|*.yaml` in the *already acquired repository snapshot* → bounded, no-execution, read-only source inspection → normalized `StaticFinding` with line evidence → `ScannerResult` → existing `RepositoryIntelligenceService` evidence store. The service reports `INVALID_OUTPUT` rather than fabricating a clean result if a workflow file cannot be safely inspected.

## Implemented v1

- Flags explicit `permissions: write-all`.
- Flags mutable remote GitHub Actions refs (not a 40-hex commit hash) and Docker action images (not a sha256 digest).
- Flags a **contextual** `pull_request_target` + checkout + PR-head-ref combination for human review, never claiming confirmed exploitation.
- Ignores comments and multiline YAML block content; does not execute or fetch anything.
- Bounds directory entries, YAML file count, individual and total byte reads, and result count.
- Rejects directory/file symlinks, non-regular workflow files, and invalid UTF-8. An incomplete scan is not "clean".
- Provides focused regression tests for safe/pinned input, risky input, confounding comments, symlinks, oversized inputs, and passive operation.

**Known limits (do not overclaim):** v1 uses conservative line-based source checks, not a full GitHub Actions YAML interpreter. YAML aliases, dynamic references, multi-job trust flow, inherited permissions, reusable workflows, and advanced expression semantics are not fully covered. It is supplementary evidence, not a substitute for GitHub/OpenSSF tools or human security review. No automated remediation, automatic deploy, or default-branch writes are implemented.

## Hourly maintenance contract

Use the hourly ChatGPT task for one year to review the feature branch and CI/PR status, look for new bugs/security guidance, and **only propose or commit incremental safe changes on the feature branch** when tests or evidence justify them and permissions/tools are available. Always report what was and wasn't verified. Never merge, deploy, force-push, weaken the release gate, run untrusted repository code, or silently modify `main`. Human approval and required CI checks remain mandatory. The scheduled task is a review/improvement attempt, not a guarantee of a code change every hour.
