# ChainBrain supply-chain risk assessment in RepoLens

ChainBrain is integrated into the existing RepoLens repository scan engine.
Its results appear under **Dependencies → ChainBrain · Supply-Chain Risk
Signals** and in scan metadata at \`model_metadata.supply_chain\`.
It does **not** install dependencies, invoke package scripts, or query an
external package registry. The signal engine is designed to run without
labeled training data.

## Supported assessment (offline policy v1)

* npm \`package.json\`: direct declared dependency selectors, lifecycle
  scripts (\`preinstall\`, \`install\`, \`postinstall\`, \`prepublish\`,
  \`prepare\`), and bounded locally referenced install-script source.
* npm \`package-lock.json\` / \`npm-shrinkwrap.json\` **v2/v3**:
  package locators (including nested/transitive packages), remote artifact
  origins, presence of an integrity digest, install hook markers, and
  bounded dependency-edge counts.
* Python \`requirements*.txt\` and PEP 621 \`pyproject.toml\`
  \`project.dependencies\`: exact-version hygiene, remote sources and
  insecure index/URL indicators. Other Python packaging formats and complex
  pip directives are not claimed to be supported.
* Deterministic, documented rule IDs: \`CB-NPM-001\` through
  \`CB-NPM-009\`, \`CB-PY-001\` through \`CB-PY-003\`, and \`CB-CODE-001\`.
  Each signal includes a bounded file/line reference, explanation,
  heuristic score, mitigation, and source ecosystem.

## What ChainBrain **does not** conclude

A heuristic score is **not** a probability of malware. Presence of an
install hook, mutable version range, or nonstandard registry is not
inherently malicious. Lack of findings is not proof of package safety.

The initial offline analyzer **does not verify**:
maintainer ownership or recent handoffs, download spikes, publish times,
malicious package labels, known vulnerabilities from live OSV, an
authoritative SBOM, signed provenance, or third-party installation-script
contents. These require independently controlled data sources. The
existing OSV scanner may supply its own separate vulnerability coverage
when available and isolated.

Descriptions and mitigations are **deterministic and evidence-grounded**.
An optional **AI Explanation Layer** is available behind the disabled-by-default
`CHAINBRAIN_AI_EXPLANATIONS_ENABLED` deployment flag. The user must
explicitly request one narrative from the Dependencies tab; the authenticated
endpoint requires CSRF and enforces a durable per-user daily quota (default
10). It sends only a bounded allowlisted detector signal to the governed
model gateway, never scripts, tokens or arbitrary repository code. Invalid
or failed model replies return a deterministic fallback. Valid model text
is labeled **model-generated and unverified**; it cannot alter findings,
scoring, or verified evidence. A production operator must configure the
model gateway, quotas, credentials and appropriate provider egress before
enabling this optional capability. AI enrichment remains off otherwise.

## Security and incomplete assessment

Input files are read from the ingested manifest with size limits and
SHA-256 matching. No source links are followed. The analyzer enforces
file, package and edge caps and emits \`INVALID_OUTPUT\` on unsupported,
truncated or malformed dependency metadata rather than returning a false
clean result. The UI explicitly displays assessment status.

The existing production acquisition and external scanner isolation gates
remain in effect. This analyzer does not bypass those gates or constitute
verification of OS-level network/CPU/disk confinement.

## Operating checks

Run \`python -m pytest tests/test_chainbrain_supply_chain.py -q\` from
\`backend/\`, plus the full RepoLens CI pipeline. Exercise a completed
scan with npm/Python manifests and inspect Dependencies. Verify the UI
distinguishes risk signals from confirmed vulnerability findings and
explicitly shows incomplete assessments.
