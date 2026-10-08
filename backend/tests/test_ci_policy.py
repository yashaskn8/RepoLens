"""Release-workflow invariants that must remain true in required CI.

These tests deliberately validate repository-owned CI policy rather than external
GitHub settings. Branch protection, signatures, and secret-backed live runs
remain separate governance/live-evidence responsibilities.
"""

from pathlib import Path
import re

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_SHA_REF = re.compile(r"^[0-9a-f]{40}$")
_USES = re.compile(r"\buses:\s*([^@\s]+)@([^\s#]+)")


def test_third_party_github_actions_are_immutably_pinned():
    offenders: list[str] = []
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for action, ref in _USES.findall(text):
            if action.startswith("./"):
                continue
            if not _SHA_REF.fullmatch(ref):
                offenders.append(f"{path.relative_to(_REPO_ROOT)}: {action}@{ref}")
    assert offenders == [], "Mutable GitHub Action refs: " + ", ".join(offenders)


def test_required_ci_executes_real_repository_controlled_infrastructure_gates():
    ci = (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    required_tokens = (
        "pgvector/pgvector:0.8.6-pg16@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b",
        "redis:7.2.16-alpine@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0",
        "REPOLENS_POSTGRES_TEST_URL:",
        "TEST_POSTGRES_URL:",
        "PGVECTOR_TEST_URL:",
        'REPOLENS_POSTGRES_TEST_ALLOW_SCHEMA_RESET: "1"',
        'ENABLE_PGVECTOR: "true"',
        "REDIS_URL:",
        "uv sync --locked --extra dev --extra observability",
        "uv sync --locked --extra dev --extra observability --extra production",
        "tests/test_postgres_integration.py",
        "tests/test_pgvector_index.py",
        "tests/test_checkpoint_recovery.py",
        "tests/test_redis_service.py",
        "-m integration -q",
    )
    missing = [token for token in required_tokens if token not in ci]
    assert missing == [], "Required CI infrastructure gate drifted: " + ", ".join(missing)


def test_integration_service_environment_is_scoped_to_the_integration_step():
    ci = (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    before_steps = ci.split("    steps:", 1)[0]
    integration_keys = (
        "REPOLENS_POSTGRES_TEST_URL:",
        "TEST_POSTGRES_URL:",
        "PGVECTOR_TEST_URL:",
        "REPOLENS_POSTGRES_TEST_ALLOW_SCHEMA_RESET:",
        "ENABLE_PGVECTOR:",
        "REDIS_URL:",
    )
    leaked = [token for token in integration_keys if token in before_steps]
    assert leaked == [], "Integration-only environment leaked into baseline suite: " + ", ".join(leaked)

    marker = "- name: Run required PostgreSQL, pgvector and Redis integration gate"
    assert marker in ci
    gate = ci.split(marker, 1)[1]
    missing = [token for token in integration_keys if token not in gate]
    assert missing == [], "Integration gate is missing scoped environment: " + ", ".join(missing)


def test_readme_does_not_publish_a_stale_backend_test_count():
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"Current backend suite[\s*]*:\s*[\d,]+ tests collected", readme) is None


def test_release_documentation_does_not_claim_unverified_production_readiness():
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    architecture = (_REPO_ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
    threat_model = (_REPO_ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    evidence_pack = (_REPO_ROOT / "docs" / "phase9" / "RELEASE_EVIDENCE_PACK.md").read_text(encoding="utf-8")

    assert "no published GitHub Release object" in readme
    assert "manual production-validation workflow has not been executed" in readme
    assert "not a current release-readiness claim" in architecture
    assert "not a current release-readiness claim" in threat_model
    assert "NOT CURRENT ATTESTATION" in evidence_pack
    assert "not a current certification" in evidence_pack


def test_ci_uses_locked_python_resolution_and_rejects_floating_installs():
    backend = _REPO_ROOT / "backend"
    pyproject = (backend / "pyproject.toml").read_text(encoding="utf-8")
    assert 'required-version = "==0.12.10"' in pyproject
    assert (backend / "uv.lock").is_file()
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert "astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4" in text
        assert "uv sync --locked" in text
        assert "pip install -e" not in text


def test_service_images_are_digest_pinned():
    ci = (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    image_lines = [line.strip() for line in ci.splitlines() if line.strip().startswith("image:")]
    assert len(image_lines) == 2
    assert all("@sha256:" in line for line in image_lines)
    assert all(re.search(r"@sha256:[0-9a-f]{64}$", line) for line in image_lines)


def test_windows_path_security_lane_runs_the_platform_sensitive_test():
    ci = (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    lane = ci.split("  windows-path-security:", 1)[1]
    assert "runs-on: windows-latest" in lane
    assert "test_manifest_skips_symlink_file_without_reading_external_target" in lane
    assert "test_corpus_loader_rejects_linked_case_file" in lane
    assert "test_post_registration_symlink_swap_fails_closed" in lane


def test_secret_backed_manual_jobs_are_main_only_and_secrets_are_step_scoped():
    workflow = (_WORKFLOWS / "production-validation.yml").read_text(encoding="utf-8")
    secret_jobs = (
        "postgres", "live-providers", "agent-live-evals", "agent-system-comparison",
        "redis", "deployment-smoke",
    )
    for index, job_name in enumerate(secret_jobs):
        marker = f"  {job_name}:\n"
        assert marker in workflow
        start = workflow.index(marker) + len(marker)
        end = min(
            (pos for pos in (workflow.find("\n  " + next_name + ":", start) for next_name in secret_jobs) if pos != -1),
            default=len(workflow),
        )
        # The next job may not be in secret_jobs, so bound this section at the next
        # top-level job declaration instead.
        next_job = re.search(r"\n  [a-z0-9-]+:\n", workflow[start:])
        if next_job:
            end = start + next_job.start()
        section = workflow[start:end]
        assert "if: ${{ github.ref == 'refs/heads/main'" in section, job_name
        assert not re.search(r"(?m)^    env:\s*$", section), (
            f"Job-level secret environment remains in {job_name}"
        )
