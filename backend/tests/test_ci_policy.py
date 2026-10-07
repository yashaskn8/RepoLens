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
        "pgvector/pgvector:0.8.6-pg16",
        "redis:7.2.16-alpine",
        "REPOLENS_POSTGRES_TEST_URL:",
        "TEST_POSTGRES_URL:",
        "PGVECTOR_TEST_URL:",
        'REPOLENS_POSTGRES_TEST_ALLOW_SCHEMA_RESET: "1"',
        'ENABLE_PGVECTOR: "true"',
        "REDIS_URL:",
        'pip install -e ".[dev,observability]"',
        'pip install -e ".[production]"',
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
