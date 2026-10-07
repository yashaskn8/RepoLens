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
        'pip install -e ".[dev,observability,production]"',
        "tests/test_postgres_integration.py",
        "tests/test_pgvector_index.py",
        "tests/test_checkpoint_recovery.py",
        "tests/test_redis_service.py",
        "-m integration -q",
    )
    missing = [token for token in required_tokens if token not in ci]
    assert missing == [], "Required CI infrastructure gate drifted: " + ", ".join(missing)
