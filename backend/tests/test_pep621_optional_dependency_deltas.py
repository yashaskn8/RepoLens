"""PEP 621 optional dependency groups must contribute to change evidence."""

import pytest

from app.analysis.diff_engine import ChangeDiffEngine, _parse_pyproject_toml


def test_optional_dependencies_are_parsed_with_group_identity():
    manifest = (
        '[project]\nname = "demo"\n'
        'dependencies = ["httpx>=0.27"]\n'
        '[project.optional-dependencies]\n'
        'security = ["cryptography>=43", "httpx>=0.28"]\n'
        'test = ["pytest>=8"]\n'
    )
    assert _parse_pyproject_toml(manifest) == {
        "httpx": ">=0.27",
        "cryptography[security]": ">=43",
        "httpx[security]": ">=0.28",
        "pytest[test]": ">=8",
    }


def test_optional_direct_references_do_not_expose_credentials():
    parsed = _parse_pyproject_toml(
        '[project]\nname = "demo"\n'
        '[project.optional-dependencies]\n'
        'internal = ["private-lib @ https://user:secret@example.com/lib.whl"]\n'
    )
    assert parsed["private-lib[internal]"].startswith("DIRECT_REFERENCE_SHA256:")
    assert "secret" not in str(parsed)


def test_invalid_optional_groups_fail_closed_instead_of_hiding_missing_evidence():
    with pytest.raises(ValueError):
        _parse_pyproject_toml(
            '[project]\\nname = "demo"\\n'
            'dependencies = ["httpx>=0.27"]\\n'
            '[project.optional-dependencies]\\n'
            'invalid = "not a list"\\n'
        )

def test_optional_dependency_deltas_are_reported(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n'
        '[project.optional-dependencies]\nsecurity = ["cryptography>=42"]\n',
        encoding="utf-8",
    )
    (head / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n'
        '[project.optional-dependencies]\n'
        'security = ["cryptography>=43"]\n'
        'test = ["pytest>=8"]\n',
        encoding="utf-8",
    )
    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )
    deltas = {(d.package_name, d.change_type) for d in result.dependency_deltas}
    assert ("cryptography[security]", "UPDATED") in deltas
    assert ("pytest[test]", "ADDED") in deltas
