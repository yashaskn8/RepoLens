"""PEP 621 dependency changes must be represented in structural PR evidence."""

from app.analysis.diff_engine import ChangeDiffEngine, _parse_pyproject_toml


def test_pep621_dependency_list_is_parsed():
    manifest = """
[project]
name = "example"
dependencies = [
  "fastapi>=0.110",
  "httpx[http2]>=0.27",
  "urllib3",
]
"""
    assert _parse_pyproject_toml(manifest) == {
        "fastapi": ">=0.110",
        "httpx": "[http2]>=0.27",
        "urllib3": "",
    }


def test_legacy_dependency_table_still_supported():
    assert _parse_pyproject_toml(
        '[project.dependencies]\nfastapi = ">=0.100"\nsqlalchemy = "==2.0"\n'
    ) == {"fastapi": ">=0.100", "sqlalchemy": "==2.0"}


def test_unrelated_tool_sections_are_not_dependencies():
    assert _parse_pyproject_toml(
        '[project]\nname = "example"\n'
        '[tool.some-plugin.dependencies]\n'
        'credential = "do-not-report-as-package"\n'
    ) == {}


def test_direct_reference_does_not_expose_embedded_credentials():
    manifest = (
        '[project]\ndependencies = '
        '["internal @ https://operator:secret@example.com/internal.whl"]\n'
    )
    parsed = _parse_pyproject_toml(manifest)
    assert parsed["internal"].startswith("DIRECT_REFERENCE_SHA256:")
    assert "secret" not in str(parsed)
    assert parsed != _parse_pyproject_toml(
        '[project]\ndependencies = '
        '["internal @ https://operator:secret@example.com/other.whl"]\n'
    )


def test_legacy_direct_reference_is_also_redacted():
    parsed = _parse_pyproject_toml(
        '[project.dependencies]\n'
        'internal = "https://operator:secret@example.com/internal.whl"\n'
    )
    assert parsed["internal"].startswith("DIRECT_REFERENCE_SHA256:")
    assert "secret" not in str(parsed)


def test_malformed_pyproject_is_not_interpreted_as_dependency_data():
    assert _parse_pyproject_toml('[project]\ndependencies = [') == {}


def test_pep621_dependency_deltas_reach_structural_diff(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "pyproject.toml").write_text(
        '[project]\nname = "example"\n'
        'dependencies = ["fastapi>=0.100", "sqlalchemy>=2"]\n',
        encoding="utf-8",
    )
    (head / "pyproject.toml").write_text(
        '[project]\nname = "example"\n'
        'dependencies = ["fastapi>=0.110", "httpx>=0.27"]\n',
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
    assert ("fastapi", "UPDATED") in deltas
    assert ("sqlalchemy", "REMOVED") in deltas
    assert ("httpx", "ADDED") in deltas
