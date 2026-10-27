"""Malformed dependency manifests must not be reported as empty dependency sets."""

import pytest

from app.analysis.diff_engine import (
    ChangeDiffEngine,
    _parse_package_json,
    _parse_pyproject_toml,
)


@pytest.mark.parametrize(
    ("parser", "invalid"),
    [
        (_parse_package_json, '{"dependencies":'),
        (_parse_package_json, '[]'),
        (_parse_package_json, '{"dependencies":[]}'),
        (_parse_package_json, '{"peerDependencies":"not a mapping"}'),
        (_parse_pyproject_toml, "[project\n"),
        (_parse_pyproject_toml, '[project]\ndependencies="requests>=3"\n'),
        (_parse_pyproject_toml, '[project]\noptional-dependencies=["requests>=3"]\n'),
        (_parse_pyproject_toml, '[project]\ndependencies=[123]\n'),
        (_parse_pyproject_toml, '[project]\ndependencies=["@@not-a-requirement"]\n'),
        (_parse_pyproject_toml, '[project.dependencies]\nrequests=123\n'),
        (_parse_pyproject_toml, '[project.optional-dependencies]\nsecurity=[false]\n'),
    ],
)
def test_malformed_manifest_is_not_an_empty_dependency_set(parser, invalid):
    with pytest.raises(ValueError):
        parser(invalid)


@pytest.mark.parametrize(
    ("filename", "base", "head"),
    [
        ("package.json", '{"dependencies":{"requests":"1"}}', '{"dependencies":'),
        ("pyproject.toml", '[project]\ndependencies=["requests>=2"]\n', "[project\n"),
    ],
)
def test_structural_diff_fails_closed_on_malformed_dependency_manifest(
    tmp_path, filename, base, head
):
    base_dir = tmp_path / "base"
    head_dir = tmp_path / "head"
    base_dir.mkdir()
    head_dir.mkdir()
    (base_dir / filename).write_text(base, encoding="utf-8")
    (head_dir / filename).write_text(head, encoding="utf-8")

    with pytest.raises(ValueError):
        ChangeDiffEngine().compute_structural_diff(
            base_workspace=str(base_dir),
            head_workspace=str(head_dir),
            base_commit_sha="1" * 40,
            head_commit_sha="2" * 40,
            repository_url="https://github.com/example/repo",
        )
