"""Multiple platform-specific constraints must not overwrite one another in PR evidence."""

from app.analysis.diff_engine import (
    ChangeDiffEngine,
    _parse_pyproject_toml,
    _parse_requirements_txt,
)


def test_requirements_preserves_distinct_marked_variants_and_is_order_independent():
    first = "uvloop>=0.19; python_version < '3.12'\nuvloop>=0.20; python_version >= '3.12'\n"
    parsed = _parse_requirements_txt(first)
    assert parsed == _parse_requirements_txt("\n".join(reversed(first.splitlines())) + "\n")
    assert parsed["uvloop"].startswith("MULTIPLE_REQUIREMENTS:")
    assert ">=0.19" in parsed["uvloop"]
    assert ">=0.20" in parsed["uvloop"]
    assert _parse_requirements_txt(first.replace(">=0.19", ">=0.18")) != parsed


def test_pep621_preserves_multiple_constraints_for_same_package():
    def manifest(first, second):
        return (
            '[project]\nname = "example"\n'
            f'dependencies = ["{first}", "{second}"]\n'
        )

    old = manifest("uvloop>=0.19; python_version < '3.12'",
                   "uvloop>=0.20; python_version >= '3.12'")
    reversed_order = manifest("uvloop>=0.20; python_version >= '3.12'",
                              "uvloop>=0.19; python_version < '3.12'")
    changed = old.replace(">=0.19", ">=0.18")
    parsed = _parse_pyproject_toml(old)
    assert parsed == _parse_pyproject_toml(reversed_order)
    assert parsed["uvloop"].startswith("MULTIPLE_REQUIREMENTS:")
    assert _parse_pyproject_toml(changed) != parsed


def test_optional_group_preserves_multiple_marked_constraints():
    manifest = (
        '[project]\nname = "example"\n'
        '[project.optional-dependencies]\n'
        'speed = ["uvloop>=0.19; python_version < \'3.12\'", '
        '"uvloop>=0.20; python_version >= \'3.12\'"]\n'
    )
    assert _parse_pyproject_toml(manifest)["uvloop[speed]"].startswith(
        "MULTIPLE_REQUIREMENTS:"
    )


def test_multiple_direct_references_remain_credential_safe():
    parsed = _parse_requirements_txt(
        "private-lib @ https://user:old-secret@example.com/a.whl\n"
        "private-lib @ https://user:new-secret@example.com/b.whl\n"
    )
    assert parsed["private-lib"].startswith("MULTIPLE_REQUIREMENTS:")
    assert "secret" not in str(parsed)
    assert parsed["private-lib"].count("DIRECT_REFERENCE_SHA256:") == 2


def test_structural_diff_detects_change_to_only_one_marked_variant(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    before = (
        "uvloop>=0.19; python_version < '3.12'\n"
        "uvloop>=0.20; python_version >= '3.12'\n"
    )
    (base / "requirements.txt").write_text(before, encoding="utf-8")
    (head / "requirements.txt").write_text(
        before.replace(">=0.19", ">=0.18"), encoding="utf-8"
    )
    (base / "pyproject.toml").write_text(
        '[project]\nname = "example"\n'
        'dependencies = ["uvloop>=0.19; python_version < \'3.12\'", '
        '"uvloop>=0.20; python_version >= \'3.12\'"]\n',
        encoding="utf-8",
    )
    (head / "pyproject.toml").write_text(
        '[project]\nname = "example"\n'
        'dependencies = ["uvloop>=0.18; python_version < \'3.12\'", '
        '"uvloop>=0.20; python_version >= \'3.12\'"]\n',
        encoding="utf-8",
    )
    diff = ChangeDiffEngine().compute_structural_diff(
        str(base), str(head), "1" * 40, "2" * 40,
        "https://github.com/example/repo",
    )
    changes = {(d.manifest_file, d.package_name): d for d in diff.dependency_deltas}
    assert set(changes) == {
        ("requirements.txt", "uvloop"), ("pyproject.toml", "uvloop")
    }
    assert all(d.change_type == "UPDATED" for d in changes.values())
