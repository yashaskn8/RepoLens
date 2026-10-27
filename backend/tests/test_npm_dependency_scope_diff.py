"""npm production and development dependency scopes must not be collapsed."""

import json

from app.analysis.diff_engine import ChangeDiffEngine, _parse_package_json


def test_moving_dev_dependency_to_runtime_is_visible():
    before = _parse_package_json(json.dumps({
        "devDependencies": {"example": "^1.2.3"},
    }))
    after = _parse_package_json(json.dumps({
        "dependencies": {"example": "^1.2.3"},
    }))
    assert before == {"example[dev]": "^1.2.3"}
    assert after == {"example": "^1.2.3"}
    assert before != after


def test_same_name_in_both_scopes_keeps_both_versions():
    parsed = _parse_package_json(json.dumps({
        "dependencies": {"shared": "^1.0"},
        "devDependencies": {"shared": "^2.0", "@scope/tool": "~3.0"},
    }))
    assert parsed == {
        "shared": "^1.0",
        "shared[dev]": "^2.0",
        "@scope/tool[dev]": "~3.0",
    }


def test_dev_reference_remains_fingerprinted():
    parsed = _parse_package_json(json.dumps({
        "devDependencies": {
            "tool": "git+https://user:private-token@example.com/tool.git",
        },
    }))
    assert parsed["tool[dev]"].startswith("DIRECT_REFERENCE_SHA256:")
    assert "private-token" not in str(parsed)


def test_structural_diff_detects_dev_to_runtime_move(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "package.json").write_text(
        '{"devDependencies":{"example":"^1.2.3"}}', encoding="utf-8"
    )
    (head / "package.json").write_text(
        '{"dependencies":{"example":"^1.2.3"}}', encoding="utf-8"
    )
    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )
    deltas = {(item.package_name, item.change_type) for item in result.dependency_deltas}
    assert ("example[dev]", "REMOVED") in deltas
    assert ("example", "ADDED") in deltas
