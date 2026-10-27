"""Direct dependency references must be detectable without leaking embedded credentials."""

import json

from app.analysis.diff_engine import (
    ChangeDiffEngine,
    _parse_package_json,
    _parse_requirements_txt,
)


def test_requirements_direct_reference_changes_are_visible_and_redacted():
    before = _parse_requirements_txt(
        "private-lib @ https://operator:old-secret@example.com/lib.whl\n"
    )
    after = _parse_requirements_txt(
        "private-lib @ https://operator:new-secret@example.com/lib.whl\n"
    )
    assert before["private-lib"].startswith("DIRECT_REFERENCE_SHA256:")
    assert after["private-lib"].startswith("DIRECT_REFERENCE_SHA256:")
    assert before != after
    assert "secret" not in str(before) + str(after)


def test_requirements_extras_direct_reference_and_normal_versions():
    parsed = _parse_requirements_txt(
        "Private_Lib[security] @ git+https://user:token@example.com/lib.git\n"
        "fastapi==0.115.0\n"
    )
    assert parsed["private_lib"].startswith("DIRECT_REFERENCE_SHA256:")
    assert "token" not in str(parsed)
    assert parsed["fastapi"] == "==0.115.0"


def test_package_json_remote_references_are_fingerprinted():
    before = _parse_package_json(json.dumps({
        "dependencies": {"internal": "git+https://user:secret@example.com/repo.git"},
        "devDependencies": {"tool": "https://user:secret@example.com/tool.tgz"},
    }))
    after = _parse_package_json(json.dumps({
        "dependencies": {"internal": "git+https://user:secret@example.com/other.git"},
        "devDependencies": {"tool": "https://user:secret@example.com/tool.tgz"},
    }))
    assert before["internal"].startswith("DIRECT_REFERENCE_SHA256:")
    assert before["tool"].startswith("DIRECT_REFERENCE_SHA256:")
    assert before["internal"] != after["internal"]
    assert before["tool"] == after["tool"]
    assert "secret" not in str(before) + str(after)


def test_package_json_normal_versions_are_preserved():
    parsed = _parse_package_json(
        '{"dependencies":{"react":"^19.0.0"},'
        '"devDependencies":{"typescript":"~5.8.0"}}'
    )
    assert parsed == {"react": "^19.0.0", "typescript": "~5.8.0"}


def test_structural_diff_reports_direct_reference_updates_without_secrets(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "requirements.txt").write_text(
        "private-lib @ https://user:old-secret@example.com/lib.whl\n", encoding="utf-8"
    )
    (head / "requirements.txt").write_text(
        "private-lib @ https://user:new-secret@example.com/lib.whl\n", encoding="utf-8"
    )
    (base / "package.json").write_text(
        '{"dependencies":{"internal":"https://user:old-secret@example.com/lib.tgz"}}',
        encoding="utf-8",
    )
    (head / "package.json").write_text(
        '{"dependencies":{"internal":"https://user:new-secret@example.com/lib.tgz"}}',
        encoding="utf-8",
    )
    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )
    deltas = {(delta.manifest_file, delta.package_name): delta
              for delta in result.dependency_deltas}
    assert set(deltas) == {
        ("requirements.txt", "private-lib"), ("package.json", "internal")
    }
    for delta in deltas.values():
        assert delta.change_type == "UPDATED"
        assert delta.base_version.startswith("DIRECT_REFERENCE_SHA256:")
        assert delta.head_version.startswith("DIRECT_REFERENCE_SHA256:")
        assert delta.base_version != delta.head_version
        assert "secret" not in str(delta)
