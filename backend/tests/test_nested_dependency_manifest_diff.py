"""Structural PR analysis must report manifests in nested workspaces."""

from app.analysis.diff_engine import ChangeDiffEngine


def test_nested_manifests_are_not_ignored(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root in (base, head):
        (root / "frontend").mkdir(parents=True)
        (root / "backend").mkdir(parents=True)

    (base / "frontend" / "package.json").write_text(
        '{"dependencies":{"react":"^18"}}', encoding="utf-8"
    )
    (head / "frontend" / "package.json").write_text(
        '{"dependencies":{"react":"^19"}}', encoding="utf-8"
    )
    (base / "backend" / "requirements.txt").write_text(
        "requests>=2\n", encoding="utf-8"
    )
    (head / "backend" / "requirements.txt").write_text(
        "requests[socks]>=2\n", encoding="utf-8"
    )

    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )
    changes = {
        (delta.manifest_file, delta.package_name): delta
        for delta in result.dependency_deltas
    }
    assert changes[("frontend/package.json", "react")].change_type == "UPDATED"
    assert changes[("backend/requirements.txt", "requests")].head_version == "[socks]>=2"


def test_same_package_in_two_nested_manifests_keeps_provenance(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root in (base, head):
        (root / "app1").mkdir(parents=True)
        (root / "app2").mkdir(parents=True)
    for name in ("app1", "app2"):
        (base / name / "package.json").write_text(
            '{"dependencies":{"shared":"1"}}', encoding="utf-8"
        )
    (head / "app1" / "package.json").write_text(
        '{"dependencies":{"shared":"2"}}', encoding="utf-8"
    )
    (head / "app2" / "package.json").write_text(
        '{"dependencies":{"shared":"3"}}', encoding="utf-8"
    )
    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )
    assert {
        (delta.manifest_file, delta.package_name, delta.head_version)
        for delta in result.dependency_deltas
    } >= {
        ("app1/package.json", "shared", "2"),
        ("app2/package.json", "shared", "3"),
    }
