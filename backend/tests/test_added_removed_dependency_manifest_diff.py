"""Added/deleted dependency manifests must compare against an absent side, not parse it."""

import pytest

from app.analysis.diff_engine import ChangeDiffEngine


@pytest.mark.parametrize(
    ("filename", "content", "package"),
    [
        ("package.json", '{"dependencies":{"example":"^1.0.0"}}', "example"),
        ("pyproject.toml", '[project]\ndependencies=["example>=1"]\n', "example"),
    ],
)
@pytest.mark.parametrize("direction", ["ADDED", "REMOVED"])
@pytest.mark.parametrize("nested", [False, True])
def test_manifest_addition_or_removal_is_not_malformed(
    tmp_path, filename, content, package, direction, nested
):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    relative = f"packages/service/{filename}" if nested else filename
    present_root = head if direction == "ADDED" else base
    manifest = present_root / relative
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(content, encoding="utf-8")

    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )

    matching = [
        delta for delta in result.dependency_deltas
        if delta.manifest_file == relative and delta.package_name == package
    ]
    assert len(matching) == 1
    delta = matching[0]
    assert delta.change_type == direction
    if direction == "ADDED":
        assert delta.base_version is None
        assert delta.head_version is not None
    else:
        assert delta.base_version is not None
        assert delta.head_version is None


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("package.json", ""),
        ("pyproject.toml", "[project\n"),
    ],
)
def test_present_invalid_manifest_still_fails_closed(tmp_path, filename, content):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / filename).write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        ChangeDiffEngine().compute_structural_diff(
            base_workspace=str(base),
            head_workspace=str(head),
            base_commit_sha="1" * 40,
            head_commit_sha="2" * 40,
            repository_url="https://github.com/example/repo",
        )
