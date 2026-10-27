"""Dependency manifest comparison must not read unbounded or invalid source bytes."""

import pytest

from app.analysis.diff_engine import ChangeDiffEngine


def test_nested_manifest_over_budget_fails_closed(tmp_path, monkeypatch):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root in (base, head):
        (root / "app").mkdir(parents=True)
    (base / "app" / "package.json").write_text(
        '{"dependencies":{"safe":"1"}}', encoding="utf-8"
    )
    (head / "app" / "package.json").write_text(
        '{"dependencies":{"safe":"2"}}', encoding="utf-8"
    )
    engine = ChangeDiffEngine()
    monkeypatch.setattr(engine.settings, "MAX_FILE_SIZE_BYTES", 12)
    with pytest.raises(ValueError):
        engine.compute_structural_diff(
            base_workspace=str(base),
            head_workspace=str(head),
            base_commit_sha="1" * 40,
            head_commit_sha="2" * 40,
            repository_url="https://github.com/example/repo",
        )


def test_manifest_invalid_utf8_is_not_treated_as_empty(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "requirements.txt").write_bytes(b"requests==2\n")
    (head / "requirements.txt").write_bytes(b"requests==3\xff\n")
    with pytest.raises(ValueError):
        ChangeDiffEngine().compute_structural_diff(
            base_workspace=str(base),
            head_workspace=str(head),
            base_commit_sha="1" * 40,
            head_commit_sha="2" * 40,
            repository_url="https://github.com/example/repo",
        )
