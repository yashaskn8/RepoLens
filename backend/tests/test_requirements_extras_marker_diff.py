"""PEP 508 extras and environment markers must survive requirements structural diffs."""

from app.analysis.diff_engine import ChangeDiffEngine, _parse_requirements_txt


def test_requirements_extras_are_not_discarded():
    assert _parse_requirements_txt("requests[socks]>=2.30\n") == {
        "requests": "[socks]>=2.30"
    }
    assert _parse_requirements_txt("requests[security,socks]\n") == {
        "requests": "[security,socks]"
    }


def test_requirements_environment_marker_without_version_is_recorded():
    assert _parse_requirements_txt(
        "importlib-metadata; python_version < '3.10'\n"
    ) == {"importlib-metadata": "; python_version < '3.10'"}


def test_requirements_direct_reference_with_extras_remains_redacted():
    parsed = _parse_requirements_txt(
        "private-lib[feature] @ https://user:secret@example.com/lib.whl\n"
    )
    assert parsed["private-lib"].startswith("DIRECT_REFERENCE_SHA256:")
    assert "secret" not in str(parsed)


def test_structural_diff_detects_requirements_extras_and_marker_changes(tmp_path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "requirements.txt").write_text(
        "requests>=2.30\nimportlib-metadata; python_version < '3.10'\n",
        encoding="utf-8",
    )
    (head / "requirements.txt").write_text(
        "requests[socks]>=2.30\nimportlib-metadata; python_version < '3.11'\n",
        encoding="utf-8",
    )
    result = ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )
    changes = {
        delta.package_name: delta
        for delta in result.dependency_deltas
        if delta.manifest_file == "requirements.txt"
    }
    assert changes["requests"].change_type == "UPDATED"
    assert changes["requests"].base_version == ">=2.30"
    assert changes["requests"].head_version == "[socks]>=2.30"
    assert changes["importlib-metadata"].change_type == "UPDATED"
