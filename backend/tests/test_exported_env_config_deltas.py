"""Export-prefixed dotenv assignments must contribute truthful, secret-safe PR evidence."""

from app.analysis.diff_engine import ChangeDiffEngine, _parse_env_file


def test_exported_env_assignments_are_parsed_alongside_plain_assignments():
    parsed = _parse_env_file(
        "export API_URL='https://example.test/v1'\n"
        "  export TOKEN = \"sensitive-value\"\n"
        "PLAIN=enabled\n"
        "# export IGNORED=comment\n"
    )
    assert parsed == {
        "API_URL": "https://example.test/v1",
        "TOKEN": "sensitive-value",
        "PLAIN": "enabled",
    }


def test_exported_env_changes_produce_fingerprinted_config_delta(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / ".env.example").write_text("export API_TOKEN=old-private-value\n", encoding="utf-8")
    (head / ".env.example").write_text("export API_TOKEN=new-private-value\n", encoding="utf-8")

    result = ChangeDiffEngine().compute_structural_diff(
        str(base), str(head), "1" * 40, "2" * 40,
        "https://github.com/example/repo",
    )
    assert len(result.config_deltas) == 1
    delta = result.config_deltas[0]
    assert delta.file_path == ".env.example"
    assert delta.key == "API_TOKEN"
    assert delta.change_type == "MODIFIED"
    assert delta.base_fingerprint != delta.head_fingerprint
    assert delta.base_value is None
    assert delta.head_value is None
    assert "private-value" not in str(delta)


def test_exported_env_addition_and_removal_are_not_lost(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / ".env.example").write_text("export OLD_KEY=old\n", encoding="utf-8")
    (head / ".env.example").write_text("export NEW_KEY=new\n", encoding="utf-8")

    result = ChangeDiffEngine().compute_structural_diff(
        str(base), str(head), "1" * 40, "2" * 40,
        "https://github.com/example/repo",
    )
    assert {(delta.key, delta.change_type) for delta in result.config_deltas} == {
        ("OLD_KEY", "REMOVED"), ("NEW_KEY", "ADDED")
    }
