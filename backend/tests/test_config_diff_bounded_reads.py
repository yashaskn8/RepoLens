"""Configuration evidence must be bounded, complete, and secret-safe."""

import pytest

from app.analysis import diff_engine
from app.analysis.diff_engine import ChangeDiffEngine


def _compare(tmp_path, base_content: bytes, head_content: bytes, filename: str = ".env"):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / filename).write_bytes(base_content)
    (head / filename).write_bytes(head_content)
    return ChangeDiffEngine().compute_structural_diff(
        base_workspace=str(base),
        head_workspace=str(head),
        base_commit_sha="1" * 40,
        head_commit_sha="2" * 40,
        repository_url="https://github.com/example/repo",
    )


def test_oversized_env_file_cannot_produce_partial_config_evidence(tmp_path, monkeypatch):
    engine_settings = diff_engine.get_settings()
    monkeypatch.setattr(engine_settings, "MAX_FILE_SIZE_BYTES", 64)
    with pytest.raises(ValueError):
        _compare(tmp_path, b"API_KEY=old\n", b"API_KEY=" + b"x" * 100 + b"\n")


def test_invalid_utf8_env_file_cannot_be_silently_ignored(tmp_path):
    with pytest.raises(UnicodeDecodeError):
        _compare(tmp_path, b"API_KEY=old\n", b"API_KEY=\xff\n")


@pytest.mark.parametrize("invalid_json", [b'{"API_KEY":', b'["not", "an", "object"]', b""])
def test_invalid_config_json_cannot_be_interpreted_as_empty(tmp_path, invalid_json):
    with pytest.raises(ValueError):
        _compare(tmp_path, b'{"API_KEY":"old"}', invalid_json, "config.json")


def test_config_read_error_is_not_silently_treated_as_removal(tmp_path, monkeypatch):
    original = diff_engine._read_bounded_snapshot_file

    def reject_head(path, max_bytes):
        if path.endswith("/head/.env"):
            raise OSError("injected source read failure")
        return original(path, max_bytes)

    monkeypatch.setattr(diff_engine, "_read_bounded_snapshot_file", reject_head)
    with pytest.raises(OSError, match="injected source read failure"):
        _compare(tmp_path, b"API_KEY=old\n", b"API_KEY=new\n")


def test_valid_config_delta_contains_only_fingerprints(tmp_path):
    result = _compare(tmp_path, b"API_KEY=old-secret\n", b"API_KEY=new-secret\n")
    delta = next(d for d in result.config_deltas if d.key == "API_KEY")
    assert delta.change_type == "MODIFIED"
    assert delta.base_fingerprint != delta.head_fingerprint
    assert delta.base_value is None and delta.head_value is None
    assert "old-secret" not in delta.model_dump_json()
    assert "new-secret" not in delta.model_dump_json()
