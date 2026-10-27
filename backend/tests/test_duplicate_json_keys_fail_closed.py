"""Duplicate JSON object keys must not silently hide dependency/configuration changes."""

import pytest

from app.analysis.diff_engine import ChangeDiffEngine, _parse_package_json


@pytest.mark.parametrize(
    "manifest",
    [
        '{"dependencies":{"pkg":"1.0","pkg":"2.0"}}',
        '{"dependencies":{"pkg":"1.0"},"dependencies":{"pkg":"2.0"}}',
        '{"meta":{"version":1,"version":2},"dependencies":{"pkg":"1.0"}}',
    ],
)
def test_package_json_rejects_duplicate_object_keys(manifest):
    with pytest.raises(ValueError, match="duplicate"):
        _parse_package_json(manifest)


@pytest.mark.parametrize(
    "config",
    [
        '{"feature":true,"feature":false}',
        '{"nested":{"token":"one","token":"two"}}',
    ],
)
def test_config_json_rejects_duplicate_object_keys(tmp_path, config):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "config.json").write_text(config, encoding="utf-8")
    (head / "config.json").write_text('{"feature":false}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate"):
        ChangeDiffEngine().compute_structural_diff(
            str(base), str(head), "1" * 40, "2" * 40,
            "https://github.com/example/repo",
        )
