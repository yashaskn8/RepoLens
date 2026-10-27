"""JSON config changes must preserve types and ignore object key order."""

import json

from app.analysis.diff_engine import ChangeDiffEngine


def _compare(tmp_path, before, after):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "config.json").write_text(json.dumps(before), encoding="utf-8")
    (head / "config.json").write_text(json.dumps(after), encoding="utf-8")
    return ChangeDiffEngine().compute_structural_diff(
        str(base), str(head), "1" * 40, "2" * 40,
        "https://github.com/example/repo",
    )


def test_json_boolean_to_string_change_is_not_lost(tmp_path):
    result = _compare(tmp_path, {"enabled": True}, {"enabled": "True"})
    assert len(result.config_deltas) == 1
    delta = result.config_deltas[0]
    assert delta.key == "enabled"
    assert delta.change_type == "MODIFIED"
    assert delta.base_fingerprint != delta.head_fingerprint
    assert delta.base_value is None and delta.head_value is None


def test_json_number_to_string_change_is_not_lost(tmp_path):
    result = _compare(tmp_path, {"retry": 1}, {"retry": "1"})
    assert [(delta.key, delta.change_type) for delta in result.config_deltas] == [
        ("retry", "MODIFIED")
    ]


def test_json_nested_object_key_reordering_is_not_a_config_change(tmp_path):
    result = _compare(
        tmp_path,
        {"nested": {"alpha": 1, "beta": 2}},
        {"nested": {"beta": 2, "alpha": 1}},
    )
    assert result.config_deltas == []
