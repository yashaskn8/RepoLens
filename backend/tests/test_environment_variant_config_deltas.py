"""Environment-specific dotenv files must contribute secret-safe change evidence."""

import pytest

from app.analysis.diff_engine import ChangeDiffEngine


@pytest.mark.parametrize(
    "relative_path",
    [
        ".env.production",
        ".env.development",
        ".env.staging",
        ".env.test.local",
        "frontend/.env.production.local",
    ],
)
def test_environment_variant_changes_are_reported(tmp_path, relative_path):
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    for root, value in ((base, "old-private-value"), (head, "new-private-value")):
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"API_TOKEN={value}\n", encoding="utf-8")

    result = ChangeDiffEngine().compute_structural_diff(
        str(base), str(head), "1" * 40, "2" * 40,
        "https://github.com/example/repo",
    )
    assert len(result.config_deltas) == 1
    delta = result.config_deltas[0]
    assert delta.file_path == relative_path
    assert delta.key == "API_TOKEN"
    assert delta.change_type == "MODIFIED"
    assert delta.base_fingerprint != delta.head_fingerprint
    assert delta.base_value is None and delta.head_value is None
    assert "private-value" not in str(delta)
