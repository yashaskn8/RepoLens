"""A previously optional argument becoming required is a breaking contract."""

import pytest

from app.analysis.diff_engine import _is_breaking_signature_change


@pytest.mark.parametrize(
    ("before", "after", "breaking"),
    [
        ("(timeout=30)", "(timeout)", True),
        ("(timeout?: number)", "(timeout: number)", True),
        ("(name, retries=3)", "(name, retries)", True),
        ("(name)", "(name, retries)", True),
        ("(name)", "(name, retries=3)", False),
        ("(name, retries=3)", "(name, retries=5)", False),
        ("(name)", "(name=None)", False),
        ("(name, retries=3)", "(name)", True),
    ],
)
def test_signature_requiredness_regression(before, after, breaking):
    assert _is_breaking_signature_change(before, after, "", "") is breaking
