"""Durable workflow event cursors are bounded and never reflected in errors."""

import pytest

from app.api.event_cursor import MAX_EVENT_CURSOR, parse_event_cursor


@pytest.mark.parametrize(
    "header,query,expected",
    [
        (None, None, 0),
        (None, 17, 17),
        ("0", 17, 0),
        (str(MAX_EVENT_CURSOR), None, MAX_EVENT_CURSOR),
    ],
)
def test_parse_event_cursor_accepts_bounded_values(header, query, expected):
    assert parse_event_cursor(header, query) == expected


@pytest.mark.parametrize(
    "header,query",
    [
        ("x" * 100_000, None),
        ("9223372036854775808", None),
        ("-1", None),
        ("+1", None),
        ("١", None),
        (None, -1),
        (None, MAX_EVENT_CURSOR + 1),
        (None, True),
    ],
    ids=[
        "oversized-header",
        "signed-bigint-overflow",
        "negative-header",
        "plus-sign-header",
        "unicode-numeral",
        "negative-query",
        "query-overflow",
        "boolean-query",
    ],
)
def test_parse_event_cursor_rejects_invalid_values_without_reflection(header, query):
    with pytest.raises(ValueError, match="^Invalid event cursor\\.$"):
        parse_event_cursor(header, query)
