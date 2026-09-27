"""Bounded parsing for durable workflow-event cursors."""

MAX_EVENT_CURSOR = (1 << 63) - 1


def parse_event_cursor(last_event_id: str | None, after_id: int | None) -> int:
    """Return a nonnegative database event ID without reflecting attacker input."""
    if last_event_id is not None and last_event_id.strip():
        value = last_event_id.strip()
        # PostgreSQL BIGINT is at most 19 decimal digits. Bound before calling
        # int(), and reject signs/Unicode numerals rather than normalizing them.
        if len(value) > 19 or not value.isascii() or not value.isdecimal():
            raise ValueError("Invalid event cursor.")
        cursor = int(value)
    else:
        cursor = 0 if after_id is None else after_id

    if isinstance(cursor, bool) or not isinstance(cursor, int) or not 0 <= cursor <= MAX_EVENT_CURSOR:
        raise ValueError("Invalid event cursor.")
    return cursor
