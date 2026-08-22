"""Canonical Markdown and HTML safety formatting utilities for RepoLens."""

import html
from typing import Optional
from app.security.redaction import redact_secrets


def escape_markdown_text(text: Optional[str]) -> str:
    """Escape raw HTML tags and redact secrets so untrusted repository text is rendered as inert text."""
    if not text:
        return ""
    redacted = redact_secrets(text)
    return html.escape(redacted, quote=False)


def escape_table_cell(text: Optional[str]) -> str:
    """Format text safely inside a Markdown table cell, escaping pipes and removing line breaks."""
    if not text:
        return "-"
    redacted = redact_secrets(text)
    escaped = html.escape(redacted, quote=False)
    # Pipes break table formatting
    escaped = escaped.replace("|", "\\|")
    # Replace newlines with spaces
    escaped = escaped.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return escaped.strip() or "-"


def safe_inline_code(text: Optional[str]) -> str:
    """Wrap content in inline code backticks, safely escaping embedded backticks."""
    if not text:
        return "``"
    redacted = redact_secrets(str(text))
    escaped = html.escape(redacted, quote=False)
    if "`" in escaped:
        return f"`` {escaped} ``"
    return f"`{escaped}`"


def safe_fenced_block(content: Optional[str], lang: str = "") -> str:
    """Render a code or diff block using dynamic fence length to prevent backtick breakout injection."""
    if not content:
        return f"```{lang}\n```"
    redacted = redact_secrets(content)
    # Calculate required fence length: at least 3, or longest consecutive backtick run + 1
    longest_run = 0
    current_run = 0
    for ch in redacted:
        if ch == "`":
            current_run += 1
            if current_run > longest_run:
                longest_run = current_run
        else:
            current_run = 0

    fence_len = max(3, longest_run + 1)
    fence = "`" * fence_len
    return f"{fence}{lang}\n{redacted}\n{fence}"
