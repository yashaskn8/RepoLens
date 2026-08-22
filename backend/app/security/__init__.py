"""Security module for RepoLens."""

from app.security.redaction import (
    MAX_METADATA_DEPTH,
    MAX_METADATA_DICT_ENTRIES,
    MAX_METADATA_LIST_ITEMS,
    MAX_METADATA_SERIALIZED_BYTES,
    MAX_METADATA_STRING_LENGTH,
    redact_secrets,
    sanitize_metadata,
)

__all__ = [
    "redact_secrets",
    "sanitize_metadata",
    "MAX_METADATA_DEPTH",
    "MAX_METADATA_DICT_ENTRIES",
    "MAX_METADATA_LIST_ITEMS",
    "MAX_METADATA_STRING_LENGTH",
    "MAX_METADATA_SERIALIZED_BYTES",
]
