"""Canonical path confinement utilities for untrusted repository workspaces.

Guarantees that all file read, write, and deletion operations remain strictly
confined within the intended repository root workspace, preventing path traversal (../),
absolute path escapes, Windows drive escapes, sibling prefix attacks, and symlink escapes.
"""

from pathlib import Path
from typing import Union


class PathTraversalError(ValueError):
    """Raised when a path attempts to escape the root workspace."""


def resolve_safe_path(root_dir: Union[str, Path], rel_path: Union[str, Path]) -> Path:
    """Safely resolve and validate a relative path within a repository root directory.

    Args:
        root_dir: The repository root directory (must exist or be an absolute workspace path).
        rel_path: The untrusted relative file path.

    Returns:
        The canonical, resolved Path strictly guaranteed to be inside root_dir.

    Raises:
        PathTraversalError: If rel_path escapes root_dir or is invalid.
    """
    if not root_dir or not str(root_dir).strip():
        raise PathTraversalError("Repository root directory cannot be empty.")

    if not rel_path or not str(rel_path).strip():
        raise PathTraversalError("Target file path cannot be empty.")

    clean_rel = str(rel_path).replace("\\", "/").strip()

    # Reject explicit absolute paths or Windows drive letters in rel_path
    if clean_rel.startswith("/") or (len(clean_rel) > 1 and clean_rel[1] == ":"):
        raise PathTraversalError(f"Absolute paths not permitted in repository relative path: '{rel_path}'")

    root_path = Path(root_dir).resolve()
    target_path = (root_path / clean_rel).resolve()

    try:
        # relative_to raises ValueError if target_path is not within root_path
        target_path.relative_to(root_path)
    except ValueError:
        raise PathTraversalError(
            f"Path traversal detected: '{rel_path}' escapes repository root '{root_dir}'."
        )

    # Also guard against sibling prefix attacks (e.g., /tmp/repo vs /tmp/repo_evil)
    root_str = str(root_path)
    target_str = str(target_path)
    if not (target_str == root_str or target_str.startswith(root_str + "\\") or target_str.startswith(root_str + "/")):
        raise PathTraversalError(
            f"Sibling prefix escape detected: '{rel_path}' is outside '{root_dir}'."
        )

    return target_path
