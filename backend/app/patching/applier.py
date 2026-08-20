"""Safe, isolated unified diff application utility operating strictly on temporary workspaces."""

import os
import re
from typing import Dict, List, Tuple


def apply_patch_hunk(original_lines: List[str], hunk_lines: List[str], orig_start: int) -> List[str]:
    """Apply a single diff hunk to lines of a file (1-indexed start line)."""
    # 0-indexed start
    idx = max(0, orig_start - 1)
    
    # Separate hunk into expected context/removals and additions
    result = list(original_lines)
    hunk_idx = 0
    curr_line = idx

    while hunk_idx < len(hunk_lines):
        hline = hunk_lines[hunk_idx]
        if not hline:
            hunk_idx += 1
            continue

        prefix = hline[0]
        content = hline[1:]

        if prefix == " ":
            # Context line - advance
            curr_line += 1
        elif prefix == "-":
            # Deletion line
            if curr_line < len(result):
                result.pop(curr_line)
        elif prefix == "+":
            # Addition line
            result.insert(curr_line, content)
            curr_line += 1

        hunk_idx += 1

    return result


def apply_unified_diff_to_directory(unified_diff: str, target_dir: str) -> Dict[str, str]:
    """Apply a unified diff string to files within a temporary workspace directory.
    
    Returns:
        Dict mapping modified relative file paths to their new patched content.
    Raises:
        ValueError or FileNotFoundError if patch cannot be applied cleanly.
    """
    abs_root = os.path.abspath(target_dir)
    patched_files: Dict[str, str] = {}

    # Split diff by file sections
    file_diffs = re.split(r"(?=^--- (?:a/|\S+))", unified_diff, flags=re.MULTILINE)

    for section in file_diffs:
        if not section.strip():
            continue

        # Extract file header
        orig_match = re.search(r"^--- (?:a/)?(\S+)", section, re.MULTILINE)
        new_match = re.search(r"^\+\+\+ (?:b/)?(\S+)", section, re.MULTILINE)

        if not orig_match or not new_match:
            continue

        rel_path = new_match.group(1).replace("\\", "/").lstrip("/")
        if rel_path == "/dev/null":
            continue

        full_path = os.path.abspath(os.path.join(abs_root, rel_path))

        # Path traversal guard
        if not full_path.startswith(abs_root):
            raise PermissionError(f"Path traversal detected in patch for '{rel_path}'.")

        # Read original content
        if not os.path.exists(full_path):
            # Creation of a new file
            orig_lines: List[str] = []
        else:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                orig_lines = [line.rstrip("\r\n") for line in f]

        # Parse hunks
        hunk_blocks = re.split(r"(?=^@@ -\d+)", section, flags=re.MULTILINE)
        working_lines = list(orig_lines)

        for block in hunk_blocks[1:]:  # Skip file header
            header_match = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", block)
            if not header_match:
                continue

            orig_start = int(header_match.group(1))
            raw_hunk_lines = block.split("\n")[1:]  # Skip the @@ line
            # Filter out non-diff lines
            clean_hunk = [l for l in raw_hunk_lines if l and l[0] in (" ", "-", "+")]

            working_lines = apply_patch_hunk(working_lines, clean_hunk, orig_start)

        # Write patched content to target file in temporary directory
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        patched_text = "\n".join(working_lines) + ("\n" if working_lines else "")
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(patched_text)

        patched_files[rel_path] = patched_text

    return patched_files
