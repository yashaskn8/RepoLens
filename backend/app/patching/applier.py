"""Safe, isolated, strict unified diff application utility operating strictly on temporary workspaces."""

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


class PatchApplyError(Exception):
    """Base exception for strict unified diff parsing and application failures."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        hunk_index: Optional[int] = None,
        line_number: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.file_path = file_path
        self.hunk_index = hunk_index
        self.line_number = line_number
        self.details = details or {}


_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc",
    ".db", ".sqlite", ".sqlite3", ".zip", ".tar", ".gz",
    ".pdf", ".wasm", ".class", ".o", ".a",
}


@dataclass
class DiffHunk:
    """Parsed and validated unified diff hunk."""

    orig_start: int
    orig_count: int
    new_start: int
    new_count: int
    lines: List[Tuple[str, str]]  # (prefix, content)
    hunk_index: int


@dataclass
class FilePatch:
    """Parsed file patch containing headers and ordered hunks."""

    orig_file: str
    new_file: str
    is_new_file: bool
    is_deleted_file: bool
    hunks: List[DiffHunk]


def parse_unified_diff(unified_diff: str) -> List[FilePatch]:
    """Strictly parse a unified diff string into structured FilePatch and DiffHunk representations.
    
    Raises:
        PatchApplyError: If diff headers, hunk ranges, or line counts are malformed or invalid.
    """
    diff_text = unified_diff.strip()
    if not diff_text:
        raise PatchApplyError("Empty unified diff provided.")

    # Check for binary patch indicators
    if "GIT binary patch" in diff_text or "Binary files " in diff_text:
        raise PatchApplyError("Binary patches are strictly rejected. Only UTF-8 text modifications are permitted.")

    file_patches: List[FilePatch] = []

    # Split into file diff sections matching '--- ' headers
    sections = re.split(r"(?=^--- (?:a/|\S+))", diff_text, flags=re.MULTILINE)

    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue

        lines = sec.splitlines()
        orig_file_match = re.match(r"^--- (?:a/)?(\S+)", lines[0]) if len(lines) > 0 else None
        new_file_match = re.match(r"^\+\+\+ (?:b/)?(\S+)", lines[1]) if len(lines) > 1 else None

        if not orig_file_match or not new_file_match:
            raise PatchApplyError(f"Malformed file headers in diff section:\n{sec[:200]}")

        orig_file = orig_file_match.group(1).replace("\\", "/")
        new_file = new_file_match.group(1).replace("\\", "/")

        target_file = new_file if new_file != "/dev/null" else orig_file
        clean_target = target_file.lstrip("/")

        # Check binary file extension
        _, ext = os.path.splitext(clean_target.lower())
        if ext in _BINARY_EXTENSIONS:
            raise PatchApplyError(f"Binary file patch rejected: '{clean_target}'", file_path=clean_target)

        is_new_file = (orig_file == "/dev/null" or orig_file.startswith("/dev/null"))
        is_deleted_file = (new_file == "/dev/null" or new_file.startswith("/dev/null"))

        # Parse hunks within this file section
        hunks: List[DiffHunk] = []
        current_hunk: Optional[DiffHunk] = None
        hunk_idx = 0

        for line_idx, line in enumerate(lines[2:], start=3):
            hunk_header_match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if hunk_header_match:
                if current_hunk:
                    _validate_hunk_internal_counts(current_hunk, clean_target)
                    hunks.append(current_hunk)

                hunk_idx += 1
                orig_start = int(hunk_header_match.group(1))
                orig_count = int(hunk_header_match.group(2)) if hunk_header_match.group(2) is not None else 1
                new_start = int(hunk_header_match.group(3))
                new_count = int(hunk_header_match.group(4)) if hunk_header_match.group(4) is not None else 1

                current_hunk = DiffHunk(
                    orig_start=orig_start,
                    orig_count=orig_count,
                    new_start=new_start,
                    new_count=new_count,
                    lines=[],
                    hunk_index=hunk_idx,
                )
            elif current_hunk is not None:
                if line.startswith(("\\ No newline at end of file", "\\")):
                    continue
                if line.startswith((" ", "-", "+")):
                    prefix = line[0]
                    content = line[1:]
                    current_hunk.lines.append((prefix, content))
                elif not line.strip():
                    # Empty line in context
                    current_hunk.lines.append((" ", ""))
                else:
                    raise PatchApplyError(
                        f"Invalid diff line marker in hunk {hunk_idx} for '{clean_target}': {repr(line)}",
                        file_path=clean_target,
                        hunk_index=hunk_idx,
                        line_number=line_idx,
                    )

        if current_hunk:
            _validate_hunk_internal_counts(current_hunk, clean_target)
            hunks.append(current_hunk)

        if not hunks and not is_deleted_file:
            raise PatchApplyError(f"No valid diff hunks found for file '{clean_target}'", file_path=clean_target)

        # Check for overlapping hunks
        _validate_no_overlapping_hunks(hunks, clean_target)

        file_patches.append(
            FilePatch(
                orig_file=orig_file,
                new_file=new_file,
                is_new_file=is_new_file,
                is_deleted_file=is_deleted_file,
                hunks=hunks,
            )
        )

    return file_patches


def _validate_hunk_internal_counts(hunk: DiffHunk, file_path: str) -> None:
    """Ensure that the hunk's line counts match the @@ -start,count +start,count @@ header."""
    actual_orig_count = sum(1 for p, _ in hunk.lines if p in (" ", "-"))
    actual_new_count = sum(1 for p, _ in hunk.lines if p in (" ", "+"))

    if actual_orig_count != hunk.orig_count or actual_new_count != hunk.new_count:
        raise PatchApplyError(
            f"Hunk {hunk.hunk_index} range header -{hunk.orig_start},{hunk.orig_count} +{hunk.new_start},{hunk.new_count} "
            f"does not match actual hunk line counts (found {actual_orig_count} original, {actual_new_count} new lines)",
            file_path=file_path,
            hunk_index=hunk.hunk_index,
        )


def _validate_no_overlapping_hunks(hunks: List[DiffHunk], file_path: str) -> None:
    """Ensure that multiple hunks for the same file do not overlap or conflict."""
    sorted_hunks = sorted(hunks, key=lambda h: h.orig_start)
    for i in range(len(sorted_hunks) - 1):
        h1 = sorted_hunks[i]
        h2 = sorted_hunks[i + 1]
        h1_end = h1.orig_start + h1.orig_count
        if h1_end > h2.orig_start:
            raise PatchApplyError(
                f"Overlapping hunks detected in '{file_path}': Hunk {h1.hunk_index} (lines {h1.orig_start}-{h1_end}) "
                f"overlaps with Hunk {h2.hunk_index} (starts at line {h2.orig_start})",
                file_path=file_path,
                hunk_index=h2.hunk_index,
            )


def apply_unified_diff_to_directory(unified_diff: str, target_dir: str) -> Dict[str, str]:
    """Strictly apply a unified diff string to files within a temporary workspace directory.
    
    Guarantees:
    - Never modifies files outside target_dir.
    - Strictly checks original line numbers, context lines, and deletion lines.
    - Rejects stale context, wrong deletions, overlapping hunks, and binary modifications.
    - Raises PatchApplyError on any mismatch.
    
    Returns:
        Dict mapping modified relative file paths to their new patched content.
    """
    abs_root = os.path.abspath(target_dir)
    file_patches = parse_unified_diff(unified_diff)
    patched_files: Dict[str, str] = {}

    for fp in file_patches:
        target_rel = (fp.new_file if not fp.is_deleted_file else fp.orig_file).replace("\\", "/").lstrip("/")

        # Path traversal guard
        if os.path.isabs(target_rel) or target_rel.startswith(("/", "\\", "..")):
            raise PatchApplyError(f"Path traversal detected: '{target_rel}' escapes repository boundary.", file_path=target_rel)

        full_path = os.path.abspath(os.path.join(abs_root, target_rel))
        if not full_path.startswith(abs_root + os.sep) and full_path != abs_root:
            raise PatchApplyError(f"Path traversal detected: '{target_rel}' resolves outside repository root.", file_path=target_rel)

        # Read original content
        if fp.is_new_file:
            original_lines: List[str] = []
        else:
            if not os.path.exists(full_path):
                raise PatchApplyError(f"Target file does not exist on disk: '{target_rel}'", file_path=target_rel)

            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    original_lines = [l.rstrip("\r\n") for l in f]
            except UnicodeDecodeError:
                raise PatchApplyError(f"Target file is binary or non-UTF-8: '{target_rel}'", file_path=target_rel)

        if fp.is_deleted_file:
            if os.path.exists(full_path):
                os.remove(full_path)
            patched_files[target_rel] = ""
            continue

        # Sort hunks by original start line
        sorted_hunks = sorted(fp.hunks, key=lambda h: h.orig_start)

        # Apply and verify all hunks sequentially
        new_file_lines: List[str] = []
        current_orig_idx = 0  # 0-indexed cursor in original_lines

        for hunk in sorted_hunks:
            hunk_orig_start_0 = max(0, hunk.orig_start - 1) if hunk.orig_start > 0 else 0

            if hunk_orig_start_0 < current_orig_idx:
                raise PatchApplyError(
                    f"Overlapping hunk execution in '{target_rel}' at hunk {hunk.hunk_index}",
                    file_path=target_rel,
                    hunk_index=hunk.hunk_index,
                )

            # Append unchanged lines prior to this hunk
            new_file_lines.extend(original_lines[current_orig_idx:hunk_orig_start_0])
            current_orig_idx = hunk_orig_start_0

            # Match and apply hunk lines
            hunk_orig_cursor = hunk_orig_start_0
            for prefix, content in hunk.lines:
                if prefix == " ":
                    # Context line: must match verbatim
                    if hunk_orig_cursor >= len(original_lines):
                        raise PatchApplyError(
                            f"Stale context line mismatch in '{target_rel}' at hunk {hunk.hunk_index} line {hunk_orig_cursor + 1}: expected {repr(content)}, found <EOF>",
                            file_path=target_rel,
                            hunk_index=hunk.hunk_index,
                            line_number=hunk_orig_cursor + 1,
                        )
                    if original_lines[hunk_orig_cursor] != content:
                        raise PatchApplyError(
                            f"Stale context line mismatch in '{target_rel}' at hunk {hunk.hunk_index} line {hunk_orig_cursor + 1}: expected {repr(content)}, found {repr(original_lines[hunk_orig_cursor])}",
                            file_path=target_rel,
                            hunk_index=hunk.hunk_index,
                            line_number=hunk_orig_cursor + 1,
                        )
                    new_file_lines.append(original_lines[hunk_orig_cursor])
                    hunk_orig_cursor += 1
                elif prefix == "-":
                    # Deletion line: must match verbatim
                    if hunk_orig_cursor >= len(original_lines):
                        raise PatchApplyError(
                            f"Deletion line mismatch in '{target_rel}' at hunk {hunk.hunk_index} line {hunk_orig_cursor + 1}: expected deletion of {repr(content)}, found <EOF>",
                            file_path=target_rel,
                            hunk_index=hunk.hunk_index,
                            line_number=hunk_orig_cursor + 1,
                        )
                    if original_lines[hunk_orig_cursor] != content:
                        raise PatchApplyError(
                            f"Deletion line mismatch in '{target_rel}' at hunk {hunk.hunk_index} line {hunk_orig_cursor + 1}: expected deletion of {repr(content)}, found {repr(original_lines[hunk_orig_cursor])}",
                            file_path=target_rel,
                            hunk_index=hunk.hunk_index,
                            line_number=hunk_orig_cursor + 1,
                        )
                    hunk_orig_cursor += 1  # consumed and omitted from new_file_lines
                elif prefix == "+":
                    # Addition line
                    new_file_lines.append(content)

            current_orig_idx = hunk_orig_cursor

        # Append remaining unchanged lines after last hunk
        new_file_lines.extend(original_lines[current_orig_idx:])

        # Write out patched file to disk in temporary workspace
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        patched_text = "\n".join(new_file_lines) + ("\n" if new_file_lines else "")
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(patched_text)

        patched_files[target_rel] = patched_text

    return patched_files


def apply_patch_hunk(original_lines: List[str], hunk_lines: List[str], orig_start: int) -> List[str]:
    """Apply a single diff hunk to lines of a file (1-indexed start line) with strict validation.
    
    Raises:
        PatchApplyError: If context or deletion lines do not match original lines.
    """
    idx = max(0, orig_start - 1) if orig_start > 0 else 0
    curr_orig_idx = idx
    output_lines: List[str] = list(original_lines[:idx])

    for line in hunk_lines:
        if not line:
            continue
        prefix = line[0]
        content = line[1:]

        if prefix == " ":
            if curr_orig_idx >= len(original_lines) or original_lines[curr_orig_idx] != content:
                raise PatchApplyError(
                    f"Stale context line mismatch: expected {repr(content)}, found {repr(original_lines[curr_orig_idx]) if curr_orig_idx < len(original_lines) else '<EOF>'}"
                )
            output_lines.append(original_lines[curr_orig_idx])
            curr_orig_idx += 1
        elif prefix == "-":
            if curr_orig_idx >= len(original_lines) or original_lines[curr_orig_idx] != content:
                raise PatchApplyError(
                    f"Deletion line mismatch: expected {repr(content)}, found {repr(original_lines[curr_orig_idx]) if curr_orig_idx < len(original_lines) else '<EOF>'}"
                )
            curr_orig_idx += 1
        elif prefix == "+":
            output_lines.append(content)

    output_lines.extend(original_lines[curr_orig_idx:])
    return output_lines

