"""Build comprehensive RepositoryManifest by inspecting files, detecting frameworks, and parsing AST symbols."""

import hashlib
import os
import stat
import time
from typing import Dict, List, Set
from app.core.config import get_settings
from app.ingestion.detector import detect_frameworks, detect_language
from app.ingestion.parser import parse_file, parse_file_with_calls
from app.ingestion.schemas import FileEntry, RepositoryManifest

# Directories to always skip during repository inspection
DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".next",
    "dist",
    "build",
    "out",
    ".idea",
    ".vscode",
    ".coverage",
    "htmlcov",
    ".turbo",
    ".cache",
}

_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _is_link_or_reparse_point(path: str) -> bool:
    """Detect links/junctions without following them during hostile-tree walks."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    )


def _is_confined_path(root: str, path: str) -> bool:
    """Compare resolved paths using platform-aware path semantics."""
    try:
        resolved_root = os.path.normcase(os.path.realpath(root))
        resolved_path = os.path.normcase(os.path.realpath(path))
        return os.path.commonpath((resolved_root, resolved_path)) == resolved_root
    except (OSError, ValueError):
        return False

# Binary file extensions that should not be parsed as text
BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".mov",
    ".pyc", ".pyo", ".pyd",
    ".db", ".sqlite", ".sqlite3",
}


def _is_binary_file(file_path: str, sample_bytes: bytes) -> bool:
    """Check if file is binary by extension or null-byte heuristic."""
    _, ext = os.path.splitext(file_path)
    if ext.lower() in BINARY_EXTENSIONS:
        return True
    return b"\x00" in sample_bytes[:1024]


def build_manifest(
    repo_dir: str,
    repository_url: str,
    commit_hash: str,
    branch: str | None = None,
    requested_branch: str | None = None,
    resolved_branch_or_ref: str | None = None,
) -> RepositoryManifest:
    """Scan and parse an ingested repository workspace into a typed RepositoryManifest."""
    start_time = time.perf_counter()
    settings = get_settings()

    total_observed_files = 0
    total_observed_bytes = 0
    processed_source_bytes = 0
    processed_files_count = 0
    is_truncated = False
    truncation_reason: str | None = None

    file_entries: List[FileEntry] = []
    language_counts: Dict[str, int] = {}
    framework_manifest_contents: dict[str, bytes] = {}

    max_files = settings.MAX_REPO_FILES
    max_file_size = settings.MAX_FILE_SIZE_BYTES
    max_total_source_bytes = getattr(settings, "MAX_TOTAL_SOURCE_BYTES", 52_428_800)
    resolved_repo_root = os.path.realpath(os.path.abspath(repo_dir))

    # 1. Walk directory tree safely
    for root, dirs, files in os.walk(resolved_repo_root, topdown=True, followlinks=False):
        # Prune ignored directories in place
        safe_dirs = []
        for dirname in dirs:
            directory_path = os.path.join(root, dirname)
            if dirname in DEFAULT_IGNORE_DIRS or dirname.startswith("."):
                continue
            if _is_link_or_reparse_point(directory_path) or not _is_confined_path(
                resolved_repo_root, directory_path
            ):
                is_truncated = True
                truncation_reason = "unsafe_link_or_reparse_entry"
                continue
            safe_dirs.append(dirname)
        dirs[:] = safe_dirs

        for filename in files:
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, resolved_repo_root).replace("\\", "/")
            total_observed_files += 1

            # Never stat/open a repository-provided link. Even an in-root link
            # can change what a manifest path means between ingestion and use.
            if _is_link_or_reparse_point(abs_path) or not _is_confined_path(
                resolved_repo_root, abs_path
            ):
                is_truncated = True
                truncation_reason = "unsafe_link_or_reparse_entry"
                file_entries.append(
                    FileEntry(
                        path=rel_path,
                        language=detect_language(filename),
                        size_bytes=0,
                        lines_count=0,
                        skipped_reason="unsafe_link_or_reparse_entry",
                    )
                )
                continue

            try:
                file_size = os.path.getsize(abs_path)
                total_observed_bytes += file_size

                if total_observed_files > max_files:
                    is_truncated = True
                    truncation_reason = f"exceeded_max_repo_files ({max_files})"
                    break

                lang = detect_language(filename)
                if lang:
                    language_counts[lang] = language_counts.get(lang, 0) + 1

                # Check if adding this file's size exceeds total source byte budget
                if processed_source_bytes + file_size > max_total_source_bytes:
                    is_truncated = True
                    truncation_reason = f"exceeded_max_total_source_bytes ({max_total_source_bytes} bytes)"
                    file_entries.append(
                        FileEntry(
                            path=rel_path,
                            language=lang,
                            size_bytes=file_size,
                            lines_count=0,
                            skipped_reason="total_source_byte_budget_exceeded",
                        )
                    )
                    continue

                # Skip individual oversized files
                if file_size > max_file_size:
                    file_entries.append(
                        FileEntry(
                            path=rel_path,
                            language=lang,
                            size_bytes=file_size,
                            lines_count=0,
                            skipped_reason="exceeds_max_size",
                        )
                    )
                    continue

                # Read text and count lines
                with open(abs_path, "rb") as f:
                    content_bytes = f.read(max_file_size + 1)

                # The stat check above is an early optimization, not the byte
                # authority. Bound the read itself and fail closed on a
                # concurrent file replacement/resize.
                if len(content_bytes) > max_file_size:
                    file_entries.append(
                        FileEntry(
                            path=rel_path,
                            language=lang,
                            size_bytes=file_size,
                            lines_count=0,
                            skipped_reason="exceeds_max_size",
                        )
                    )
                    continue
                if len(content_bytes) != file_size:
                    file_entries.append(
                        FileEntry(
                            path=rel_path,
                            language=lang,
                            size_bytes=file_size,
                            lines_count=0,
                            skipped_reason="file_changed_during_read",
                        )
                    )
                    continue

                # Basic binary check
                if b"\x00" in content_bytes:
                    file_entries.append(
                        FileEntry(
                            path=rel_path,
                            language=lang,
                            size_bytes=file_size,
                            lines_count=0,
                            is_binary=True,
                            skipped_reason="binary_file",
                        )
                    )
                    continue

                if rel_path in {"package.json", "requirements.txt", "pyproject.toml"}:
                    framework_manifest_contents[rel_path] = content_bytes

                lines_count = content_bytes.count(b"\n") + (1 if content_bytes and not content_bytes.endswith(b"\n") else 0)

                # Parse AST symbols and calls if language is supported by tree-sitter
                symbols = []
                calls = []
                if lang in ("python", "javascript", "typescript", "tsx"):
                    symbols, calls = parse_file_with_calls(rel_path, lang, content_bytes)

                file_entries.append(
                    FileEntry(
                        path=rel_path,
                        language=lang,
                        size_bytes=file_size,
                        content_sha256=hashlib.sha256(content_bytes).hexdigest(),
                        lines_count=lines_count,
                        symbols=symbols,
                        calls=calls,
                        is_binary=False,
                    )
                )
                processed_source_bytes += len(content_bytes)
                processed_files_count += 1

            except Exception as exc:
                file_entries.append(
                    FileEntry(
                        path=rel_path,
                        language=None,
                        size_bytes=0,
                        lines_count=0,
                        skipped_reason=f"read_error: {str(exc)}",
                    )
                )

        if is_truncated and total_observed_files > max_files:
            break

    # 2. Detect frameworks from repository files
    frameworks = detect_frameworks(
        repo_dir,
        max_file_bytes=max_file_size,
        manifest_contents=framework_manifest_contents,
    )

    # 3. Determine truthful Git branch and ref metadata if available
    from app.ingestion.clone import get_git_resolved_branch_or_ref
    git_resolved = get_git_resolved_branch_or_ref(repo_dir)

    resolved_branch = resolved_branch_or_ref or git_resolved or branch
    req_branch = requested_branch if requested_branch is not None else (branch if branch else None)

    duration_ms = (time.perf_counter() - start_time) * 1000.0

    from app.ingestion.schemas import AnalysisScope

    scope = AnalysisScope(
        truncated=is_truncated,
        reason=truncation_reason,
        files_processed=processed_files_count,
        source_bytes_processed=processed_source_bytes,
        total_observed_files=total_observed_files,
        total_observed_bytes=total_observed_bytes,
    )

    return RepositoryManifest(
        repository_url=repository_url,
        commit_hash=commit_hash,
        commit_sha=commit_hash,
        branch=resolved_branch or req_branch,
        requested_branch=req_branch,
        resolved_branch_or_ref=resolved_branch,
        total_files=total_observed_files,
        total_size_bytes=total_observed_bytes,
        languages=language_counts,
        frameworks=frameworks,
        files=file_entries,
        scan_duration_ms=duration_ms,
        analysis_scope=scope,
    )
