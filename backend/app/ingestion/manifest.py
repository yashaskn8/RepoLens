"""Build comprehensive RepositoryManifest by inspecting files, detecting frameworks, and parsing AST symbols."""

import os
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

    max_files = settings.MAX_REPO_FILES
    max_file_size = settings.MAX_FILE_SIZE_BYTES
    max_total_source_bytes = getattr(settings, "MAX_TOTAL_SOURCE_BYTES", 52_428_800)

    # 1. Walk directory tree safely
    for root, dirs, files in os.walk(repo_dir, topdown=True):
        # Prune ignored directories in place
        dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORE_DIRS and not d.startswith(".")]

        for filename in files:
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, repo_dir).replace("\\", "/")
            total_observed_files += 1

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
                    content_bytes = f.read()

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
                        lines_count=lines_count,
                        symbols=symbols,
                        calls=calls,
                        is_binary=False,
                    )
                )
                processed_source_bytes += file_size
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
    frameworks = detect_frameworks(repo_dir)

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
