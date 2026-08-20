"""Build comprehensive RepositoryManifest by inspecting files, detecting frameworks, and parsing AST symbols."""

import os
import time
from typing import Dict, List, Set
from app.core.config import get_settings
from app.ingestion.detector import detect_frameworks, detect_language
from app.ingestion.parser import parse_file
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
) -> RepositoryManifest:
    """Scan and parse an ingested repository workspace into a typed RepositoryManifest."""
    start_time = time.perf_counter()
    settings = get_settings()

    total_files = 0
    total_size_bytes = 0
    file_entries: List[FileEntry] = []
    language_counts: Dict[str, int] = {}

    max_files = settings.MAX_REPO_FILES
    max_file_size = settings.MAX_FILE_SIZE_BYTES

    # 1. Walk directory tree safely
    for root, dirs, files in os.walk(repo_dir, topdown=True):
        # Prune ignored directories in place
        dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORE_DIRS and not d.startswith(".")]

        for filename in files:
            if total_files >= max_files:
                break

            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, repo_dir).replace("\\", "/")

            try:
                file_stat = os.stat(abs_path)
                file_size = file_stat.st_size
            except Exception:
                continue

            total_files += 1
            total_size_bytes += file_size

            lang = detect_language(rel_path)
            if lang:
                language_counts[lang] = language_counts.get(lang, 0) + 1

            # Skip reading files that exceed the single file limit
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

            try:
                with open(abs_path, "rb") as f:
                    content_bytes = f.read()

                if _is_binary_file(rel_path, content_bytes):
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

                # Parse AST symbols if language is supported by tree-sitter
                symbols = []
                if lang in ("python", "javascript", "typescript", "tsx"):
                    symbols = parse_file(rel_path, lang, content_bytes)

                file_entries.append(
                    FileEntry(
                        path=rel_path,
                        language=lang,
                        size_bytes=file_size,
                        lines_count=lines_count,
                        symbols=symbols,
                        is_binary=False,
                    )
                )

            except Exception as exc:
                file_entries.append(
                    FileEntry(
                        path=rel_path,
                        language=lang,
                        size_bytes=file_size,
                        lines_count=0,
                        skipped_reason=f"read_error: {str(exc)}",
                    )
                )

    # 2. Detect frameworks from repository files
    frameworks = detect_frameworks(repo_dir)

    duration_ms = (time.perf_counter() - start_time) * 1000.0

    return RepositoryManifest(
        repository_url=repository_url,
        commit_hash=commit_hash,
        branch=branch,
        total_files=total_files,
        total_size_bytes=total_size_bytes,
        languages=language_counts,
        frameworks=frameworks,
        files=file_entries,
        scan_duration_ms=duration_ms,
    )
