"""Symbol-aware code chunker generating CodeChunks from a RepositoryManifest."""

import os
from typing import Dict, List, Optional, Set

from app.indexing.schemas import (
    ChunkSymbolKind,
    CodeChunk,
    INDEX_VERSION,
    content_hash,
)
from app.ingestion.schemas import FileEntry, RepositoryManifest, SymbolKind

# SymbolKind -> ChunkSymbolKind mapping
_SYMBOL_KIND_MAP: Dict[SymbolKind, ChunkSymbolKind] = {
    SymbolKind.FUNCTION: ChunkSymbolKind.FUNCTION,
    SymbolKind.CLASS: ChunkSymbolKind.CLASS,
    SymbolKind.METHOD: ChunkSymbolKind.METHOD,
    SymbolKind.FASTAPI_ROUTE: ChunkSymbolKind.ROUTE,
    SymbolKind.EXPRESS_ROUTE: ChunkSymbolKind.ROUTE,
}

# Symbol kinds that produce meaningful chunks
_CHUNKABLE_KINDS: Set[SymbolKind] = set(_SYMBOL_KIND_MAP.keys())

# Maximum lines for a file-level fallback chunk
MAX_FILE_FALLBACK_LINES: int = 500


def _make_chunk_id(commit_sha: str, file_path: str, symbol: str, start_line: int) -> str:
    """Build a deterministic chunk ID from its identity coordinates."""
    return f"{commit_sha[:12]}:{file_path}:{symbol}:{start_line}"


def _extract_content(file_content: str, start_line: int, end_line: int) -> str:
    """Extract content for a given 1-indexed line range."""
    lines = file_content.split("\n")
    selected = lines[max(0, start_line - 1):end_line]
    return "\n".join(selected)


def chunk_file(
    file_entry: FileEntry,
    commit_sha: str,
    file_content: str,
) -> List[CodeChunk]:
    """Generate CodeChunks from a single file's parsed symbols.

    Symbol-derived chunks are created for FUNCTION, CLASS, METHOD,
    FASTAPI_ROUTE, and EXPRESS_ROUTE symbols. If no chunkable symbol
    exists, a bounded file-level fallback chunk is emitted.
    """
    clean_path = file_entry.path.replace("\\", "/")
    chunks: List[CodeChunk] = []

    chunkable_symbols = [s for s in file_entry.symbols if s.kind in _CHUNKABLE_KINDS]

    if chunkable_symbols:
        for sym in chunkable_symbols:
            chunk_kind = _SYMBOL_KIND_MAP[sym.kind]
            sym_content = _extract_content(file_content, sym.start_line, sym.end_line)
            if not sym_content.strip():
                continue

            c_hash = content_hash(sym_content)
            chunk_id = _make_chunk_id(commit_sha, clean_path, sym.name, sym.start_line)

            chunks.append(
                CodeChunk(
                    chunk_id=chunk_id,
                    commit_sha=commit_sha,
                    file_path=clean_path,
                    language=file_entry.language,
                    symbol=sym.name,
                    symbol_kind=chunk_kind,
                    start_line=sym.start_line,
                    end_line=sym.end_line,
                    content=sym_content,
                    content_hash=c_hash,
                    index_version=INDEX_VERSION,
                )
            )
    else:
        # File-level fallback: bounded to MAX_FILE_FALLBACK_LINES
        if file_entry.is_binary or not file_content.strip():
            return chunks

        total_lines = file_entry.lines_count or len(file_content.split("\n"))
        end_line = min(total_lines, MAX_FILE_FALLBACK_LINES)
        fallback_content = _extract_content(file_content, 1, end_line)

        if fallback_content.strip():
            c_hash = content_hash(fallback_content)
            basename = os.path.basename(clean_path)
            chunk_id = _make_chunk_id(commit_sha, clean_path, basename, 1)

            chunks.append(
                CodeChunk(
                    chunk_id=chunk_id,
                    commit_sha=commit_sha,
                    file_path=clean_path,
                    language=file_entry.language,
                    symbol=basename,
                    symbol_kind=ChunkSymbolKind.FILE,
                    start_line=1,
                    end_line=end_line,
                    content=fallback_content,
                    content_hash=c_hash,
                    index_version=INDEX_VERSION,
                )
            )

    return chunks


def chunk_manifest(
    manifest: RepositoryManifest,
    file_contents: Dict[str, str],
) -> List[CodeChunk]:
    """Generate all CodeChunks from a RepositoryManifest and file contents.

    Args:
        manifest: Parsed repository manifest with file entries and symbols.
        file_contents: Mapping of file paths to source code text.

    Returns:
        Deterministic list of CodeChunks.
    """
    all_chunks: List[CodeChunk] = []

    for file_entry in manifest.files:
        clean_path = file_entry.path.replace("\\", "/")
        source = file_contents.get(clean_path, file_contents.get(file_entry.path, ""))

        if not source and file_entry.is_binary:
            continue

        file_chunks = chunk_file(file_entry, manifest.commit_hash, source)
        all_chunks.extend(file_chunks)

    return all_chunks
