"""Deterministic eligibility shared by ingestion and every source consumer."""

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath


CLASSIFICATION_VERSION = "classification/1"


class FileClass(str, Enum):
    SOURCE = "SOURCE"
    TEST = "TEST"
    CONFIG = "CONFIG"
    DOC = "DOC"
    GENERATED = "GENERATED"
    VENDORED = "VENDORED"
    MINIFIED = "MINIFIED"
    BINARY = "BINARY"
    LOCKFILE = "LOCKFILE"
    BUILD_ARTIFACT = "BUILD_ARTIFACT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Disposition:
    classification: FileClass
    eligible: bool
    reason: str


def classify_file(path: str, *, language: str | None, sample: bytes = b"", mode: str = "100644") -> Disposition:
    """Repository hints never authorize execution or following external paths."""
    normalized = path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    name = parts[-1].lower() if parts else ""
    directories = {part.lower() for part in parts[:-1]}
    if mode not in {"100644", "100755"}:
        return Disposition(FileClass.UNKNOWN, False, "symlink_or_submodule")
    if not parts or normalized.startswith("/") or any(part in {".", ".."} for part in parts):
        return Disposition(FileClass.UNKNOWN, False, "unsafe_path")
    if directories & {".git", "node_modules", "vendor", "third_party", ".venv", "venv"}:
        return Disposition(FileClass.VENDORED, False, "vendored_directory")
    if directories & {"dist", "build", ".next", "__pycache__", ".cache", "coverage", "out"}:
        return Disposition(FileClass.BUILD_ARTIFACT, False, "build_directory")
    if name.endswith((".min.js", ".min.css", ".map")):
        return Disposition(FileClass.MINIFIED, False, "minified_or_source_map")
    if b"\x00" in sample or name.endswith((".png", ".jpg", ".zip", ".pdf", ".exe", ".dll", ".db", ".sqlite", ".woff", ".pyc")):
        return Disposition(FileClass.BINARY, False, "binary_file")
    if name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock", "cargo.lock", "go.sum"}:
        return Disposition(FileClass.LOCKFILE, False, "dependency_scanner_only")
    if name.endswith((".generated.ts", "_pb2.py", ".g.cs")) or b"@generated" in sample[:2048].lower():
        return Disposition(FileClass.GENERATED, False, "generated_source")
    if directories & {"tests", "test", "__tests__"} or name.startswith("test_") or any(marker in name for marker in (".test.", ".spec.", "_test.")):
        return Disposition(FileClass.TEST, True, "passive_test_source")
    if language in {"python", "javascript", "typescript", "tsx"}:
        return Disposition(FileClass.SOURCE, True, "supported_source")
    if name.endswith((".json", ".toml", ".yaml", ".yml", ".ini")) or name in {"requirements.txt", "dockerfile", ".env.example"}:
        return Disposition(FileClass.CONFIG, True, "bounded_configuration")
    if name.endswith((".md", ".rst", ".txt")):
        return Disposition(FileClass.DOC, False, "documentation_not_behavior_authority")
    return Disposition(FileClass.UNKNOWN, False, "unsupported_source")
