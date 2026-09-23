"""Fixed, public-only DEV repository-scan case loader.

This intentionally does not discover files recursively and accepts no path
override. Private holdout data is governed separately and must never be
materialized by iterative development evaluation.
"""

from __future__ import annotations

import os
from pathlib import Path

from app.evaluation.ground_truth.loader import BenchmarkDatasetLoader
from app.evaluation.ground_truth.schemas import BenchmarkCase, BenchmarkSplit, TargetPipeline


# Explicit inventory of the public DEV repository-scan cases. Keeping this
# closed prevents a newly placed private/holdout file from being opened before
# its split is inspected by the general-purpose benchmark loader.
PUBLIC_DEV_REPOSITORY_SCAN_FILES: tuple[str, ...] = (
    "correctness/BUG-ASYNC-BLOCK-01A.json",
    "correctness/BUG-ASYNC-BLOCK-01B.json",
    "correctness/BUG-ASYNC-BLOCK-01C.json",
    "correctness/BUG-ASYNC-BLOCK-01D.json",
    "correctness/BUG-EXCEPT-01A.json",
    "correctness/BUG-EXCEPT-01B.json",
    "correctness/BUG-EXCEPT-01C.json",
    "correctness/BUG-EXCEPT-01D.json",
    "correctness/BUG-UNAWAITED-01A.json",
    "correctness/BUG-UNAWAITED-01B.json",
    "correctness/BUG-UNAWAITED-01C.json",
    "correctness/BUG-UNAWAITED-01D.json",
    "security/SEC-AUTH-01A.json",
    "security/SEC-AUTH-01B.json",
    "security/SEC-AUTH-01C.json",
    "security/SEC-AUTH-01D.json",
    "security/SEC-AUTH-02A.json",
    "security/SEC-AUTH-02B.json",
    "security/SEC-AUTH-02C.json",
    "security/SEC-AUTH-02D.json",
    "security/SEC-CMDI-01A.json",
    "security/SEC-CMDI-01B.json",
    "security/SEC-CMDI-01C.json",
    "security/SEC-CMDI-01D.json",
    "security/SEC-CRED-01A.json",
    "security/SEC-CRED-01B.json",
    "security/SEC-CRED-01C.json",
    "security/SEC-CRED-01D.json",
    "security/SEC-CRED-02A.json",
    "security/SEC-CRED-02B.json",
    "security/SEC-CRED-02C.json",
    "security/SEC-SQLI-01A.json",
    "security/SEC-SQLI-01B.json",
    "security/SEC-SQLI-01C.json",
    "security/SEC-SQLI-01D.json",
)
PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS: tuple[str, ...] = tuple(sorted(
    Path(relative).stem for relative in PUBLIC_DEV_REPOSITORY_SCAN_FILES
))


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical_public_cases_root() -> Path:
    return _repository_root() / "evaluation_data" / "ground_truth" / "v1" / "cases"


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _preflight_paths(
    root: Path,
    relative_paths: tuple[str, ...],
    *,
    trusted_base: Path,
) -> tuple[Path, ...]:
    """Validate the entire fixed inventory before any case content is read."""
    if _is_link_or_junction(trusted_base) or not trusted_base.is_dir():
        raise ValueError("trusted repository root is unavailable or linked")
    resolved_base = trusted_base.resolve(strict=True)
    absolute_root = Path(os.path.abspath(root))
    try:
        root_relative = absolute_root.relative_to(resolved_base)
    except ValueError as exc:
        raise ValueError("canonical public DEV dataset root is outside the trusted repository") from exc
    if any(part in {".", ".."} for part in root_relative.parts):
        raise ValueError("canonical public DEV dataset root contains traversal")

    current_root = resolved_base
    for part in root_relative.parts:
        current_root = current_root / part
        if _is_link_or_junction(current_root):
            raise ValueError("linked or junctioned public DEV dataset ancestor is forbidden")
        if not current_root.exists():
            raise FileNotFoundError("canonical public DEV dataset root is unavailable")
        resolved = current_root.resolve(strict=True)
        try:
            common = os.path.commonpath((str(resolved_base), str(resolved)))
        except ValueError as exc:
            raise ValueError("public DEV dataset ancestor escapes the trusted repository") from exc
        if os.path.normcase(common) != os.path.normcase(str(resolved_base)):
            raise ValueError("public DEV dataset ancestor escapes the trusted repository")
    root = current_root
    if not root.is_dir():
        raise ValueError("canonical public DEV dataset root is unavailable")
    resolved_root = root.resolve(strict=True)
    paths: list[Path] = []
    for relative in relative_paths:
        relative_path = Path(relative)
        if relative_path.is_absolute() or any(part in {".", ".."} for part in relative_path.parts):
            raise ValueError("public DEV inventory contains an invalid relative path")
        if any("holdout" in part.casefold() or "private" in part.casefold() for part in relative_path.parts):
            raise ValueError("private or holdout paths are forbidden in the public DEV inventory")
        current = root
        for part in relative_path.parts:
            current = current / part
            if _is_link_or_junction(current):
                raise ValueError("linked or junctioned public DEV case path is forbidden")
            if not current.exists():
                raise FileNotFoundError("a canonical public DEV case file is missing")
            resolved = current.resolve(strict=True)
            try:
                common = os.path.commonpath((str(resolved_root), str(resolved)))
            except ValueError as exc:
                raise ValueError("public DEV case path escapes the canonical dataset root") from exc
            if os.path.normcase(common) != os.path.normcase(str(resolved_root)):
                raise ValueError("public DEV case path escapes the canonical dataset root")
        if not current.is_file():
            raise ValueError("canonical public DEV inventory entries must be files")
        paths.append(current)
    return tuple(paths)


def load_public_dev_repository_cases() -> list[BenchmarkCase]:
    """Load only the fixed public DEV repository-scan inventory.

    No environment variable, CLI argument, symlink, recursive discovery, or
    caller-provided path can broaden the files read by this function.
    """
    paths = _preflight_paths(
        _canonical_public_cases_root(),
        PUBLIC_DEV_REPOSITORY_SCAN_FILES,
        trusted_base=_repository_root(),
    )
    loader = BenchmarkDatasetLoader()
    cases: list[BenchmarkCase] = []
    seen_ids: set[str] = set()
    for relative, path in zip(PUBLIC_DEV_REPOSITORY_SCAN_FILES, paths, strict=True):
        case = loader.load_case_file(path)
        if case.case_id != Path(relative).stem:
            raise ValueError("public DEV case identity does not match the fixed inventory")
        if case.split != BenchmarkSplit.DEV or case.target_pipeline != TargetPipeline.REPOSITORY_SCAN:
            raise ValueError("fixed public DEV inventory contains a case outside its authorized split")
        if case.case_id in seen_ids:
            raise ValueError("fixed public DEV inventory contains duplicate case identities")
        seen_ids.add(case.case_id)
        cases.append(case)
    return sorted(cases, key=lambda item: item.case_id)


__all__ = [
    "PUBLIC_DEV_REPOSITORY_SCAN_CASE_IDS",
    "PUBLIC_DEV_REPOSITORY_SCAN_FILES",
    "load_public_dev_repository_cases",
]
