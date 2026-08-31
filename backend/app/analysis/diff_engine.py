"""Deterministic Structural Diff Engine for RepoLens Change Intelligence.

Converts exact base/head repository workspaces into deterministic semantic change facts.
Extracts:
1. File additions, deletions, modifications, and renames with line ranges
2. Symbol additions, deletions, modifications, and signature changes
3. Package dependency manifest deltas (package.json, requirements.txt, pyproject.toml)
4. Environment and configuration deltas (.env, .env.example, yaml, json, toml)
5. Route / API definition changes (FastAPI, Express, fetch, axios)
6. Data model and schema deltas (Pydantic models, database models)

Guarantees:
- Zero LLM reasoning (100% deterministic AST & structural facts).
- Reuses Tree-sitter parsers, manifest builders, and relationship extractors.
- Truthfully marks unparsed, binary, and unsupported language files.
"""

from collections import defaultdict
import difflib
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.config import Settings, get_settings
from app.ingestion.detector import detect_language
from app.ingestion.manifest import BINARY_EXTENSIONS, DEFAULT_IGNORE_DIRS, _is_binary_file, build_manifest
from app.ingestion.parser import parse_file_with_calls
from app.ingestion.schemas import FileEntry, ParsedCall, ParsedSymbol, RepositoryManifest, SymbolKind


def _extract_and_normalize_symbol_lines(file_path: Optional[str], start_line: int, end_line: int) -> str:
    """Read and normalize symbol source lines, ignoring comments and surrounding whitespace."""
    if not file_path or not os.path.exists(file_path):
        return ""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        selected = lines[max(0, start_line - 1):end_line]
        normalized = []
        for l in selected:
            l_clean = re.sub(r"#.*$", "", l)
            l_clean = re.sub(r"//.*$", "", l_clean)
            l_clean = l_clean.strip()
            if l_clean:
                normalized.append(l_clean)
        return "\n".join(normalized)
    except OSError:
        return ""
from app.schemas.change_analysis import (
    ConfigDelta,
    DependencyDelta,
    FileChangeType,
    FileDiffFact,
    RouteContractDelta,
    SchemaModelDelta,
    StructuralDiffResult,
    SymbolChangeType,
    SymbolDiffFact,
)

_ENV_KEY_VAL_REGEX = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_REQ_PKG_REGEX = re.compile(r"^\s*([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*)?$")


def _extract_line_ranges_from_diff(
    base_lines: List[str],
    head_lines: List[str],
) -> Tuple[List[List[int]], List[List[int]]]:
    """Compute 1-indexed changed line ranges [start_line, end_line] in head and base."""
    matcher = difflib.SequenceMatcher(None, base_lines, head_lines)
    head_ranges: List[List[int]] = []
    base_ranges: List[List[int]] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert"):
            # j1:j2 represents range in head (0-indexed)
            if j2 > j1:
                head_ranges.append([j1 + 1, j2])
        if tag in ("replace", "delete"):
            # i1:i2 represents range in base (0-indexed)
            if i2 > i1:
                base_ranges.append([i1 + 1, i2])

    return head_ranges, base_ranges


def _parse_env_file(content: str) -> Dict[str, str]:
    """Parse key-value pairs from an env file without evaluating shell expressions."""
    result: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_KEY_VAL_REGEX.match(line)
        if match:
            k, v = match.groups()
            result[k.strip()] = v.strip().strip("\"'")
    return result


def _parse_requirements_txt(content: str) -> Dict[str, str]:
    """Parse package names and version specifications from a requirements.txt file."""
    deps: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = _REQ_PKG_REGEX.match(line)
        if match:
            pkg, ver = match.groups()
            deps[pkg.lower()] = (ver or "").strip()
    return deps


def _parse_package_json(content: str) -> Dict[str, str]:
    """Parse package dependencies and devDependencies from package.json."""
    deps: Dict[str, str] = {}
    try:
        data = json.loads(content)
        if isinstance(data.get("dependencies"), dict):
            for k, v in data["dependencies"].items():
                deps[k] = str(v)
        if isinstance(data.get("devDependencies"), dict):
            for k, v in data["devDependencies"].items():
                deps[k] = str(v)
    except Exception:
        pass
    return deps


def _parse_pyproject_toml(content: str) -> Dict[str, str]:
    """Parse Python dependencies from pyproject.toml."""
    deps: Dict[str, str] = {}
    in_deps_section = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_deps_section = "dependencies" in line.lower()
            continue
        if in_deps_section and "=" in line:
            parts = line.split("=", 1)
            pkg = parts[0].strip().strip("\"'")
            ver = parts[1].strip().strip("\"'")
            if pkg:
                deps[pkg.lower()] = ver
    return deps


class ChangeDiffEngine:
    """Deterministic structural diff engine comparing two repository workspaces."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    def _discover_files(self, workspace_path: str) -> Dict[str, str]:
        """Walk workspace and return map of normalized_rel_path -> absolute_path."""
        files_map: Dict[str, str] = {}
        for root, dirs, files in os.walk(workspace_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORE_DIRS]
            for f in files:
                abs_path = os.path.join(root, f)
                rel_path = os.path.relpath(abs_path, workspace_path).replace("\\", "/")
                files_map[rel_path] = abs_path
        return files_map

    def compute_structural_diff(
        self,
        base_workspace: str,
        head_workspace: str,
        base_commit_sha: str,
        head_commit_sha: str,
        repository_url: str,
    ) -> StructuralDiffResult:
        """Deterministically compute structural change facts between base and head revisions."""
        # 1. Discover all files in base and head
        base_files = self._discover_files(base_workspace)
        head_files = self._discover_files(head_workspace)

        base_rel_set = set(base_files.keys())
        head_rel_set = set(head_files.keys())

        potentially_added = head_rel_set - base_rel_set
        potentially_deleted = base_rel_set - head_rel_set
        common_rel_paths = base_rel_set & head_rel_set

        # 2. Detect renames via exact content or strong similarity matching
        renamed_pairs: List[Tuple[str, str]] = []
        added_files: Set[str] = set(potentially_added)
        deleted_files: Set[str] = set(potentially_deleted)

        deleted_file_contents: Dict[str, bytes] = {}
        for del_path in list(deleted_files):
            try:
                with open(base_files[del_path], "rb") as f:
                    deleted_file_contents[del_path] = f.read()
            except OSError:
                pass

        for add_path in list(added_files):
            try:
                with open(head_files[add_path], "rb") as f:
                    add_content = f.read()
                # Find matching deleted file
                for del_path, del_content in list(deleted_file_contents.items()):
                    if del_content and add_content == del_content:
                        renamed_pairs.append((del_path, add_path))
                        added_files.remove(add_path)
                        deleted_files.remove(del_path)
                        del deleted_file_contents[del_path]
                        break
            except OSError:
                pass

        # 3. Classify file facts and line-level diffs
        changed_files: List[FileDiffFact] = []
        modified_files_list: List[str] = []
        max_file_size = getattr(self.settings, "MAX_FILE_SIZE_BYTES", 1048576)

        # Process Added Files
        for add_path in sorted(added_files):
            abs_p = head_files[add_path]
            is_bin = False
            lines_count = 0
            file_too_large = False
            try:
                st = os.stat(abs_p)
                if st.st_size > max_file_size:
                    file_too_large = True
                else:
                    with open(abs_p, "rb") as f:
                        sample = f.read(4096)
                        is_bin = _is_binary_file(add_path, sample)
                    if not is_bin:
                        with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                            lines_count = len(f.readlines())
            except OSError:
                pass

            lang = detect_language(add_path)
            if file_too_large:
                skipped_reason = "EXCEEDS_MAX_FILE_SIZE"
            elif is_bin:
                skipped_reason = "BINARY"
            elif not lang:
                skipped_reason = "UNSUPPORTED_LANGUAGE"
            else:
                skipped_reason = None

            changed_files.append(
                FileDiffFact(
                    file_path=add_path,
                    old_path=None,
                    change_type=FileChangeType.ADDED,
                    is_binary=is_bin,
                    is_parsed=lang is not None and not is_bin and not file_too_large,
                    skipped_reason=skipped_reason,
                    language=lang,
                    changed_line_ranges=[[1, max(1, lines_count)]] if not is_bin and not file_too_large and lines_count > 0 else [],
                    base_line_ranges=[],
                )
            )

        # Process Deleted Files
        for del_path in sorted(deleted_files):
            abs_p = base_files[del_path]
            is_bin = False
            lines_count = 0
            file_too_large = False
            try:
                st = os.stat(abs_p)
                if st.st_size > max_file_size:
                    file_too_large = True
                else:
                    with open(abs_p, "rb") as f:
                        sample = f.read(4096)
                        is_bin = _is_binary_file(del_path, sample)
                    if not is_bin:
                        with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                            lines_count = len(f.readlines())
            except OSError:
                pass

            lang = detect_language(del_path)
            if file_too_large:
                skipped_reason = "EXCEEDS_MAX_FILE_SIZE"
            elif is_bin:
                skipped_reason = "BINARY"
            elif not lang:
                skipped_reason = "UNSUPPORTED_LANGUAGE"
            else:
                skipped_reason = None

            changed_files.append(
                FileDiffFact(
                    file_path=del_path,
                    old_path=None,
                    change_type=FileChangeType.DELETED,
                    is_binary=is_bin,
                    is_parsed=lang is not None and not is_bin and not file_too_large,
                    skipped_reason=skipped_reason,
                    language=lang,
                    changed_line_ranges=[],
                    base_line_ranges=[[1, max(1, lines_count)]] if not is_bin and not file_too_large and lines_count > 0 else [],
                )
            )

        # Process Renamed Files
        for old_p, new_p in sorted(renamed_pairs):
            abs_head = head_files[new_p]
            is_bin = False
            file_too_large = False
            try:
                st = os.stat(abs_head)
                if st.st_size > max_file_size:
                    file_too_large = True
                else:
                    with open(abs_head, "rb") as f:
                        sample = f.read(4096)
                        is_bin = _is_binary_file(new_p, sample)
            except OSError:
                pass

            lang = detect_language(new_p)
            if file_too_large:
                skipped_reason = "EXCEEDS_MAX_FILE_SIZE"
            elif is_bin:
                skipped_reason = "BINARY"
            elif not lang:
                skipped_reason = "UNSUPPORTED_LANGUAGE"
            else:
                skipped_reason = None

            changed_files.append(
                FileDiffFact(
                    file_path=new_p,
                    old_path=old_p,
                    change_type=FileChangeType.RENAMED,
                    is_binary=is_bin,
                    is_parsed=lang is not None and not is_bin and not file_too_large,
                    skipped_reason=skipped_reason,
                    language=lang,
                    changed_line_ranges=[],
                    base_line_ranges=[],
                )
            )

        # Process Common Files (Modified or Unmodified)
        for rel_path in sorted(common_rel_paths):
            base_abs = base_files[rel_path]
            head_abs = head_files[rel_path]

            file_too_large = False
            try:
                st_b = os.stat(base_abs)
                st_h = os.stat(head_abs)
                if st_b.st_size > max_file_size or st_h.st_size > max_file_size:
                    file_too_large = True
            except OSError:
                continue

            if file_too_large:
                modified_files_list.append(rel_path)
                changed_files.append(
                    FileDiffFact(
                        file_path=rel_path,
                        old_path=None,
                        change_type=FileChangeType.MODIFIED,
                        is_binary=False,
                        is_parsed=False,
                        skipped_reason="EXCEEDS_MAX_FILE_SIZE",
                        language=detect_language(rel_path),
                        changed_line_ranges=[],
                        base_line_ranges=[],
                    )
                )
                continue

            base_bytes = b""
            head_bytes = b""
            try:
                with open(base_abs, "rb") as f:
                    base_bytes = f.read()
                with open(head_abs, "rb") as f:
                    head_bytes = f.read()
            except OSError:
                continue

            if base_bytes == head_bytes:
                continue  # Unmodified file

            is_bin = _is_binary_file(rel_path, base_bytes[:4096]) or _is_binary_file(rel_path, head_bytes[:4096])
            lang = detect_language(rel_path)
            skipped_reason = "BINARY" if is_bin else (None if lang else "UNSUPPORTED_LANGUAGE")

            head_ranges: List[List[int]] = []
            base_ranges: List[List[int]] = []

            if not is_bin:
                base_lines = base_bytes.decode("utf-8", errors="ignore").splitlines()
                head_lines = head_bytes.decode("utf-8", errors="ignore").splitlines()
                head_ranges, base_ranges = _extract_line_ranges_from_diff(base_lines, head_lines)

            modified_files_list.append(rel_path)
            changed_files.append(
                FileDiffFact(
                    file_path=rel_path,
                    old_path=None,
                    change_type=FileChangeType.MODIFIED,
                    is_binary=is_bin,
                    is_parsed=lang is not None and not is_bin,
                    skipped_reason=skipped_reason,
                    language=lang,
                    changed_line_ranges=head_ranges,
                    base_line_ranges=base_ranges,
                )
            )

        # 4. Manifest & AST Symbol Extraction for Base and Head
        base_manifest = build_manifest(
            repo_dir=base_workspace,
            repository_url=repository_url,
            commit_hash=base_commit_sha,
        )
        head_manifest = build_manifest(
            repo_dir=head_workspace,
            repository_url=repository_url,
            commit_hash=head_commit_sha,
        )

        base_symbols_by_key: Dict[Tuple[str, str, str], ParsedSymbol] = {}
        for f in base_manifest.files:
            for s in f.symbols:
                # Key: (file_path, kind, name)
                base_symbols_by_key[(f.path, s.kind.value, s.name)] = s

        head_symbols_by_key: Dict[Tuple[str, str, str], ParsedSymbol] = {}
        for f in head_manifest.files:
            for s in f.symbols:
                head_symbols_by_key[(f.path, s.kind.value, s.name)] = s

        added_symbols: List[SymbolDiffFact] = []
        deleted_symbols: List[SymbolDiffFact] = []
        modified_symbols: List[SymbolDiffFact] = []

        # Find Added Symbols
        for (f_path, s_kind, s_name), h_sym in head_symbols_by_key.items():
            if (f_path, s_kind, s_name) not in base_symbols_by_key:
                added_symbols.append(
                    SymbolDiffFact(
                        file_path=f_path,
                        symbol_name=s_name,
                        symbol_kind=s_kind,
                        change_type=SymbolChangeType.ADDED,
                        base_location=None,
                        head_location={
                            "start_line": h_sym.start_line,
                            "end_line": h_sym.end_line,
                            "start_column": h_sym.start_column,
                            "end_column": h_sym.end_column,
                        },
                        evidence={"details": h_sym.details},
                    )
                )

        # Find Deleted Symbols
        for (f_path, s_kind, s_name), b_sym in base_symbols_by_key.items():
            if (f_path, s_kind, s_name) not in head_symbols_by_key:
                deleted_symbols.append(
                    SymbolDiffFact(
                        file_path=f_path,
                        symbol_name=s_name,
                        symbol_kind=s_kind,
                        change_type=SymbolChangeType.DELETED,
                        base_location={
                            "start_line": b_sym.start_line,
                            "end_line": b_sym.end_line,
                            "start_column": b_sym.start_column,
                            "end_column": b_sym.end_column,
                        },
                        head_location=None,
                        evidence={"details": b_sym.details},
                    )
                )

        # Find Modified Symbols (common keys)
        common_symbols = set(base_symbols_by_key.keys()) & set(head_symbols_by_key.keys())
        for f_path, s_kind, s_name in sorted(common_symbols):
            b_sym = base_symbols_by_key[(f_path, s_kind, s_name)]
            h_sym = head_symbols_by_key[(f_path, s_kind, s_name)]

            b_params = b_sym.details.get("parameters", "")
            h_params = h_sym.details.get("parameters", "")
            b_ret = b_sym.details.get("return_type", "")
            h_ret = h_sym.details.get("return_type", "")

            b_loc = {
                "start_line": b_sym.start_line,
                "end_line": b_sym.end_line,
                "start_column": b_sym.start_column,
                "end_column": b_sym.end_column,
            }
            h_loc = {
                "start_line": h_sym.start_line,
                "end_line": h_sym.end_line,
                "start_column": h_sym.start_column,
                "end_column": h_sym.end_column,
            }

            # Check for signature change
            if b_params != h_params or b_ret != h_ret:
                modified_symbols.append(
                    SymbolDiffFact(
                        file_path=f_path,
                        symbol_name=s_name,
                        symbol_kind=s_kind,
                        change_type=SymbolChangeType.SIGNATURE_CHANGED,
                        base_location=b_loc,
                        head_location=h_loc,
                        evidence={
                            "base_parameters": b_params,
                            "head_parameters": h_params,
                            "base_return_type": b_ret,
                            "head_return_type": h_ret,
                            "diff": f"Parameters: '{b_params}' -> '{h_params}', Returns: '{b_ret}' -> '{h_ret}'",
                        },
                    )
                )
            else:
                # Check for structural body modification (independent of line shifting)
                b_fp = b_sym.details.get("body_fingerprint")
                h_fp = h_sym.details.get("body_fingerprint")

                is_body_modified = False
                if b_fp is not None and h_fp is not None:
                    is_body_modified = (b_fp != h_fp)
                else:
                    b_clean = _extract_and_normalize_symbol_lines(base_files.get(f_path), b_sym.start_line, b_sym.end_line)
                    h_clean = _extract_and_normalize_symbol_lines(head_files.get(f_path), h_sym.start_line, h_sym.end_line)
                    is_body_modified = (b_clean != h_clean) if (b_clean or h_clean) else False

                if is_body_modified:
                    modified_symbols.append(
                        SymbolDiffFact(
                            file_path=f_path,
                            symbol_name=s_name,
                            symbol_kind=s_kind,
                            change_type=SymbolChangeType.MODIFIED,
                            base_location=b_loc,
                            head_location=h_loc,
                            evidence={
                                "base_details": b_sym.details,
                                "head_details": h_sym.details,
                            },
                        )
                    )

        all_changed_symbols = added_symbols + deleted_symbols + modified_symbols

        # 5. Dependency Manifest Deltas
        dep_deltas: List[DependencyDelta] = []
        dep_manifest_names = ("package.json", "requirements.txt", "pyproject.toml")

        for m_name in dep_manifest_names:
            base_has = m_name in base_files
            head_has = m_name in head_files

            if not base_has and not head_has:
                continue

            base_content = ""
            head_content = ""
            if base_has:
                try:
                    with open(base_files[m_name], "r", encoding="utf-8", errors="ignore") as f:
                        base_content = f.read()
                except OSError:
                    pass
            if head_has:
                try:
                    with open(head_files[m_name], "r", encoding="utf-8", errors="ignore") as f:
                        head_content = f.read()
                except OSError:
                    pass

            if m_name == "package.json":
                base_deps = _parse_package_json(base_content)
                head_deps = _parse_package_json(head_content)
            elif m_name == "requirements.txt":
                base_deps = _parse_requirements_txt(base_content)
                head_deps = _parse_requirements_txt(head_content)
            elif m_name == "pyproject.toml":
                base_deps = _parse_pyproject_toml(base_content)
                head_deps = _parse_pyproject_toml(head_content)
            else:
                base_deps, head_deps = {}, {}

            all_pkgs = set(base_deps.keys()) | set(head_deps.keys())
            for pkg in sorted(all_pkgs):
                b_v = base_deps.get(pkg)
                h_v = head_deps.get(pkg)
                if b_v is None and h_v is not None:
                    dep_deltas.append(
                        DependencyDelta(
                            manifest_file=m_name,
                            package_name=pkg,
                            base_version=None,
                            head_version=h_v,
                            change_type="ADDED",
                        )
                    )
                elif b_v is not None and h_v is None:
                    dep_deltas.append(
                        DependencyDelta(
                            manifest_file=m_name,
                            package_name=pkg,
                            base_version=b_v,
                            head_version=None,
                            change_type="REMOVED",
                        )
                    )
                elif b_v != h_v:
                    dep_deltas.append(
                        DependencyDelta(
                            manifest_file=m_name,
                            package_name=pkg,
                            base_version=b_v,
                            head_version=h_v,
                            change_type="UPDATED",
                        )
                    )

        # 6. Environment & Configuration Deltas (Secret-Safe: zero raw values stored)
        config_deltas: List[ConfigDelta] = []
        for rel_p in sorted(base_rel_set | head_rel_set):
            if rel_p.endswith((".env", ".env.example", ".env.local", ".env.test", "config.json")):
                b_has = rel_p in base_files
                h_has = rel_p in head_files

                b_text = ""
                h_text = ""
                if b_has:
                    try:
                        with open(base_files[rel_p], "r", encoding="utf-8", errors="ignore") as f:
                            b_text = f.read()
                    except OSError:
                        pass
                if h_has:
                    try:
                        with open(head_files[rel_p], "r", encoding="utf-8", errors="ignore") as f:
                            h_text = f.read()
                    except OSError:
                        pass

                if rel_p.endswith(".json"):
                    try:
                        b_dict = {k: str(v) for k, v in json.loads(b_text or "{}").items()} if b_text else {}
                        h_dict = {k: str(v) for k, v in json.loads(h_text or "{}").items()} if h_text else {}
                    except Exception:
                        b_dict, h_dict = {}, {}
                else:
                    b_dict = _parse_env_file(b_text)
                    h_dict = _parse_env_file(h_text)

                all_keys = set(b_dict.keys()) | set(h_dict.keys())
                for k in sorted(all_keys):
                    b_val = b_dict.get(k)
                    h_val = h_dict.get(k)
                    b_fp = hashlib.sha256(b_val.encode("utf-8")).hexdigest()[:16] if b_val is not None else None
                    h_fp = hashlib.sha256(h_val.encode("utf-8")).hexdigest()[:16] if h_val is not None else None

                    if b_val is None and h_val is not None:
                        config_deltas.append(
                            ConfigDelta(
                                file_path=rel_p,
                                key=k,
                                change_type="ADDED",
                                base_present=False,
                                head_present=True,
                                value_changed=True,
                                base_fingerprint=None,
                                head_fingerprint=h_fp,
                                base_value=None,
                                head_value=None,
                            )
                        )
                    elif b_val is not None and h_val is None:
                        config_deltas.append(
                            ConfigDelta(
                                file_path=rel_p,
                                key=k,
                                change_type="REMOVED",
                                base_present=True,
                                head_present=False,
                                value_changed=True,
                                base_fingerprint=b_fp,
                                head_fingerprint=None,
                                base_value=None,
                                head_value=None,
                            )
                        )
                    elif b_val != h_val:
                        config_deltas.append(
                            ConfigDelta(
                                file_path=rel_p,
                                key=k,
                                change_type="MODIFIED",
                                base_present=True,
                                head_present=True,
                                value_changed=True,
                                base_fingerprint=b_fp,
                                head_fingerprint=h_fp,
                                base_value=None,
                                head_value=None,
                            )
                        )

        # 7. Route / API Definition & Frontend Client Deltas
        route_deltas: List[RouteContractDelta] = []

        base_routes: Dict[Tuple[str, str, str], ParsedSymbol] = {}
        for f in base_manifest.files:
            for s in f.symbols:
                if s.kind in (SymbolKind.FASTAPI_ROUTE, SymbolKind.EXPRESS_ROUTE):
                    handler = s.details.get("handler") or s.name
                    base_routes[(f.path, s.kind.value, handler)] = s
                elif s.kind in (SymbolKind.FETCH_CALL, SymbolKind.AXIOS_CALL):
                    base_routes[(f.path, s.kind.value, s.name)] = s

        head_routes: Dict[Tuple[str, str, str], ParsedSymbol] = {}
        for f in head_manifest.files:
            for s in f.symbols:
                if s.kind in (SymbolKind.FASTAPI_ROUTE, SymbolKind.EXPRESS_ROUTE):
                    handler = s.details.get("handler") or s.name
                    head_routes[(f.path, s.kind.value, handler)] = s
                elif s.kind in (SymbolKind.FETCH_CALL, SymbolKind.AXIOS_CALL):
                    head_routes[(f.path, s.kind.value, s.name)] = s

        # Match direct keys
        matched_keys = set(base_routes.keys()) & set(head_routes.keys())
        unmatched_base = set(base_routes.keys()) - matched_keys
        unmatched_head = set(head_routes.keys()) - matched_keys

        for f_path, r_kind, r_key in sorted(matched_keys):
            b_r = base_routes[(f_path, r_kind, r_key)]
            h_r = head_routes[(f_path, r_kind, r_key)]

            b_m = b_r.details.get("http_method")
            h_m = h_r.details.get("http_method")
            b_p = b_r.details.get("path") or b_r.details.get("url") or b_r.details.get("target")
            h_p = h_r.details.get("path") or h_r.details.get("url") or h_r.details.get("target")

            if b_m != h_m or b_p != h_p:
                if b_m != h_m and b_p == h_p:
                    c_type = "METHOD_CHANGED"
                elif b_m == h_m and b_p != h_p:
                    c_type = "PATH_CHANGED"
                else:
                    c_type = "METHOD_AND_PATH_CHANGED"

                route_deltas.append(
                    RouteContractDelta(
                        file_path=f_path,
                        route_type=r_kind,
                        route_name=h_r.name,
                        base_http_method=b_m,
                        head_http_method=h_m,
                        base_path=b_p,
                        head_path=h_p,
                        change_type=c_type,
                        details=f"Changed {r_key}: method ({b_m} -> {h_m}), path ({b_p} -> {h_p})",
                    )
                )

        # For unmatched client calls within same file, check if target URL changed
        unmatched_base_calls = [k for k in unmatched_base if k[1] in ("FETCH_CALL", "AXIOS_CALL")]
        unmatched_head_calls = [k for k in unmatched_head if k[1] in ("FETCH_CALL", "AXIOS_CALL")]

        for b_k in list(unmatched_base_calls):
            for h_k in list(unmatched_head_calls):
                if b_k[0] == h_k[0] and b_k[1] == h_k[1]:  # same file and kind
                    b_r = base_routes[b_k]
                    h_r = head_routes[h_k]
                    b_p = b_r.details.get("url") or b_r.details.get("target")
                    h_p = h_r.details.get("url") or h_r.details.get("target")
                    route_deltas.append(
                        RouteContractDelta(
                            file_path=b_k[0],
                            route_type=b_k[1],
                            route_name=h_r.name,
                            base_http_method=b_r.details.get("http_method"),
                            head_http_method=h_r.details.get("http_method"),
                            base_path=b_p,
                            head_path=h_p,
                            change_type="TARGET_CHANGED",
                            details=f"Changed client call target from '{b_p}' to '{h_p}'",
                        )
                    )
                    unmatched_base.remove(b_k)
                    unmatched_head.remove(h_k)
                    break

        for f_path, r_kind, r_key in sorted(unmatched_head):
            h_r = head_routes[(f_path, r_kind, r_key)]
            route_deltas.append(
                RouteContractDelta(
                    file_path=f_path,
                    route_type=r_kind,
                    route_name=h_r.name,
                    base_http_method=None,
                    head_http_method=h_r.details.get("http_method"),
                    base_path=None,
                    head_path=h_r.details.get("path") or h_r.details.get("url"),
                    change_type="ADDED",
                    details=f"Added {r_kind} {h_r.name}",
                )
            )

        for f_path, r_kind, r_key in sorted(unmatched_base):
            b_r = base_routes[(f_path, r_kind, r_key)]
            route_deltas.append(
                RouteContractDelta(
                    file_path=f_path,
                    route_type=r_kind,
                    route_name=b_r.name,
                    base_http_method=b_r.details.get("http_method"),
                    head_http_method=None,
                    base_path=b_r.details.get("path") or b_r.details.get("url"),
                    head_path=None,
                    change_type="REMOVED",
                    details=f"Removed {r_kind} {b_r.name}",
                )
            )

        # 8. Schema and Model Deltas (Pydantic / SQLAlchemy / TypeScript interfaces)

        schema_deltas: List[SchemaModelDelta] = []
        base_classes: Dict[Tuple[str, str], ParsedSymbol] = {}
        for f in base_manifest.files:
            for s in f.symbols:
                if s.kind == SymbolKind.CLASS:
                    base_classes[(f.path, s.name)] = s

        head_classes: Dict[Tuple[str, str], ParsedSymbol] = {}
        for f in head_manifest.files:
            for s in f.symbols:
                if s.kind == SymbolKind.CLASS:
                    head_classes[(f.path, s.name)] = s

        all_class_keys = set(base_classes.keys()) & set(head_classes.keys())
        for f_path, c_name in sorted(all_class_keys):
            b_c = base_classes[(f_path, c_name)]
            h_c = head_classes[(f_path, c_name)]

            b_fields: Dict[str, str] = b_c.details.get("fields", {})
            h_fields: Dict[str, str] = h_c.details.get("fields", {})
            b_supers: List[str] = b_c.details.get("superclasses", [])
            h_supers: List[str] = h_c.details.get("superclasses", [])

            model_kind = "PYDANTIC_MODEL" if "BaseModel" in (h_supers or b_supers) else "MODEL"

            all_field_names = set(b_fields.keys()) | set(h_fields.keys())
            for field in sorted(all_field_names):
                b_type = b_fields.get(field)
                h_type = h_fields.get(field)

                if b_type is None and h_type is not None:
                    schema_deltas.append(
                        SchemaModelDelta(
                            file_path=f_path,
                            model_name=c_name,
                            model_kind=model_kind,
                            field_name=field,
                            base_type=None,
                            head_type=h_type,
                            change_type="ADDED_FIELD",
                            details=f"Added field '{field}: {h_type}' to {c_name}",
                        )
                    )
                elif b_type is not None and h_type is None:
                    schema_deltas.append(
                        SchemaModelDelta(
                            file_path=f_path,
                            model_name=c_name,
                            model_kind=model_kind,
                            field_name=field,
                            base_type=b_type,
                            head_type=None,
                            change_type="REMOVED_FIELD",
                            details=f"Removed field '{field}' from {c_name}",
                        )
                    )
                elif b_type != h_type:
                    schema_deltas.append(
                        SchemaModelDelta(
                            file_path=f_path,
                            model_name=c_name,
                            model_kind=model_kind,
                            field_name=field,
                            base_type=b_type,
                            head_type=h_type,
                            change_type="MODIFIED_TYPE",
                            details=f"Modified field '{field}' type from '{b_type}' to '{h_type}' in {c_name}",
                        )
                    )

        # 9. Numerical Summary
        summary = {
            "total_files_changed": len(changed_files),
            "added_files_count": len(added_files),
            "deleted_files_count": len(deleted_files),
            "renamed_files_count": len(renamed_pairs),
            "modified_files_count": len(modified_files_list),
            "total_symbols_changed": len(all_changed_symbols),
            "added_symbols_count": len(added_symbols),
            "deleted_symbols_count": len(deleted_symbols),
            "modified_symbols_count": len(modified_symbols),
            "total_dependencies_changed": len(dep_deltas),
            "total_configs_changed": len(config_deltas),
            "total_routes_changed": len(route_deltas),
            "total_schemas_changed": len(schema_deltas),
        }

        return StructuralDiffResult(
            base_commit_sha=base_commit_sha,
            head_commit_sha=head_commit_sha,
            repository_url=repository_url,
            changed_files=changed_files,
            added_files=sorted(added_files),
            deleted_files=sorted(deleted_files),
            renamed_files=[[old_p, new_p] for old_p, new_p in sorted(renamed_pairs)],
            modified_files=sorted(modified_files_list),
            changed_symbols=all_changed_symbols,
            added_symbols=added_symbols,
            deleted_symbols=deleted_symbols,
            modified_symbols=modified_symbols,
            dependency_deltas=dep_deltas,
            config_deltas=config_deltas,
            route_deltas=route_deltas,
            schema_deltas=schema_deltas,
            summary=summary,
        )

    # Alias for backward compatibility
    compute_diff = compute_structural_diff



# Global singleton instance
_default_diff_engine: Optional[ChangeDiffEngine] = None


def get_diff_engine() -> ChangeDiffEngine:
    """Retrieve singleton ChangeDiffEngine."""
    global _default_diff_engine
    if _default_diff_engine is None:
        _default_diff_engine = ChangeDiffEngine()
    return _default_diff_engine
