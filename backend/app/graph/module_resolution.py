"""Bounded, source-attested JS/TS module resolution over immutable Git objects."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import json
import posixpath
import re
from typing import Any

from app.ingestion.git_inventory import InventoryBound
from app.ingestion.schemas import FileEntry, SymbolKind


@dataclass(frozen=True)
class ModuleResolution:
    specifier: str
    state: str
    target: str | None
    method: str
    evidence: tuple[tuple[str, str], ...] = ()
    reason: str | None = None


def import_specifiers(file: FileEntry, *, limit: int = 64) -> list[str]:
    values: list[str] = []
    for symbol in file.symbols:
        if symbol.kind != SymbolKind.IMPORT:
            continue
        source = symbol.details.get("source")
        if isinstance(source, str) and source and len(source.encode("utf-8")) <= 512:
            values.append(source)
        if len(values) >= limit:
            break
    return list(dict.fromkeys(values))


def _strip_jsonc(value: str) -> str:
    """Remove JSONC comments without treating comment markers inside strings as syntax."""
    result: list[str] = []
    index, quoted, escaped = 0, False, False
    while index < len(value):
        char = value[index]
        if quoted:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            index += 1
            continue
        if char == '"':
            quoted = True
            escaped = False
            result.append(char)
            index += 1
        elif value[index:index + 2] == "//":
            index = value.find("\n", index)
            if index < 0:
                break
        elif value[index:index + 2] == "/*":
            end = value.find("*/", index + 2)
            if end < 0:
                break
            index = end + 2
        else:
            result.append(char)
            index += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(result))


class TypeScriptModuleResolver:
    """Resolve only relationships proven by checked-in config and existing files.

    All reads use immutable object IDs. Repository scripts, package managers, and
    JavaScript configuration files are never evaluated.
    """

    _EXTENSIONS = ("", ".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs",
                   "/index.ts", "/index.tsx", "/index.js", "/index.jsx", "/index.mts", "/index.cts")

    def __init__(self, index, *, max_configs: int = 64, max_workspace_packages: int = 256):
        self.index = index
        self.inventory = index.inventory
        self.root = self.inventory.root_tree(index.commit_sha)
        self.max_configs = max_configs
        self.max_workspace_packages = max_workspace_packages
        self._json_cache: OrderedDict[str, tuple[dict[str, Any] | None, str | None]] = OrderedDict()
        self._config_cache: dict[str, tuple[dict[str, tuple[str, list[str], str]], str | None, tuple[tuple[str, str], ...]]] = {}
        self._workspace_cache: dict[str, list[tuple[str, str, dict[str, Any], str]]] = {}

    @staticmethod
    def _safe(path: str) -> str | None:
        value = posixpath.normpath(path.replace("\\", "/"))
        if value in {"", "."} or value.startswith(("../", "/")) or "\x00" in value or len(value.encode()) > 2048:
            return None
        return value

    def _read_text(self, path: str, *, limit: int = 262_144) -> tuple[str | None, str | None]:
        safe = self._safe(path)
        if safe is None:
            return None, None
        entry = self.inventory.path_entry(self.root, safe)
        if entry is None or entry.kind != "blob" or entry.mode not in {"100644", "100755"}:
            return None, None
        try:
            return self.inventory.read_object(entry.object_id, kind="blob", max_bytes=limit).decode("utf-8"), entry.object_id
        except (UnicodeError, ValueError, InventoryBound):
            return None, entry.object_id

    def _read_json(self, path: str) -> tuple[dict[str, Any] | None, str | None]:
        if path in self._json_cache:
            self._json_cache.move_to_end(path)
            return self._json_cache[path]
        text, oid = self._read_text(path)
        value = None
        if text is not None:
            try:
                parsed = json.loads(_strip_jsonc(text))
                value = parsed if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, RecursionError):
                value = None
        self._json_cache[path] = (value, oid)
        if len(self._json_cache) > self.max_configs:
            self._json_cache.popitem(last=False)
        return value, oid

    def _existing(self, base: str) -> list[str]:
        safe = self._safe(base)
        if safe is None:
            return []
        result = []
        for suffix in self._EXTENSIONS:
            candidate = self._safe(safe + suffix)
            if candidate and self.index.file_projection(candidate) is not None:
                result.append(candidate)
        return list(dict.fromkeys(result))

    @staticmethod
    def _match(pattern: str, value: str) -> str | None:
        if "*" not in pattern:
            return "" if pattern == value else None
        if pattern.count("*") != 1:
            return None
        prefix, suffix = pattern.split("*", 1)
        if value.startswith(prefix) and value.endswith(suffix) and len(value) >= len(prefix) + len(suffix):
            return value[len(prefix):len(value) - len(suffix) if suffix else None]
        return None

    @staticmethod
    def _static_target(value: Any, capture: str = "") -> tuple[str | None, bool]:
        leaves: list[str] = []
        def visit(item: Any, depth: int = 0) -> None:
            if depth > 8 or len(leaves) > 16:
                return
            if isinstance(item, str):
                leaves.append(item.replace("*", capture))
            elif isinstance(item, list):
                for child in item[:16]:
                    visit(child, depth + 1)
            elif isinstance(item, dict):
                for key in sorted(item)[:16]:
                    visit(item[key], depth + 1)
        visit(value)
        unique = list(dict.fromkeys(leaves))
        return (unique[0], False) if len(unique) == 1 else (None, bool(unique))

    def _find_up(self, source_path: str, filename: str) -> list[str]:
        current = posixpath.dirname(source_path)
        result = []
        for _ in range(32):
            candidate = posixpath.join(current, filename) if current else filename
            if self.inventory.path_entry(self.root, candidate) is not None:
                result.append(candidate)
            if not current:
                break
            current = posixpath.dirname(current)
        return result

    def _config(self, path: str, stack: tuple[str, ...] = ()) -> tuple[dict[str, tuple[str, list[str], str]], str | None, tuple[tuple[str, str], ...]]:
        if path in self._config_cache:
            return self._config_cache[path]
        if path in stack or len(stack) >= 8:
            return {}, None, ((path, "CYCLE_OR_DEPTH"),)
        value, oid = self._read_json(path)
        if value is None or oid is None:
            return {}, None, ((path, oid or "INVALID"),)
        rules: dict[str, tuple[str, list[str], str]] = {}
        base_url = None
        evidence: list[tuple[str, str]] = [(path, oid)]
        extended = value.get("extends")
        if isinstance(extended, str) and extended.startswith(("./", "../")):
            parent = posixpath.normpath(posixpath.join(posixpath.dirname(path), extended))
            candidates = [parent] if parent.endswith(".json") else [parent + ".json", parent + "/tsconfig.json"]
            existing = [candidate for candidate in candidates if self.inventory.path_entry(self.root, candidate)]
            if len(existing) == 1:
                rules, base_url, parent_evidence = self._config(existing[0], stack + (path,))
                rules = dict(rules)
                evidence.extend(parent_evidence)
            else:
                evidence.append((extended, "UNRESOLVED_EXTENDS"))
        elif extended is not None:
            evidence.append((str(extended)[:256], "UNRESOLVED_EXTENDS"))
        compiler = value.get("compilerOptions", {})
        if isinstance(compiler, dict):
            configured_base = compiler.get("baseUrl")
            if isinstance(configured_base, str):
                normalized_base = posixpath.normpath(posixpath.join(posixpath.dirname(path), configured_base or "."))
                base_url = "" if normalized_base == "." else self._safe(normalized_base)
            path_rules = compiler.get("paths", {})
            if isinstance(path_rules, dict):
                rule_base = base_url if base_url is not None else (posixpath.dirname(path) or "")
                for alias, targets in list(path_rules.items())[:128]:
                    if (isinstance(alias, str) and alias.count("*") <= 1 and isinstance(targets, list)
                            and all(isinstance(target, str) and target.count("*") <= 1 for target in targets[:16])):
                        rules[alias] = (rule_base, targets[:16], path)
        result = (rules, base_url, tuple(evidence[:16]))
        self._config_cache[path] = result
        return result

    def _resolve_tsconfig(self, source_path: str, specifier: str) -> ModuleResolution | None:
        configs = self._find_up(source_path, "tsconfig.json")
        if not configs:
            configs = self._find_up(source_path, "jsconfig.json")
        if not configs:
            return None
        rules, base_url, evidence = self._config(configs[0])
        candidates: list[str] = []
        matched = False
        for alias, (root, targets, _) in rules.items():
            capture = self._match(alias, specifier)
            if capture is None:
                continue
            matched = True
            for target in targets:
                candidates.extend(self._existing(posixpath.join(root, target.replace("*", capture))))
        if not matched and base_url is not None:
            candidates.extend(self._existing(posixpath.join(base_url, specifier)))
        unique = list(dict.fromkeys(candidates))
        if len(unique) == 1:
            return ModuleResolution(specifier, "PROVEN", unique[0], "TSCONFIG_PATHS" if matched else "TSCONFIG_BASE_URL", evidence)
        if len(unique) > 1:
            return ModuleResolution(specifier, "UNRESOLVED", None, "TSCONFIG", evidence, "AMBIGUOUS_STATIC_TARGETS")
        if matched or base_url is not None:
            return ModuleResolution(specifier, "POSSIBLE", None, "TSCONFIG", evidence, "CONFIGURED_TARGET_NOT_INDEXED")
        return None

    def _workspace_patterns(self, source_path: str) -> tuple[str, list[str], tuple[tuple[str, str], ...]] | None:
        for package_path in reversed(self._find_up(source_path, "package.json")):
            package, oid = self._read_json(package_path)
            if not package:
                continue
            workspaces = package.get("workspaces")
            if isinstance(workspaces, dict):
                workspaces = workspaces.get("packages")
            if isinstance(workspaces, list):
                values = [value.rstrip("/") for value in workspaces[:64]
                          if isinstance(value, str) and value.count("*") <= 1 and not any(c in value for c in "?[]{}")]
                if values:
                    return posixpath.dirname(package_path), values, ((package_path, oid or "INVALID"),)
        text, oid = self._read_text("pnpm-workspace.yaml")
        if text is not None and oid:
            values = []
            in_packages = False
            for line in text.splitlines()[:256]:
                clean = line.split("#", 1)[0].strip()
                if clean == "packages:":
                    in_packages = True
                elif in_packages and clean.startswith("-"):
                    value = clean[1:].strip().strip("'\"").rstrip("/")
                    if value and value.count("*") <= 1 and not any(c in value for c in "?[]{}"):
                        values.append(value)
                elif in_packages and clean and not line.startswith((" ", "\t")):
                    break
            if values:
                return "", values[:64], (("pnpm-workspace.yaml", oid),)
        return None

    def _workspace_packages(self, source_path: str) -> tuple[list[tuple[str, str, dict[str, Any], str]], tuple[tuple[str, str], ...]]:
        workspace = self._workspace_patterns(source_path)
        if workspace is None:
            return [], ()
        root, patterns, evidence = workspace
        cache_key = json.dumps([root, patterns])
        if cache_key in self._workspace_cache:
            return self._workspace_cache[cache_key], evidence
        package_dirs: list[str] = []
        for pattern in patterns:
            joined = posixpath.normpath(posixpath.join(root, pattern))
            if "*" not in joined:
                package_dirs.append(joined)
                continue
            prefix, suffix = joined.split("*", 1)
            parent = prefix.rstrip("/")
            entry = self.inventory.path_entry(self.root, parent)
            if entry is None or entry.kind != "tree":
                continue
            for child in self.inventory.entries(entry.object_id):
                if child.kind != "tree" or len(package_dirs) >= self.max_workspace_packages:
                    continue
                candidate = prefix + child.name + suffix
                if self._safe(candidate):
                    package_dirs.append(candidate.rstrip("/"))
        packages = []
        for directory in list(dict.fromkeys(package_dirs))[:self.max_workspace_packages]:
            package_path = posixpath.join(directory, "package.json")
            package, oid = self._read_json(package_path)
            name = package.get("name") if package else None
            if isinstance(name, str) and name and oid:
                packages.append((name, directory, package, oid))
        self._workspace_cache[cache_key] = packages
        return packages, evidence

    def _resolve_mapping(self, specifier: str, key: str, mapping: Any, root: str,
                         method: str, evidence: tuple[tuple[str, str], ...]) -> ModuleResolution | None:
        if mapping is None:
            return None
        if not isinstance(mapping, dict) or (key == "." and not any(
                isinstance(pattern, str) and pattern.startswith(".") for pattern in mapping)):
            if key != ".":
                return None
            target, ambiguous = self._static_target(mapping)
            if ambiguous or not target or not target.startswith("./"):
                return ModuleResolution(specifier, "UNRESOLVED", None, method, evidence,
                                        "DYNAMIC_OR_CONDITIONAL_MAPPING")
            existing = self._existing(posixpath.join(root, target))
            if len(existing) == 1:
                return ModuleResolution(specifier, "PROVEN", existing[0], method, evidence)
            return ModuleResolution(specifier, "UNRESOLVED" if len(existing) > 1 else "POSSIBLE", None,
                                    method, evidence, "AMBIGUOUS_STATIC_TARGETS" if existing else "TARGET_NOT_INDEXED")
        matches = []
        for pattern, value in list(mapping.items())[:128]:
            if not isinstance(pattern, str):
                continue
            capture = self._match(pattern, key)
            if capture is not None:
                matches.append((len(pattern.replace("*", "")), pattern, value, capture))
        if not matches:
            return None
        best = max(item[0] for item in matches)
        selected = [item for item in matches if item[0] == best]
        if len(selected) != 1:
            return ModuleResolution(specifier, "UNRESOLVED", None, method, evidence, "AMBIGUOUS_MAPPING")
        _, _, value, capture = selected[0]
        target, ambiguous = self._static_target(value, capture)
        if ambiguous or not target or not target.startswith("./"):
            return ModuleResolution(specifier, "UNRESOLVED", None, method, evidence, "DYNAMIC_OR_CONDITIONAL_MAPPING")
        existing = self._existing(posixpath.join(root, target))
        if len(existing) == 1:
            return ModuleResolution(specifier, "PROVEN", existing[0], method, evidence)
        return ModuleResolution(specifier, "UNRESOLVED" if len(existing) > 1 else "POSSIBLE", None,
                                method, evidence, "AMBIGUOUS_STATIC_TARGETS" if existing else "TARGET_NOT_INDEXED")

    def _resolve_package_import(self, source_path: str, specifier: str) -> ModuleResolution | None:
        if specifier.startswith("#"):
            packages = self._find_up(source_path, "package.json")
            if not packages:
                return None
            package, oid = self._read_json(packages[0])
            if package and oid:
                return self._resolve_mapping(specifier, specifier, package.get("imports"),
                    posixpath.dirname(packages[0]), "PACKAGE_IMPORTS", ((packages[0], oid),))
            return None
        packages, workspace_evidence = self._workspace_packages(source_path)
        matches = [(name, root, package, oid) for name, root, package, oid in packages
                   if specifier == name or specifier.startswith(name + "/")]
        if not matches:
            return None
        longest = max(len(item[0]) for item in matches)
        matches = [item for item in matches if len(item[0]) == longest]
        if len(matches) != 1:
            return ModuleResolution(specifier, "UNRESOLVED", None, "WORKSPACE_PACKAGE", workspace_evidence,
                                    "DUPLICATE_WORKSPACE_PACKAGE_NAME")
        name, root, package, oid = matches[0]
        evidence = workspace_evidence + ((posixpath.join(root, "package.json"), oid),)
        subpath = "." if specifier == name else "./" + specifier[len(name) + 1:]
        resolved = self._resolve_mapping(specifier, subpath, package.get("exports"), root, "PACKAGE_EXPORTS", evidence)
        if resolved:
            return resolved
        direct = root if subpath == "." else posixpath.join(root, subpath[2:])
        if subpath == ".":
            fields = list(dict.fromkeys(value for key in ("module", "main")
                if isinstance((value := package.get(key)), str)))
            if len(fields) == 1:
                direct = posixpath.join(root, fields[0])
            elif len(fields) > 1:
                return ModuleResolution(specifier, "UNRESOLVED", None, "PACKAGE_ENTRY", evidence,
                                        "CONDITION_DEPENDENT_ENTRY")
        existing = self._existing(direct)
        if len(existing) == 1:
            return ModuleResolution(specifier, "PROVEN", existing[0], "WORKSPACE_PACKAGE", evidence)
        return ModuleResolution(specifier, "UNRESOLVED" if len(existing) > 1 else "POSSIBLE", None,
                                "WORKSPACE_PACKAGE", evidence,
                                "AMBIGUOUS_STATIC_TARGETS" if existing else "TARGET_NOT_INDEXED")

    def resolve(self, source_path: str, specifier: str) -> ModuleResolution:
        if specifier.startswith(("./", "../")):
            existing = self._existing(posixpath.join(posixpath.dirname(source_path), specifier))
            if len(existing) == 1:
                return ModuleResolution(specifier, "PROVEN", existing[0], "RELATIVE_SOURCE")
            return ModuleResolution(specifier, "UNRESOLVED" if len(existing) > 1 else "POSSIBLE", None,
                                    "RELATIVE_SOURCE", reason="AMBIGUOUS_STATIC_TARGETS" if existing else "TARGET_NOT_INDEXED")
        package = self._resolve_package_import(source_path, specifier)
        if package is not None:
            return package
        configured = self._resolve_tsconfig(source_path, specifier)
        if configured is not None:
            return configured
        return ModuleResolution(specifier, "UNRESOLVED", None, "BARE_SPECIFIER", reason="NO_STATIC_REPOSITORY_MAPPING")

    def resolve_file(self, file: FileEntry) -> list[ModuleResolution]:
        return [self.resolve(file.path, specifier) for specifier in import_specifiers(file)]
