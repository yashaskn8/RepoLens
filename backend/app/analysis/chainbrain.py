"""ChainBrain: bounded, offline, evidence-backed software supply-chain risk analysis.

Never installs packages, executes lifecycle scripts, or makes registry/network
requests. A finding is a risk *signal*, never an assertion of malicious intent.
The optional external registry/AI enrichment is deliberately not simulated.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
import tomllib
from typing import Any
from urllib.parse import urlsplit

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.ingestion.schemas import RepositoryManifest
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence

TOOL = "chainbrain"
POLICY = "chainbrain.offline.v1"
MAX_METADATA_BYTES = 1_048_576
MAX_PACKAGES = 2_000
MAX_FINDINGS = 250
MAX_EDGES = 8_000
MAX_NAME_LENGTH = 214
_NPM_NAME = re.compile(r"^(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+$", re.I)
_PY_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,199}[A-Za-z0-9])?$")
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]{0,199})\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^;#\s]*)")
_LIFECYCLE = ("preinstall", "install", "postinstall", "prepublish", "prepare")
_SHELL_PIPE = re.compile(r"(?:\bcurl\b|\bwget\b)[^\r\n]{0,240}\|\s*(?:sh|bash|zsh)\b", re.I)
_OBFUSCATION = re.compile(
    r"(?:\b(?:base64\s+(?:-d|--decode)|atob\s*\(|fromcharcode\s*\()[^\r\n]{0,140}"
    r"(?:\|\s*(?:sh|bash)\b|\beval\s*\(|\bexec\s*\())"
    r"|(?:\bpowershell(?:\.exe)?\b[^\r\n]{0,90}\s-(?:enc|encodedcommand)\b)",
    re.I,
)
_ENV_EXFIL = re.compile(
    r"(?:\b(?:curl|wget)\b[^\r\n]{0,180}(?:\$\{?(?:TOKEN|SECRET|PASSWORD|API_KEY|AWS_)|process\.env))"
    r"|(?:process\.env[^\r\n]{0,160}\b(?:fetch|https?\.request)\s*\()",
    re.I,
)
_REMOTE = re.compile(r"^(?:git\+|git:|https?://|ssh:|git@)", re.I)


class ChainBrainInputError(ValueError):
    """Untrusted manifest could not be evaluated completely."""


def _description(rule: str, name: str) -> tuple[str, str, Severity, int]:
    templates = {
        "CB-NPM-001": ("Install hook contains download-and-execute behavior",
                       "The repository declares an install-time shell pipeline that executes remotely retrieved content.",
                       Severity.HIGH, 85),
        "CB-NPM-002": ("Install hook contains obfuscated execution",
                       "The installation command contains a common obfuscated execution pattern; inspect the complete script before trusting it.",
                       Severity.HIGH, 80),
        "CB-NPM-003": ("Install hook may transmit environment secrets",
                       "Installation-time code references environment secrets and an outbound network operation.",
                       Severity.HIGH, 85),
        "CB-NPM-004": ("Dependency fetch uses insecure transport",
                       "A dependency lock entry uses plain HTTP or embeds URL credentials. The package content may be intercepted or exposed.",
                       Severity.HIGH, 75),
        "CB-NPM-005": ("Registry artifact lacks verifiable integrity",
                       "A registry-hosted lockfile artifact has no supported integrity digest.",
                       Severity.MEDIUM, 45),
        "CB-NPM-006": ("Dependency has an installation hook",
                       "Lockfile declares a dependency install script, but its downloaded script contents were not inspected.",
                       Severity.LOW, 20),
        "CB-NPM-007": ("Dependency uses nonstandard package origin",
                       "The lock entry resolves outside the default npm registry; explicitly verify your approved registry/mirror policy.",
                       Severity.MEDIUM, 45),
        "CB-NPM-008": ("Dependency uses a mutable or non-registry locator",
                       "The dependency uses a remote locator without an immutable commit or verified registry artifact.",
                       Severity.MEDIUM, 50),
        "CB-NPM-009": ("Dependency version is not pinned",
                       "The manifest permits dependency substitution through a range or floating selector; prefer a reviewed lockfile.",
                       Severity.LOW, 20),
        "CB-PY-001": ("Python dependency is not exactly pinned",
                      "A Python requirement does not identify one immutable package version; review resolution and hashes.",
                      Severity.LOW, 20),
        "CB-PY-002": ("Python dependency uses an unverified source",
                      "A Python requirement refers to a source/index not independently authenticated or pinned to a known artifact.",
                      Severity.MEDIUM, 50),
        "CB-PY-003": ("Python dependency uses insecure URL transport",
                      "A Python source reference uses plaintext HTTP or embeds credentials.",
                      Severity.HIGH, 75),
        "CB-CODE-001": ("Install-script source contains execution/download pattern",
                        "A locally referenced install script contains a download/execute or obfuscated execution pattern.",
                        Severity.HIGH, 80),
    }
    return templates[rule]


def _safe_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_NAME_LENGTH:
        return None
    return value if _NPM_NAME.fullmatch(value) or _PY_NAME.fullmatch(value) else None


def _safe_read(root: str, rel_path: str, expected_sha: str | None) -> str:
    path = PurePosixPath(rel_path)
    if (
        not rel_path or path.is_absolute()
        or any(part in (".", "..", "") for part in path.parts)
        or "\\" in rel_path
    ):
        raise ChainBrainInputError("Unsafe manifest path")
    current = Path(root)
    for part in path.parts[:-1]:
        current /= part
        if current.is_symlink() or not current.is_dir():
            raise ChainBrainInputError("Unsafe metadata directory")
    filename = current / path.parts[-1]
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(filename, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA_BYTES:
                raise ChainBrainInputError("Metadata file is not a bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_METADATA_BYTES + 1)
            if len(data) > MAX_METADATA_BYTES or len(data) != info.st_size:
                raise ChainBrainInputError("Metadata file size changed or exceeded limit")
            if expected_sha and hashlib.sha256(data).hexdigest() != expected_sha:
                raise ChainBrainInputError("Metadata does not match ingested evidence")
            return data.decode("utf-8")
        finally:
            os.close(fd)
    except (OSError, UnicodeError) as exc:
        raise ChainBrainInputError("Cannot safely read dependency metadata") from exc


def _line(text: str, needle: str) -> int:
    for number, row in enumerate(text.splitlines(), 1):
        if needle in row:
            return number
    return 1


def _origin(url: str) -> str:
    # Store only a coarse indicator, never raw URLs/tokens/query parameters.
    if url.startswith("http://"):
        return "http"
    if url.startswith("https://"):
        return "https"
    if url.startswith(("git+", "git:", "ssh:", "git@")):
        return "git"
    return "unknown"


def _unsafe_origin(url: str) -> bool:
    if not isinstance(url, str) or len(url) > 4096:
        return True
    try:
        parsed = urlsplit(url.removeprefix("git+"))
    except ValueError:
        return True
    return parsed.scheme == "http" or bool(parsed.username or parsed.password)


def _is_official_registry(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return parsed.scheme == "https" and parsed.hostname == "registry.npmjs.org" and not parsed.username and not parsed.password and parsed.port in (None, 443)
    except ValueError:
        return False


class _Collector:
    def __init__(self) -> None:
        self.findings: list[StaticFinding] = []
        self.seen: set[tuple[str, str, str]] = set()

    def add(self, rule: str, path: str, name: str, text: str, *,
            ecosystem: str, depth: str, explanation_note: str = "",
            line_hint: str | None = None) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            raise ChainBrainInputError("Finding budget exceeded")
        safe = _safe_name(name) or "package"
        key = (rule, path, safe)
        if key in self.seen:
            return
        self.seen.add(key)
        title, explanation, severity, score = _description(rule, safe)
        line_number = _line(text, line_hint or safe)
        self.findings.append(StaticFinding(
            tool=TOOL, source_tool=TOOL, rule_id=rule, detector_id=rule,
            detector_kind="deterministic_supply_chain", category="dependency",
            title=f"{title}: {safe}", description=explanation,
            severity=severity, confidence="MEDIUM",
            evidence=Evidence(
                file_path=path, start_line=line_number, end_line=line_number,
                context_notes="ChainBrain offline package-risk indicator; not proof of malware.",
            ),
            mitigation="Review the pinned package, installation behavior, and provenance before integration; use an approved lockfile and trusted registry policy.",
            raw_details={
                "policy": POLICY, "ecosystem": ecosystem,
                "package": safe, "dependency_scope": depth,
                "risk_score": score, "risk_score_kind": "heuristic_not_probability",
                "metadata_verification": "offline_only",
                "maintainer_reputation": "not_evaluated",
                "ai_explanation": "not_requested",
                "rationale": explanation,
                "context": explanation_note[:150],
            },
        ))


def _install_scripts(data: dict[str, Any], path: str, source: str,
                     reader: Any, collector: _Collector) -> None:
    scripts = data.get("scripts") or {}
    if not isinstance(scripts, dict):
        raise ChainBrainInputError("Invalid package scripts object")
    for hook in _LIFECYCLE:
        command = scripts.get(hook)
        if command is None:
            continue
        if not isinstance(command, str) or len(command) > 16_384:
            raise ChainBrainInputError("Invalid install script")
        name = _safe_name(data.get("name")) or "root-package"
        for rule, pattern in (
            ("CB-NPM-001", _SHELL_PIPE),
            ("CB-NPM-002", _OBFUSCATION),
            ("CB-NPM-003", _ENV_EXFIL),
        ):
            if pattern.search(command):
                collector.add(rule, path, name, source, ecosystem="npm",
                              depth="root", explanation_note=f"Lifecycle hook: {hook}",
                              line_hint=f'"{hook}"')
        # Inspect only local scripts directly referenced from a lifecycle command.
        # Do not follow dynamic paths, traverse directories, or execute anything.
        tokens = re.findall(r"(?:^|\s)(?:node|sh|bash)\s+([A-Za-z0-9_./-]+\.(?:js|cjs|mjs|sh))(?=\s|$)", command)
        for rel in tokens[:2]:
            if rel.startswith("/") or ".." in PurePosixPath(rel).parts:
                continue
            try:
                script = reader(rel)
            except (KeyError, ChainBrainInputError):
                continue
            if _SHELL_PIPE.search(script) or _OBFUSCATION.search(script) or _ENV_EXFIL.search(script):
                collector.add("CB-CODE-001", rel, name, script, ecosystem="npm", depth="root",
                              explanation_note=f"Referenced by {hook}")


def _npm(root_reader: Any, files: dict[str, Any], collector: _Collector) -> None:
    for path in sorted(files):
        if not (path == "package.json" or path.endswith("/package.json")):
            continue
        if "node_modules/" in path:
            continue
        source = root_reader(path)
        try:
            data = json.loads(source)
        except (ValueError, TypeError) as exc:
            raise ChainBrainInputError("Invalid npm package manifest") from exc
        if not isinstance(data, dict):
            raise ChainBrainInputError("Invalid npm package manifest")
        parent = str(PurePosixPath(path).parent)
        prefix = "" if parent == "." else parent + "/"
        def read_script(name: str) -> str:
            key = prefix + name
            if key not in files:
                raise KeyError(key)
            return root_reader(key)
        _install_scripts(data, path, source, read_script, collector)
        for section in ("dependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                raise ChainBrainInputError("Invalid dependency mapping")
            if len(deps) > MAX_PACKAGES:
                raise ChainBrainInputError("Package count exceeded")
            for name, selector in deps.items():
                safe = _safe_name(name)
                if safe is None or not isinstance(selector, str) or len(selector) > 1024:
                    raise ChainBrainInputError("Invalid dependency name/version")
                if _REMOTE.match(selector):
                    rule = "CB-NPM-004" if _unsafe_origin(selector) else "CB-NPM-008"
                    collector.add(rule, path, safe, source, ecosystem="npm", depth="direct",
                                  line_hint=f'"{name}"')
                elif selector in ("*", "latest", "next") or selector.startswith((">", "<", "^", "~")):
                    # Avoid noisy range warnings when an authoritative lockfile exists.
                    if prefix + "package-lock.json" not in files and prefix + "npm-shrinkwrap.json" not in files:
                        collector.add("CB-NPM-009", path, safe, source, ecosystem="npm", depth="direct")


def _locks(read: Any, files: dict[str, Any], collector: _Collector) -> None:
    for path in sorted(files):
        if not path.endswith(("package-lock.json", "npm-shrinkwrap.json")):
            continue
        source = read(path)
        try:
            data = json.loads(source)
        except (TypeError, ValueError) as exc:
            raise ChainBrainInputError("Invalid npm lockfile") from exc
        if not isinstance(data, dict):
            raise ChainBrainInputError("Invalid npm lockfile")
        version = data.get("lockfileVersion")
        packages = data.get("packages")
        if version not in (2, 3) or not isinstance(packages, dict):
            # Not a successful assessment: older/unknown lock schemas unsupported.
            raise ChainBrainInputError("Unsupported npm lockfile schema")
        if len(packages) > MAX_PACKAGES:
            raise ChainBrainInputError("Lockfile package budget exceeded")
        edge_count = 0
        for locator, pkg in sorted(packages.items()):
            if not isinstance(locator, str) or not isinstance(pkg, dict):
                raise ChainBrainInputError("Malformed lockfile package entry")
            deps = pkg.get("dependencies", {})
            if deps is None:
                deps = {}
            if not isinstance(deps, dict):
                raise ChainBrainInputError("Malformed lockfile dependency edges")
            edge_count += len(deps)
            if edge_count > MAX_EDGES:
                raise ChainBrainInputError("Lockfile dependency-edge budget exceeded")
            if not locator or not locator.startswith("node_modules/") and "/node_modules/" not in locator:
                continue
            name = locator.rsplit("node_modules/", 1)[-1]
            if name.startswith("@"):
                # Preserve scoped name, not just the last path component.
                parts = locator.split("node_modules/")
                name = parts[-1]
            safe = _safe_name(name)
            if safe is None:
                raise ChainBrainInputError("Invalid lockfile package locator")
            scope = "transitive" if "/node_modules/" in locator else "direct_or_hoisted"
            resolved = pkg.get("resolved")
            if resolved is not None and (not isinstance(resolved, str) or len(resolved) > 4096):
                raise ChainBrainInputError("Invalid lockfile resolved locator")
            resolved = resolved or ""
            if resolved.startswith(("http://", "https://")):
                if _unsafe_origin(resolved):
                    collector.add("CB-NPM-004", path, safe, source, ecosystem="npm",
                                  depth=scope, line_hint=f'"{locator}"')
                elif not _is_official_registry(resolved):
                    collector.add("CB-NPM-007", path, safe, source, ecosystem="npm",
                                  depth=scope, line_hint=f'"{locator}"')
                integrity = pkg.get("integrity")
                if not isinstance(integrity, str) or not re.search(r"\bsha(?:256|384|512)-[A-Za-z0-9+/=]{24,}", integrity):
                    collector.add("CB-NPM-005", path, safe, source, ecosystem="npm",
                                  depth=scope, line_hint=f'"{locator}"')
            elif resolved and _REMOTE.match(resolved):
                collector.add("CB-NPM-008", path, safe, source, ecosystem="npm",
                              depth=scope, line_hint=f'"{locator}"')
            if pkg.get("hasInstallScript") is True:
                collector.add("CB-NPM-006", path, safe, source, ecosystem="npm",
                              depth=scope, line_hint=f'"{locator}"')


def _python(read: Any, files: dict[str, Any], collector: _Collector) -> None:
    for path in sorted(files):
        if not (PurePosixPath(path).name.startswith("requirements") and path.endswith(".txt")):
            continue
        source = read(path)
        if len(source.splitlines()) > 5_000:
            raise ChainBrainInputError("Python requirements file exceeds rule budget")
        for row in source.splitlines():
            stripped = row.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith(("--extra-index-url", "--index-url", "--find-links", "-e ", "-r ", "--requirement")):
                collector.add("CB-PY-002", path, "python-index", source, ecosystem="pypi", depth="root",
                              line_hint=stripped[:min(12, len(stripped))])
                continue
            if _REMOTE.match(stripped):
                collector.add("CB-PY-003" if _unsafe_origin(stripped) else "CB-PY-002",
                              path, "python-source", source, ecosystem="pypi", depth="direct",
                              line_hint=stripped[:min(12, len(stripped))])
                continue
            m = _REQ.match(stripped)
            if not m:
                # Do not falsely claim complete parsing of unsupported syntax.
                raise ChainBrainInputError("Unsupported Python requirement entry")
            name, comparator, version = m.groups()
            if _safe_name(name) is None:
                raise ChainBrainInputError("Invalid Python package name")
            if comparator != "==" or not version or "*" in version:
                collector.add("CB-PY-001", path, name, source, ecosystem="pypi",
                              depth="direct", line_hint=name)
    for path in sorted(files):
        if not (path == "pyproject.toml" or path.endswith("/pyproject.toml")):
            continue
        source = read(path)
        try:
            data = tomllib.loads(source)
        except (ValueError, TypeError) as exc:
            raise ChainBrainInputError("Invalid pyproject metadata") from exc
        if not isinstance(data, dict):
            raise ChainBrainInputError("Invalid pyproject metadata")
        project = data.get("project") or {}
        if not isinstance(project, dict):
            raise ChainBrainInputError("Invalid Python project metadata")
        deps = project.get("dependencies") or []
        if not isinstance(deps, list) or len(deps) > MAX_PACKAGES:
            raise ChainBrainInputError("Invalid Python dependency declarations")
        for value in deps:
            if not isinstance(value, str) or len(value) > 1024:
                raise ChainBrainInputError("Invalid Python dependency declaration")
            matched = _REQ.match(value)
            if not matched:
                raise ChainBrainInputError("Unsupported Python dependency declaration")
            name, comparator, version = matched.groups()
            if _safe_name(name) is None:
                raise ChainBrainInputError("Invalid Python dependency name")
            if "@" in value:
                url = value.split("@", 1)[1].strip()
                collector.add("CB-PY-003" if _unsafe_origin(url) else "CB-PY-002",
                              path, name, source, ecosystem="pypi", depth="direct",
                              line_hint=name)
            elif comparator != "==" or not version or "*" in version:
                collector.add("CB-PY-001", path, name, source, ecosystem="pypi",
                              depth="direct", line_hint=name)


def analyze_supply_chain_repository(repo_dir: str, manifest: RepositoryManifest) -> ScannerResult:
    """Return bounded package-risk findings; never treat incomplete parsing as clean."""
    start = time.perf_counter()
    collector = _Collector()
    try:
        if manifest.analysis_scope and manifest.analysis_scope.truncated:
            raise ChainBrainInputError("Repository manifest is incomplete")
        def relevant_metadata(path: str) -> bool:
            filename = PurePosixPath(path).name
            return (
                filename in {"package.json", "package-lock.json",
                             "npm-shrinkwrap.json", "pyproject.toml"}
                or (filename.startswith("requirements") and filename.endswith(".txt"))
            )

        # A skipped dependency declaration is not an assessment of that file.
        # Ingestion may skip oversize, unsafe, binary or racing source entries.
        if any(
            relevant_metadata(item.path) and item.skipped_reason is not None
            for item in manifest.files
        ):
            raise ChainBrainInputError("Dependency metadata was excluded from ingestion")
        files = {
            item.path: item
            for item in manifest.files
            if item.skipped_reason is None
        }
        candidates = {p for p in files if relevant_metadata(p)}
        if len(candidates) > MAX_PACKAGES:
            raise ChainBrainInputError("Metadata candidate budget exceeded")
        root = os.path.realpath(repo_dir)
        def read(path: str) -> str:
            entry = files.get(path)
            if entry is None:
                raise ChainBrainInputError("Metadata is outside the ingested manifest")
            return _safe_read(root, path, entry.content_sha256)

        # Local install scripts are looked up lazily in the complete bounded
        # manifest. Counting every .js as metadata would reject ordinary repos.
        _npm(read, files, collector)
        metadata_files = {key: files[key] for key in candidates}
        _locks(read, metadata_files, collector)
        _python(read, metadata_files, collector)
        return ScannerResult(
            tool=TOOL, status=ToolStatus.COMPLETED, findings=collector.findings,
            execution_time_ms=(time.perf_counter() - start) * 1000,
        )
    except ChainBrainInputError as exc:
        # Do not propagate untrusted metadata or potentially credential-bearing paths.
        return ScannerResult(
            tool=TOOL, status=ToolStatus.INVALID_OUTPUT,
            error_message=f"ChainBrain assessment incomplete ({type(exc).__name__}).",
            execution_time_ms=(time.perf_counter() - start) * 1000,
        )
    except Exception:
        return ScannerResult(
            tool=TOOL, status=ToolStatus.FAILED,
            error_message="ChainBrain could not safely complete package analysis.",
            execution_time_ms=(time.perf_counter() - start) * 1000,
        )
