"""RepoLens-owned deterministic security checks that require no external binary."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from app.analysis.schemas import ScannerResult, StaticFinding, ToolStatus
from app.ingestion.schemas import RepositoryManifest
from app.schemas.enums import Severity
from app.schemas.evidence import Evidence

_MAX_CORE_FILE_BYTES = 1_048_576
_SENSITIVE_HEADER_PARTS = ("tenant", "role", "user-id", "user_id", "identity")
_VERIFIED_IDENTITY_MARKERS = (
    "decode_token(", "jwt.decode(", "verify_jwt(", "verify_token(",
    "validate_token(", "verify_signed_identity(", "get_current_user(",
    "authenticate_identity(",
)
_AUTHORIZATION_USE_MARKERS = (
    "allowed_roles", "permission", "authoriz", "tenant_id_context.set(",
    "current_tenant_id.set(", "set_config(", ".where(", "create_order(",
    "tenant_id=", "user_id=", "roles.split(",
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\s*[:=]\s*(?P<value>.+?)\s*$",
    re.IGNORECASE,
)
_CONFIG_SUFFIXES = {".tf", ".tfvars", ".yaml", ".yml", ".toml", ".ini"}


def _call_name(node: ast.Call) -> str:
    try:
        return ast.unparse(node.func)
    except Exception:
        return ""


def _header_name_from_default(default: ast.AST | None, variable_name: str) -> str | None:
    if not isinstance(default, ast.Call) or _call_name(default).rsplit(".", 1)[-1] != "Header":
        return None
    alias = next(
        (
            keyword.value.value
            for keyword in default.keywords
            if keyword.arg == "alias"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ),
        None,
    )
    return alias or variable_name.replace("_", "-")


def _assignment_header_sources(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, str, int]]:
    sources: list[tuple[str, str, int]] = []
    positional = list(node.args.posonlyargs) + list(node.args.args)
    defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    for argument, default in zip(positional, defaults):
        header = _header_name_from_default(default, argument.arg)
        if header and any(part in header.lower() for part in _SENSITIVE_HEADER_PARTS):
            sources.append((argument.arg, header, getattr(default, "lineno", argument.lineno)))

    for assignment in ast.walk(node):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)) or assignment.value is None:
            continue
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        target_names = [target.id for target in targets if isinstance(target, ast.Name)]
        if not target_names:
            continue
        for call in (item for item in ast.walk(assignment.value) if isinstance(item, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "get":
                continue
            owner = ast.unparse(call.func.value).lower()
            if not owner.endswith("headers") or not call.args:
                continue
            header_arg = call.args[0]
            if not isinstance(header_arg, ast.Constant) or not isinstance(header_arg.value, str):
                continue
            header = header_arg.value
            if any(part in header.lower() for part in _SENSITIVE_HEADER_PARTS):
                sources.extend((target, header, assignment.lineno) for target in target_names)
    return sources


def _authorization_header_findings(path: str, text: str, *, gateway_auth_visible: bool) -> list[StaticFinding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    findings: list[StaticFinding] = []
    source_lines = text.splitlines()
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        segment = "\n".join(source_lines[function.lineno - 1 : getattr(function, "end_lineno", function.lineno)]).lower()
        if any(marker in segment for marker in _VERIFIED_IDENTITY_MARKERS):
            continue
        if not any(marker in segment for marker in _AUTHORIZATION_USE_MARKERS):
            continue
        for variable, header, source_line in _assignment_header_sources(function):
            if len(re.findall(rf"\b{re.escape(variable.lower())}\b", segment)) < 2:
                continue
            header_lower = header.lower()
            boundary = "tenant isolation" if "tenant" in header_lower else "authorization" if "role" in header_lower else "user identity"
            severity = Severity.CRITICAL if any(part in header_lower for part in ("tenant", "role")) else Severity.HIGH
            detector_id = f"python.security.client-controlled-{boundary.replace(' ', '-')}"
            findings.append(
                StaticFinding(
                    tool="repolens-core",
                    rule_id=detector_id,
                    title=f"Client-controlled header drives {boundary}",
                    description=(
                        f"Request header {header!r} is used as {boundary} input in {function.name!r} "
                        "without a visible cryptographically verified identity derivation in that boundary."
                    ),
                    severity=severity,
                    category="authorization",
                    evidence=Evidence(
                        file_path=path,
                        start_line=source_line,
                        end_line=min(getattr(function, "end_lineno", source_line), source_line + 16),
                        context_notes=(
                            f"source=HTTP header {header}; use={boundary}; "
                            f"verified_identity_boundary=absent; gateway_authentication_visible={gateway_auth_visible}"
                        ),
                    ),
                    mitigation="Derive identity and tenant/role claims from a verified token or trusted gateway assertion; reject direct client assertions.",
                    confidence="HIGH",
                    source_tool="repolens-core",
                    detector_id=detector_id,
                    detector_kind="static_scanner",
                    raw_details={
                        "header": header,
                        "boundary": boundary,
                        "function": function.name,
                        "gateway_authentication_visible": gateway_auth_visible,
                    },
                )
            )
    return findings


def _is_obvious_reference_or_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return (
        not normalized
        or any(marker in normalized for marker in (
            "${", "{{", "var.", "local.", "module.", "secretkeyref",
            "valuefrom", "getenv", "secret_string", ".result",
        ))
        or normalized.startswith(("data.", "aws_", "azurerm_", "google_", "random_", "vault_"))
        or normalized.startswith(("<", "your_", "your-", "example", "placeholder", "changeme", "change-me", "dummy", "test_", "dev_", "dev-"))
        or set(normalized) <= {"x", "*", "-", "_"}
    )


def _is_sensitive_assignment_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized.endswith(("secret_id", "secret_name", "secret_ref", "secret_path", "secret_arn", "secret_string")):
        return False
    return (
        any(marker in normalized for marker in ("password", "passwd", "credential"))
        or normalized == "secret"
        or normalized.endswith(("_api_key", "_admin_key", "_signing_key", "_secret_key", "_client_secret", "_private_key"))
        or normalized in {"api_key", "admin_key", "signing_key", "secret_key", "client_secret", "private_key"}
    )


def _literal_assignment_value(raw_value: str) -> str | None:
    """Return a fixed scalar value without retaining comments or quote syntax."""
    value = raw_value.strip()
    if not value:
        return None
    if value[0] in {"\"", "'"}:
        quote = value[0]
        end = value.find(quote, 1)
        if end < 0 or value[end + 1 :].strip().split("#", 1)[0].strip():
            return None
        value = value[1:end]
    else:
        value = value.split(" #", 1)[0].strip()
    return value if len(value) >= 8 else None


def _hardcoded_credential_findings(path: str, text: str) -> list[StaticFinding]:
    if Path(path).suffix.lower() not in _CONFIG_SUFFIXES:
        return []
    findings: list[StaticFinding] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = _SENSITIVE_ASSIGNMENT.match(line)
        if not match:
            continue
        key = match.group("key")
        value = _literal_assignment_value(match.group("value"))
        if not _is_sensitive_assignment_key(key) or value is None or _is_obvious_reference_or_placeholder(value):
            continue
        detector_id = f"iac.security.hardcoded-{key.lower().replace('-', '_')}"
        findings.append(
            StaticFinding(
                tool="repolens-core",
                rule_id=detector_id,
                title="Hardcoded infrastructure credential",
                description=f"Infrastructure/configuration field {key!r} contains a fixed credential value rather than a runtime secret reference.",
                severity=Severity.HIGH,
                category="secret",
                evidence=Evidence(
                    file_path=path,
                    start_line=line_number,
                    end_line=line_number,
                    context_notes=f"sensitive_field={key}; fixed_value=true; value_redacted=true",
                ),
                mitigation="Generate and inject the credential through a managed secret reference; rotate any deployed fixed value.",
                confidence="HIGH",
                source_tool="repolens-secret",
                detector_id=detector_id,
                detector_kind="deterministic_secret",
                raw_details={"sensitive_field": key, "value_redacted": True},
            )
        )
    return findings


def analyze_core_repository(repo_dir: str, manifest: RepositoryManifest) -> ScannerResult:
    """Analyze bounded, manifest-authorized source/configuration files without execution."""
    root = Path(repo_dir).resolve()
    contents: list[tuple[str, str]] = []
    for entry in sorted(manifest.files, key=lambda item: item.path):
        if entry.is_binary or entry.skipped_reason or entry.size_bytes > _MAX_CORE_FILE_BYTES:
            continue
        candidate = (root / entry.path).resolve()
        if not candidate.is_relative_to(root) or not candidate.is_file():
            continue
        try:
            contents.append((entry.path.replace("\\", "/"), candidate.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue

    config_text = "\n".join(
        text for path, text in contents if Path(path).suffix.lower() in _CONFIG_SUFFIXES
    ).lower()
    gateway_auth_visible = bool(re.search(
        r"(?:konghq\.com/plugins:.*(?:jwt|openid|oauth|auth[-_])|auth-url:|forwardauth|oauth2-proxy)",
        config_text,
    ))
    findings: list[StaticFinding] = []
    for path, text in contents:
        if Path(path).suffix.lower() == ".py":
            findings.extend(_authorization_header_findings(path, text, gateway_auth_visible=gateway_auth_visible))
        findings.extend(_hardcoded_credential_findings(path, text))
    deduplicated = {
        (finding.detector_id, finding.evidence.file_path, finding.evidence.start_line): finding
        for finding in findings
    }
    return ScannerResult(
        tool="repolens-core",
        status=ToolStatus.COMPLETED,
        findings=[deduplicated[key] for key in sorted(deduplicated)],
    )


__all__ = ["analyze_core_repository"]
