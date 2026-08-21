"""Tests for Phase 3.5O: Deterministic function/method CALLS edge extraction and graph wiring."""

import os
import tempfile
import pytest

from app.graph.builder import build_repository_graph
from app.graph.schemas import EdgeKind, NodeKind
from app.ingestion.manifest import build_manifest
from app.ingestion.parser import parse_file_with_calls


# =============================================================================
# 1. AST Parser Unit Tests for Calls and Structured Imports
# =============================================================================

def test_python_call_and_import_extraction():
    """Verify Tree-sitter extracts Python calls and structured import details."""
    py_code = b"""
from services.auth import verify_token, hash_password as hash_pwd
import utils.logger as logger

def helper():
    return 42

def process_request():
    token = verify_token("header")
    pwd = hash_pwd("secret")
    val = helper()
    logger.log_event("done")
    user.save()
"""
    symbols, calls = parse_file_with_calls("main.py", "python", py_code)

    # 1. Check symbols
    sym_names = [s.name for s in symbols]
    assert "helper" in sym_names
    assert "process_request" in sym_names
    assert any("services.auth" in s.name for s in symbols if s.kind.value == "IMPORT")

    # 2. Check import details
    import_sym = next(s for s in symbols if "services.auth" in s.name)
    assert import_sym.details["is_from"] is True
    assert import_sym.details["module"] == "services.auth"
    assert import_sym.details["imported_names"]["verify_token"] == "verify_token"
    assert import_sym.details["imported_names"]["hash_pwd"] == "hash_password"

    # 3. Check calls
    callee_names = [c.callee_name for c in calls]
    assert "verify_token" in callee_names
    assert "hash_pwd" in callee_names
    assert "helper" in callee_names
    assert "log_event" in callee_names
    assert "save" in callee_names

    # Check caller context
    helper_call = next(c for c in calls if c.callee_name == "helper")
    assert helper_call.caller_name == "process_request"
    assert helper_call.caller_kind == "FUNCTION"
    assert helper_call.callee_base is None

    member_call = next(c for c in calls if c.callee_name == "log_event")
    assert member_call.callee_base == "logger"


def test_js_ts_call_and_import_extraction():
    """Verify Tree-sitter extracts JS/TS calls and structured import details."""
    ts_code = b"""
import { verifyToken, hashPassword as hashPwd } from './auth';
import * as formatters from '../utils/formatter';

function localHelper(val: string) {
    return val.toUpperCase();
}

export function handleAction() {
    const v1 = localHelper("test");
    const v2 = verifyToken("token");
    const v3 = hashPwd("pass");
    const v4 = formatters.formatName("alice");
    res.status(200).json({ ok: true });
}
"""
    symbols, calls = parse_file_with_calls("controller.ts", "typescript", ts_code)

    sym_names = [s.name for s in symbols]
    assert "localHelper" in sym_names
    assert "handleAction" in sym_names

    # Import details
    auth_imp = next(s for s in symbols if "./auth" in s.name)
    assert auth_imp.details["source"] == "./auth"
    assert auth_imp.details["imported_names"]["verifyToken"] == "verifyToken"
    assert auth_imp.details["imported_names"]["hashPwd"] == "hashPassword"

    # Calls
    callee_names = [c.callee_name for c in calls]
    assert "localHelper" in callee_names
    assert "verifyToken" in callee_names
    assert "hashPwd" in callee_names
    assert "formatName" in callee_names


# =============================================================================
# 2. Graph Wiring Fixtures & Verification
# =============================================================================

@pytest.fixture
def multi_module_repo_fixture():
    """Create a temporary repository workspace with:
    - Same-file calls
    - Imported cross-file calls
    - Same-name functions in different modules
    - Ambiguous unimported calls
    - Unresolvable dynamic receiver method calls
    """
    with tempfile.TemporaryDirectory(prefix="calls_repo_") as tmp_dir:
        # 1. services/auth.py
        os.makedirs(os.path.join(tmp_dir, "services"), exist_ok=True)
        with open(os.path.join(tmp_dir, "services", "auth.py"), "w", encoding="utf-8") as f:
            f.write(
                "def verify_token(token: str):\n"
                "    return {'valid': True}\n\n"
                "def validate():\n"
                "    return 'AUTH_VALIDATE'\n"
            )

        # 2. services/data.py (has same-name function validate())
        with open(os.path.join(tmp_dir, "services", "data.py"), "w", encoding="utf-8") as f:
            f.write(
                "def validate():\n"
                "    return 'DATA_VALIDATE'\n\n"
                "def fetch_records():\n"
                "    return [1, 2, 3]\n"
            )

        # 3. main.py (resolves same-file, imported auth.verify_token and auth.validate)
        with open(os.path.join(tmp_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "from services.auth import verify_token, validate as auth_validate\n\n"
                "def local_helper():\n"
                "    return 42\n\n"
                "def entrypoint():\n"
                "    h = local_helper()\n"
                "    t = verify_token('abc')\n"
                "    v = auth_validate()\n"
                "    return h\n"
            )

        # 4. ambiguous_caller.py (calls validate() without importing it from anywhere)
        with open(os.path.join(tmp_dir, "ambiguous_caller.py"), "w", encoding="utf-8") as f:
            f.write(
                "def run_unimported():\n"
                "    return validate()\n"
            )

        # 5. method_caller.py (invokes dynamic receiver method calls that cannot safely be resolved)
        with open(os.path.join(tmp_dir, "method_caller.py"), "w", encoding="utf-8") as f:
            f.write(
                "def handle_user(user, response):\n"
                "    user.save()\n"
                "    response.json({'status': 'ok'})\n"
            )

        # 6. TS components: utils/math.ts and app.ts
        os.makedirs(os.path.join(tmp_dir, "src", "utils"), exist_ok=True)
        with open(os.path.join(tmp_dir, "src", "utils", "math.ts"), "w", encoding="utf-8") as f:
            f.write(
                "export function addNumbers(a: number, b: number): number {\n"
                "    return a + b;\n"
                "}\n"
            )

        with open(os.path.join(tmp_dir, "src", "app.ts"), "w", encoding="utf-8") as f:
            f.write(
                "import { addNumbers } from './utils/math';\n\n"
                "function internalCompute(x: number) {\n"
                "    return addNumbers(x, 10);\n"
                "}\n\n"
                "export function main() {\n"
                "    return internalCompute(5);\n"
                "}\n"
            )

        manifest = build_manifest(tmp_dir, "https://github.com/org/calls-test.git", "commit123")
        graph = build_repository_graph(manifest)

        yield graph, tmp_dir


def test_same_file_python_calls_resolved(multi_module_repo_fixture):
    """Verify same-file Python function calls produce deterministic CALLS edges with line numbers."""
    graph, _ = multi_module_repo_fixture

    call_edges = [e for e in graph.get_edges_by_kind(EdgeKind.CALLS) if e.metadata.get("resolution") == "same_file"]
    same_file_python = [e for e in call_edges if "main.py" in e.metadata.get("call_site_file", "")]

    assert len(same_file_python) >= 1
    edge = same_file_python[0]
    assert edge.metadata["callee_name"] == "local_helper"
    assert edge.metadata["call_site_line"] == 7
    assert edge.metadata["deterministic"] is True
    assert "symbol:main.py:FUNCTION:local_helper" in edge.target


def test_imported_python_symbol_resolved_deterministically(multi_module_repo_fixture):
    """Verify imported symbol calls resolve strictly to target module functions."""
    graph, _ = multi_module_repo_fixture

    call_edges = [e for e in graph.get_edges_by_kind(EdgeKind.CALLS) if e.metadata.get("resolution") == "imported"]

    verify_token_edges = [e for e in call_edges if e.metadata.get("callee_name") == "verify_token"]
    assert len(verify_token_edges) == 1
    v_edge = verify_token_edges[0]
    assert v_edge.metadata["imported_from"] == "services/auth.py"
    assert v_edge.metadata["call_site_line"] == 8
    assert "services/auth.py" in v_edge.target


def test_same_name_functions_in_different_modules_isolated(multi_module_repo_fixture):
    """Verify validate() in auth.py is linked when imported, and data.py validate() is NOT falsely targeted."""
    graph, _ = multi_module_repo_fixture

    call_edges = [e for e in graph.get_edges_by_kind(EdgeKind.CALLS) if "auth_validate" in e.metadata.get("callee_name", "")]
    assert len(call_edges) == 1

    edge = call_edges[0]
    # Must target services/auth.py's validate, NEVER services/data.py
    assert "services/auth.py" in edge.target
    assert "services/data.py" not in edge.target


def test_ambiguous_unimported_calls_do_not_guess(multi_module_repo_fixture):
    """Verify unimported calls to functions with ambiguous definitions create NO edges and are recorded in metadata."""
    graph, _ = multi_module_repo_fixture

    # Ensure NO CALLS edge originates from ambiguous_caller.py
    ambiguous_edges = [
        e for e in graph.get_edges_by_kind(EdgeKind.CALLS)
        if "ambiguous_caller.py" in e.metadata.get("call_site_file", "")
    ]
    assert len(ambiguous_edges) == 0

    # Ensure file node metadata preserved the unresolved call
    file_node = graph.get_node("file:ambiguous_caller.py")
    assert file_node is not None
    unresolved = file_node.metadata.get("unresolved_calls", [])
    assert len(unresolved) == 1
    assert unresolved[0]["callee_name"] == "validate"


def test_dynamic_receiver_method_calls_safely_unresolved(multi_module_repo_fixture):
    """Verify user.save() and response.json() do not fabricate guessed edges."""
    graph, _ = multi_module_repo_fixture

    method_edges = [
        e for e in graph.get_edges_by_kind(EdgeKind.CALLS)
        if "method_caller.py" in e.metadata.get("call_site_file", "")
    ]
    assert len(method_edges) == 0

    file_node = graph.get_node("file:method_caller.py")
    assert file_node is not None
    unresolved = file_node.metadata.get("unresolved_calls", [])
    assert len(unresolved) == 2
    callees = [u["callee"] for u in unresolved]
    assert "user.save" in callees
    assert "response.json" in callees


def test_js_ts_same_file_and_imported_calls_resolved(multi_module_repo_fixture):
    """Verify JS/TS same-file and imported calls are resolved into CALLS edges."""
    graph, _ = multi_module_repo_fixture

    ts_calls = [
        e for e in graph.get_edges_by_kind(EdgeKind.CALLS)
        if "src/app.ts" in e.metadata.get("call_site_file", "")
    ]

    assert len(ts_calls) == 2

    # 1. Same-file: main -> internalCompute
    same_file = next(e for e in ts_calls if e.metadata.get("resolution") == "same_file")
    assert same_file.metadata["callee_name"] == "internalCompute"
    assert "src/app.ts" in same_file.target

    # 2. Imported: internalCompute -> addNumbers (in src/utils/math.ts)
    imported = next(e for e in ts_calls if e.metadata.get("resolution") == "imported")
    assert imported.metadata["callee_name"] == "addNumbers"
    assert imported.metadata["imported_from"] == "src/utils/math.ts"
    assert "src/utils/math.ts" in imported.target
