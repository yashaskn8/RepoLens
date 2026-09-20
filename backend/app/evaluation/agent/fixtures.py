"""Construction of hostile temporary repositories for agent evaluation trials."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import tempfile
from typing import Any
from uuid import uuid4

from app.agent_tools import AgentToolContext, AgentToolRegistry, RepositorySnapshot, create_agent_tool_registry
from app.agents.state import AnalysisState
from app.analysis.store import EvidenceStore
from app.evaluation.agent.loader import canonical_json
from app.evaluation.agent.schemas import AgentEvalCase
from app.graph.builder import build_repository_graph
from app.indexing.chunker import chunk_manifest
from app.ingestion.detector import detect_language
from app.ingestion.parser import parse_file_with_calls
from app.ingestion.schemas import FileEntry, RepositoryManifest
from app.schemas.enums import Severity, VerificationVerdict
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.metadata import ModelExecutionMetadata


def fixture_snapshot_id(case: AgentEvalCase) -> str:
    """Derive a deterministic 40-character fixture snapshot identity."""
    material = canonical_json({
        "repository_url": case.fixture.repository_url,
        "files": case.fixture.files,
    }).encode("utf-8")
    return hashlib.sha1(material).hexdigest()


@dataclass
class AgentEvalFixtureRuntime:
    """Real deterministic services owned by one isolated evaluation trial."""

    case: AgentEvalCase
    temporary_directory: tempfile.TemporaryDirectory[str]
    repository_root: Path
    evidence_store: EvidenceStore
    repository_graph: Any
    chunks: list[Any]
    snapshot: RepositorySnapshot
    registry: AgentToolRegistry
    initial_state: AnalysisState

    def close(self) -> None:
        self.temporary_directory.cleanup()

    def __enter__(self) -> "AgentEvalFixtureRuntime":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _severity(value: str | None) -> Severity:
    try:
        return Severity(str(value or "INFO").upper())
    except ValueError:
        return Severity.INFO


def build_fixture_runtime(case: AgentEvalCase) -> AgentEvalFixtureRuntime:
    """Build production ingestion/index/tool services without executing fixture code."""
    temporary_directory = tempfile.TemporaryDirectory(prefix="repolens_agent_eval_")
    repository_root = Path(temporary_directory.name).resolve()
    snapshot_id = fixture_snapshot_id(case)
    file_entries: list[FileEntry] = []
    file_contents: dict[str, str] = {}
    language_counts: dict[str, int] = {}

    try:
        for relative_path, content in sorted(case.fixture.files.items()):
            target = (repository_root / Path(*relative_path.split("/"))).resolve()
            target.relative_to(repository_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            source_bytes = content.encode("utf-8")
            # Preserve the fixture bytes exactly.  ``Path.write_text`` applies
            # platform newline translation on Windows, which would make the
            # manifest size/digest disagree with the snapshot attestation.
            target.write_bytes(source_bytes)
            language = detect_language(relative_path)
            symbols, calls = parse_file_with_calls(relative_path, language or "", source_bytes)
            file_entries.append(FileEntry(
                path=relative_path,
                language=language,
                size_bytes=len(source_bytes),
                lines_count=max(1, len(content.splitlines())),
                symbols=symbols,
                calls=calls,
            ))
            if language:
                language_counts[language] = language_counts.get(language, 0) + 1

        manifest = RepositoryManifest(
            repository_url=case.fixture.repository_url,
            commit_hash=snapshot_id,
            commit_sha=snapshot_id,
            total_files=len(file_entries),
            total_size_bytes=sum(item.size_bytes for item in file_entries),
            languages=language_counts,
            files=file_entries,
        )
        evidence_store = EvidenceStore(manifest)
        repository_graph = build_repository_graph(manifest, evidence_store)
        chunks = chunk_manifest(manifest, file_contents=case.fixture.files)
        snapshot = RepositorySnapshot.create(
            snapshot_id=snapshot_id,
            repository_root=repository_root,
            evidence_store=evidence_store,
            graph=repository_graph,
            chunks=chunks,
            component_versions={"agent_eval": "1.0.0"},
            capture_source_digests=True,
        )
        registry = create_agent_tool_registry(AgentToolContext.from_snapshot(snapshot))
        finding_id = uuid4()
        scan_id = str(uuid4())
        finding = Finding(
            id=finding_id,
            scan_id=scan_id,
            title=case.investigator_input.title,
            description=case.investigator_input.description,
            category=case.category,
            severity=_severity(case.investigator_input.severity),
            verification_verdict=VerificationVerdict.POSSIBLE,
            verification_reason=case.investigator_input.verifier_uncertainty_reason,
            evidences=[Evidence(
                file_path=case.investigator_input.primary_file,
                start_line=case.investigator_input.primary_start_line,
                end_line=case.investigator_input.primary_end_line,
            )],
            model_metadata=ModelExecutionMetadata(
                model_name="agent-eval-input",
                provider="evaluation",
            ),
        )
        initial_state: AnalysisState = {
            "scan_id": scan_id,
            "commit_hash": snapshot_id,
            "candidate_findings": [finding],
            "rejected_findings": [{
                "finding_id": str(finding_id),
                "verdict": VerificationVerdict.POSSIBLE.value,
                "reason": case.investigator_input.verifier_uncertainty_reason,
            }],
            "revision_target_ids": [str(finding_id)],
            "revision_count": 0,
            "agent_investigator_enabled": True,
            "investigator": {},
            "investigation_evidence": {},
            "completed_nodes": [],
            "model_executions": [],
            "errors": [],
        }
        return AgentEvalFixtureRuntime(
            case=case,
            temporary_directory=temporary_directory,
            repository_root=repository_root,
            evidence_store=evidence_store,
            repository_graph=repository_graph,
            chunks=chunks,
            snapshot=snapshot,
            registry=registry,
            initial_state=initial_state,
        )
    except Exception:
        temporary_directory.cleanup()
        raise


__all__ = ["AgentEvalFixtureRuntime", "build_fixture_runtime", "fixture_snapshot_id"]
