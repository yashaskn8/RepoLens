"""Safe loading, canonical hashing, and anti-leakage checks for agent evals."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from app.evaluation.agent.schemas import (
    AgentEvalCase,
    AgentEvalDatasetManifest,
)


DEFAULT_DATASET_ROOT = Path(__file__).resolve().parents[3] / "evaluation_data" / "agent" / "v1"


class AgentEvalDatasetError(ValueError):
    """Raised when the agent-evaluation dataset is invalid or mutated."""


class AgentEvalDataset(BaseModel):
    """Loaded immutable case inventory with its canonical content hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: AgentEvalDatasetManifest
    cases: tuple[AgentEvalCase, ...] = Field(min_length=1)
    dataset_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    root: str = Field(min_length=1)


def canonical_json(value: Any) -> str:
    """Serialize JSON-compatible values deterministically for hashing."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_dataset_hash(cases: Iterable[AgentEvalCase]) -> str:
    """Hash canonical case content independent of manifest file ordering."""
    payload = [
        case.model_dump(mode="json")
        for case in sorted(cases, key=lambda item: item.case_id)
    ]
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def public_case_payload(case: AgentEvalCase) -> dict[str, Any]:
    """Return only repository input and verifier facts safe for model setup.

    Hidden annotations and scripted decisions are intentionally absent.
    """
    return {
        "fixture": case.fixture.model_dump(mode="json"),
        "investigator_input": case.investigator_input.model_dump(mode="json"),
    }


def assert_no_case_leakage(case: AgentEvalCase) -> None:
    """Reject hidden labels or controls appearing in model-visible case data."""
    fixture_text = "\n".join(case.fixture.files.values())
    public_text = canonical_json(public_case_payload(case))
    scripted_text = canonical_json([item.model_dump(mode="json") for item in case.scripted_decisions])
    hidden_canary = case.annotation.hidden_canary
    if hidden_canary in fixture_text or hidden_canary in public_text or hidden_canary in scripted_text:
        raise AgentEvalDatasetError(f"hidden canary leaked for case {case.case_id}")

    annotation_text = canonical_json(case.annotation.model_dump(mode="json"))
    # The canary check is authoritative for arbitrary hidden prose.  This
    # additional exact serialized check catches accidental annotation dumps.
    if annotation_text in fixture_text or annotation_text in public_text:
        raise AgentEvalDatasetError(f"annotation payload leaked for case {case.case_id}")


def _load_manifest(root: Path) -> AgentEvalDatasetManifest:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise AgentEvalDatasetError(f"missing dataset manifest: {manifest_path}")
    try:
        return AgentEvalDatasetManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AgentEvalDatasetError(f"invalid dataset manifest: {exc}") from exc


def load_agent_dataset(root: str | Path = DEFAULT_DATASET_ROOT) -> AgentEvalDataset:
    """Load and validate every case without silently repairing malformed data."""
    dataset_root = Path(root).resolve()
    manifest = _load_manifest(dataset_root)
    cases_dir = dataset_root / "cases"
    cases: list[AgentEvalCase] = []
    seen_ids: set[str] = set()
    for filename in manifest.case_files:
        path = cases_dir / filename
        if not path.is_file() or path.parent != cases_dir:
            raise AgentEvalDatasetError(f"missing or unsafe case file: {filename}")
        try:
            case = AgentEvalCase.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise AgentEvalDatasetError(f"invalid case file {filename}: {exc}") from exc
        if case.case_id in seen_ids:
            raise AgentEvalDatasetError(f"duplicate case_id: {case.case_id}")
        seen_ids.add(case.case_id)
        assert_no_case_leakage(case)
        cases.append(case)

    computed_hash = compute_dataset_hash(cases)
    if manifest.dataset_hash is not None and manifest.dataset_hash != computed_hash:
        raise AgentEvalDatasetError(
            f"dataset hash mismatch: manifest={manifest.dataset_hash}, computed={computed_hash}"
        )
    return AgentEvalDataset(
        manifest=manifest,
        cases=tuple(sorted(cases, key=lambda item: item.case_id)),
        dataset_hash=computed_hash,
        root=str(dataset_root),
    )


__all__ = [
    "AgentEvalDataset",
    "AgentEvalDatasetError",
    "DEFAULT_DATASET_ROOT",
    "assert_no_case_leakage",
    "canonical_json",
    "compute_dataset_hash",
    "load_agent_dataset",
    "public_case_payload",
]
