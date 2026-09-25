"""Reviewed, versioned model-execution expectations for the bounded live smoke.

This campaign metadata is deliberately separate from the frozen ground-truth
benchmark contract: it describes execution paths, not labels or case inputs.
Entries are added only after a canonical full-graph trace proves the named
model node is reached for that public DEV case.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from app.evaluation.campaign.contracts import CampaignModel, canonical_digest


SMOKE_PATH_MANIFEST_VERSION = "live-model-smoke-paths/1.0"


class SmokeModelPathEntry(CampaignModel):
    case_id: str = Field(min_length=1, max_length=128)
    category: Literal["CORRECTNESS", "SECURITY"]
    expected_model_nodes: tuple[Literal[
        "architecture", "integration", "security", "bug", "verifier",
        "investigator_decide", "revise",
    ], ...] = Field(min_length=1, max_length=7)

    @model_validator(mode="after")
    def validate_nodes(self) -> "SmokeModelPathEntry":
        if len(self.expected_model_nodes) != len(set(self.expected_model_nodes)):
            raise ValueError("smoke model-path nodes must be unique")
        return self


class SmokeModelPathManifest(CampaignModel):
    version: Literal["live-model-smoke-paths/1.0"] = SMOKE_PATH_MANIFEST_VERSION
    entries: tuple[SmokeModelPathEntry, ...] = Field(max_length=35)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_manifest(self) -> "SmokeModelPathManifest":
        case_ids = [entry.case_id for entry in self.entries]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("smoke model-path manifest case IDs must be unique")
        payload = self.model_dump(mode="json", exclude={"digest"})
        if canonical_digest(payload) != self.digest:
            raise ValueError("smoke model-path manifest digest mismatch")
        return self


_SMOKE_PATH_PAYLOAD = {
    "version": SMOKE_PATH_MANIFEST_VERSION,
    "entries": [
        {
            "case_id": "BUG-EXCEPT-01A",
            "category": "CORRECTNESS",
            "expected_model_nodes": ["bug"],
        },
    ],
}

# No SECURITY case is qualified yet: the zero-key canonical full-graph run
# reached no live-model node for any public DEV security case. Keep the
# manifest incomplete rather than manufacture a qualification or spend calls
# probing cases at runtime.
SMOKE_MODEL_PATH_MANIFEST = SmokeModelPathManifest(
    **_SMOKE_PATH_PAYLOAD,
    digest=canonical_digest(_SMOKE_PATH_PAYLOAD),
)


__all__ = [
    "SMOKE_MODEL_PATH_MANIFEST",
    "SMOKE_PATH_MANIFEST_VERSION",
    "SmokeModelPathEntry",
    "SmokeModelPathManifest",
]
