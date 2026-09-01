"""Canonical immutable artifact and provenance schemas.

Artifact payloads live in an ``ArtifactStore``.  These records are the durable,
small metadata authority used to prove which repository revision, producer,
configuration, policy, and upstream artifacts created an analysis result.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ArtifactType(str, Enum):
    REPOSITORY_REVISION = "REPOSITORY_REVISION"
    ANALYZER_RUN = "ANALYZER_RUN"
    SCANNER = "SCANNER"
    SYMBOL_INDEX = "SYMBOL_INDEX"
    CONTRACT = "CONTRACT"
    COVERAGE = "COVERAGE"
    EVIDENCE = "EVIDENCE"
    CLAIM = "CLAIM"
    FINDING = "FINDING"
    AI_EXECUTION = "AI_EXECUTION"
    REPORT_DOCUMENT = "REPORT_DOCUMENT"
    PDF_REPORT = "PDF_REPORT"


class LineageRelation(str, Enum):
    """Direction is ``artifact_id --relation--> related_artifact_id``."""

    DERIVED_FROM = "DERIVED_FROM"
    PRODUCED_BY = "PRODUCED_BY"
    INVALIDATES = "INVALIDATES"
    SUPERSEDES = "SUPERSEDES"


class CoverageStatus(str, Enum):
    SUCCESSFULLY_ANALYZED = "SUCCESSFULLY_ANALYZED"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    TRUNCATED = "TRUNCATED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ArtifactSensitivity(str, Enum):
    INTERNAL = "INTERNAL"
    SOURCE_DERIVED = "SOURCE_DERIVED"
    SECURITY_SENSITIVE = "SECURITY_SENSITIVE"
    RESTRICTED = "RESTRICTED"


class RetentionClass(str, Enum):
    EPHEMERAL_REPOSITORY_SNAPSHOT = "EPHEMERAL_REPOSITORY_SNAPSHOT"
    SOURCE_BEARING_ARTIFACT = "SOURCE_BEARING_ARTIFACT"
    EMBEDDING = "EMBEDDING"
    ANALYSIS_ARTIFACT = "ANALYSIS_ARTIFACT"
    PDF_REPORT = "PDF_REPORT"
    WORKFLOW_EVENT = "WORKFLOW_EVENT"
    AUDIT_RECORD = "AUDIT_RECORD"
    GITHUB_PUBLICATION_RECORD = "GITHUB_PUBLICATION_RECORD"


class FrozenArtifactModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


class ArtifactCoverage(FrozenArtifactModel):
    status: CoverageStatus
    discovered_count: int | None = Field(default=None, ge=0)
    analyzed_count: int | None = Field(default=None, ge=0)
    unsupported_count: int = Field(default=0, ge=0)
    skipped_count: int = Field(default=0, ge=0)
    truncated_count: int = Field(default=0, ge=0)
    failed_count: int = Field(default=0, ge=0)
    explanation: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def validate_counts(self) -> "ArtifactCoverage":
        if (
            self.discovered_count is not None
            and self.analyzed_count is not None
            and self.analyzed_count > self.discovered_count
        ):
            raise ValueError("analyzed_count cannot exceed discovered_count")
        accounted = (
            (self.analyzed_count or 0)
            + self.unsupported_count
            + self.skipped_count
            + self.truncated_count
            + self.failed_count
        )
        if self.discovered_count is not None and accounted > self.discovered_count:
            raise ValueError("coverage counts cannot exceed discovered_count")
        if self.status != CoverageStatus.SUCCESSFULLY_ANALYZED and not self.explanation:
            raise ValueError("non-success coverage requires an explanation")
        return self


class ArtifactLineageEdge(FrozenArtifactModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    artifact_id: str = Field(min_length=1, max_length=128)
    relation: LineageRelation
    related_artifact_id: str = Field(min_length=1, max_length=128)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def prevent_self_reference(self) -> "ArtifactLineageEdge":
        if self.artifact_id == self.related_artifact_id:
            raise ValueError("artifact lineage cannot reference itself")
        return self


class CanonicalArtifact(FrozenArtifactModel):
    artifact_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    repository_id: str | None = Field(default=None, max_length=128)
    revision_id: str | None = Field(default=None, max_length=128)
    artifact_type: ArtifactType
    schema_version: str = Field(min_length=1, max_length=64)
    content_digest: str
    payload_locator: str = Field(min_length=1, max_length=1024)
    payload_size_bytes: int = Field(ge=0)
    media_type: str = Field(default="application/json", min_length=1, max_length=128)
    producer: str = Field(min_length=1, max_length=128)
    producer_version: str = Field(min_length=1, max_length=128)
    producer_config_digest: str
    policy_snapshot_id: str = Field(min_length=1, max_length=128)
    created_at: datetime
    lineage: tuple[ArtifactLineageEdge, ...] = ()
    coverage: ArtifactCoverage
    sensitivity: ArtifactSensitivity
    retention_class: RetentionClass

    @field_validator("content_digest", "producer_config_digest")
    @classmethod
    def require_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not _SHA256_RE.fullmatch(normalized):
            raise ValueError("digest must be a lowercase SHA-256 hexadecimal value")
        return normalized

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_lineage_ownership(self) -> "CanonicalArtifact":
        seen: set[tuple[LineageRelation, str]] = set()
        for edge in self.lineage:
            if edge.tenant_id != self.tenant_id:
                raise ValueError("lineage edge tenant does not match artifact tenant")
            if edge.artifact_id != self.artifact_id:
                raise ValueError("lineage edge does not originate from this artifact")
            identity = (edge.relation, edge.related_artifact_id)
            if identity in seen:
                raise ValueError("duplicate lineage edge")
            seen.add(identity)
        return self

    def identity_digest(self) -> str:
        """Stable idempotency identity, excluding locator, time, and record id."""

        identity = {
            "tenant_id": self.tenant_id,
            "repository_id": self.repository_id,
            "revision_id": self.revision_id,
            "artifact_type": self.artifact_type.value,
            "schema_version": self.schema_version,
            "content_digest": self.content_digest,
            "producer": self.producer,
            "producer_version": self.producer_version,
            "producer_config_digest": self.producer_config_digest,
            "policy_snapshot_id": self.policy_snapshot_id,
            "lineage": sorted(
                (edge.relation.value, edge.related_artifact_id) for edge in self.lineage
            ),
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class RevisionBoundArtifact(CanonicalArtifact):
    repository_id: str = Field(min_length=1, max_length=128)
    revision_id: str = Field(min_length=1, max_length=128)


class RepositoryRevisionArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.REPOSITORY_REVISION] = ArtifactType.REPOSITORY_REVISION


class AnalyzerRunArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.ANALYZER_RUN] = ArtifactType.ANALYZER_RUN


class ScannerArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.SCANNER] = ArtifactType.SCANNER


class SymbolIndexArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.SYMBOL_INDEX] = ArtifactType.SYMBOL_INDEX


class ContractArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.CONTRACT] = ArtifactType.CONTRACT


class CoverageArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.COVERAGE] = ArtifactType.COVERAGE


class EvidenceArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.EVIDENCE] = ArtifactType.EVIDENCE


class ClaimArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.CLAIM] = ArtifactType.CLAIM


class FindingArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.FINDING] = ArtifactType.FINDING


class AIExecutionArtifact(CanonicalArtifact):
    artifact_type: Literal[ArtifactType.AI_EXECUTION] = ArtifactType.AI_EXECUTION


class ReportDocumentArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.REPORT_DOCUMENT] = ArtifactType.REPORT_DOCUMENT


class PdfReportArtifact(RevisionBoundArtifact):
    artifact_type: Literal[ArtifactType.PDF_REPORT] = ArtifactType.PDF_REPORT


ArtifactRecord = Annotated[
    Union[
        RepositoryRevisionArtifact,
        AnalyzerRunArtifact,
        ScannerArtifact,
        SymbolIndexArtifact,
        ContractArtifact,
        CoverageArtifact,
        EvidenceArtifact,
        ClaimArtifact,
        FindingArtifact,
        AIExecutionArtifact,
        ReportDocumentArtifact,
        PdfReportArtifact,
    ],
    Field(discriminator="artifact_type"),
]


ARTIFACT_CLASS_BY_TYPE: dict[ArtifactType, type[CanonicalArtifact]] = {
    ArtifactType.REPOSITORY_REVISION: RepositoryRevisionArtifact,
    ArtifactType.ANALYZER_RUN: AnalyzerRunArtifact,
    ArtifactType.SCANNER: ScannerArtifact,
    ArtifactType.SYMBOL_INDEX: SymbolIndexArtifact,
    ArtifactType.CONTRACT: ContractArtifact,
    ArtifactType.COVERAGE: CoverageArtifact,
    ArtifactType.EVIDENCE: EvidenceArtifact,
    ArtifactType.CLAIM: ClaimArtifact,
    ArtifactType.FINDING: FindingArtifact,
    ArtifactType.AI_EXECUTION: AIExecutionArtifact,
    ArtifactType.REPORT_DOCUMENT: ReportDocumentArtifact,
    ArtifactType.PDF_REPORT: PdfReportArtifact,
}
