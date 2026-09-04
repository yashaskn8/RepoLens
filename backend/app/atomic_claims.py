"""Internal atomic claim contract for deterministic verifier decisions."""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, Field


class AtomicClaimType(str, Enum):
    SOURCE_BEHAVIOR = "SOURCE_BEHAVIOR"
    TRIGGER = "TRIGGER"
    MECHANISM = "MECHANISM"
    IMPACT = "IMPACT"
    SEVERITY = "SEVERITY"
    MITIGATION = "MITIGATION"


class ClaimVerificationState(str, Enum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT = "INSUFFICIENT"


class AtomicClaim(BaseModel):
    """One independently verifiable material assertion in a model finding."""

    claim_id: str
    claim_type: AtomicClaimType
    claim_text: str = Field(min_length=1, max_length=4_000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)
    depends_on: list[str] = Field(default_factory=list, max_length=4)
    verification_state: ClaimVerificationState = ClaimVerificationState.INSUFFICIENT
    verification_reason: str | None = Field(default=None, max_length=2_000)


def _claim_id(claim_type: AtomicClaimType, text: str, evidence_refs: list[str]) -> str:
    material = "\0".join([claim_type.value, text, *evidence_refs])
    return f"claim:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}"


def claims_from_model_item(item: Mapping[str, Any]) -> list[AtomicClaim]:
    """Extract explicit specialist claims without inventing missing semantics."""
    references = [
        value for value in item.get("evidence_refs", [])
        if isinstance(value, str) and value
    ][:16]
    claims: list[AtomicClaim] = []

    def add_claim(
        claim_type: AtomicClaimType,
        field_name: str,
        *,
        evidence_refs: list[str],
        depends_on: list[str],
    ) -> AtomicClaim | None:
        value = item.get(field_name)
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()[:4_000]
        claim = AtomicClaim(
            claim_id=_claim_id(claim_type, text, evidence_refs),
            claim_type=claim_type,
            claim_text=text,
            evidence_refs=evidence_refs,
            depends_on=depends_on,
        )
        claims.append(claim)
        return claim

    source = add_claim(
        AtomicClaimType.SOURCE_BEHAVIOR,
        "source_behavior",
        evidence_refs=references[:1],
        depends_on=[],
    )
    trigger = add_claim(
        AtomicClaimType.TRIGGER,
        "trigger_condition",
        evidence_refs=references[:2],
        depends_on=[source.claim_id] if source else [],
    )
    mechanism = add_claim(
        AtomicClaimType.MECHANISM,
        "failure_mechanism",
        evidence_refs=references[:2],
        depends_on=[trigger.claim_id] if trigger else [],
    )
    impact = add_claim(
        AtomicClaimType.IMPACT,
        "impact_claim",
        evidence_refs=references[:1],
        depends_on=[mechanism.claim_id] if mechanism else [],
    )
    if claims and isinstance(item.get("severity"), str):
        text = f"Claimed severity is {item['severity']}."
        claims.append(
            AtomicClaim(
                claim_id=_claim_id(AtomicClaimType.SEVERITY, text, references),
                claim_type=AtomicClaimType.SEVERITY,
                claim_text=text,
                evidence_refs=[],
                depends_on=[impact.claim_id] if impact else ([mechanism.claim_id] if mechanism else []),
            )
        )
    mitigation = item.get("mitigation_guidance")
    if claims and isinstance(mitigation, str) and mitigation.strip():
        text = mitigation.strip()[:4_000]
        claims.append(
            AtomicClaim(
                claim_id=_claim_id(AtomicClaimType.MITIGATION, text, references),
                claim_type=AtomicClaimType.MITIGATION,
                claim_text=text,
                evidence_refs=[],
                depends_on=[mechanism.claim_id] if mechanism else [],
            )
        )
    return claims


def has_complete_atomic_contract(claims: list[AtomicClaim]) -> bool:
    """Require the complete candidate-first claim dependency chain."""
    by_type = {claim.claim_type: claim for claim in claims}
    required = {
        AtomicClaimType.SOURCE_BEHAVIOR,
        AtomicClaimType.TRIGGER,
        AtomicClaimType.MECHANISM,
        AtomicClaimType.IMPACT,
        AtomicClaimType.SEVERITY,
    }
    if not required.issubset(by_type):
        return False
    return (
        not by_type[AtomicClaimType.SOURCE_BEHAVIOR].depends_on
        and by_type[AtomicClaimType.SOURCE_BEHAVIOR].claim_id
        in by_type[AtomicClaimType.TRIGGER].depends_on
        and by_type[AtomicClaimType.TRIGGER].claim_id
        in by_type[AtomicClaimType.MECHANISM].depends_on
        and by_type[AtomicClaimType.MECHANISM].claim_id
        in by_type[AtomicClaimType.IMPACT].depends_on
        and by_type[AtomicClaimType.IMPACT].claim_id
        in by_type[AtomicClaimType.SEVERITY].depends_on
    )


def claims_from_metadata(metadata: Any) -> list[AtomicClaim]:
    """Fail closed when persisted model metadata contains malformed claims."""
    extra = getattr(metadata, "extra_metadata", None)
    raw_claims = extra.get("atomic_claims", []) if isinstance(extra, dict) else []
    claims: list[AtomicClaim] = []
    for raw in raw_claims:
        try:
            claims.append(AtomicClaim.model_validate(raw))
        except (TypeError, ValueError):
            return []
    return claims


__all__ = [
    "AtomicClaim",
    "AtomicClaimType",
    "ClaimVerificationState",
    "claims_from_metadata",
    "claims_from_model_item",
    "has_complete_atomic_contract",
]
