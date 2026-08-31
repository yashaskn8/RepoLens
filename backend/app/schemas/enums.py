"""Domain enums for RepoLens findings, scans, and severities."""

from enum import Enum


class Severity(str, Enum):
    """Severity levels for detected issues and security/quality findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""

    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"


class ScanStatus(str, Enum):
    """Lifecycle status of a repository scan."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class VerificationVerdict(str, Enum):
    """Verification verdict for candidate findings."""

    CONFIRMED = "CONFIRMED"
    POSSIBLE = "POSSIBLE"
    REJECTED = "REJECTED"


class PatchStatus(str, Enum):
    """Lifecycle and approval status of a remediation patch."""

    DRAFT = "DRAFT"
    VERIFIED = "VERIFIED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    REJECTED = "REJECTED"
    APPROVED = "APPROVED"


class DeliveryStatus(str, Enum):
    """Lifecycle and execution status of a patch pull request delivery."""

    PENDING = "PENDING"
    VALIDATING = "VALIDATING"
    BLOCKED = "BLOCKED"
    READY = "READY"
    CREATING_COMMIT = "CREATING_COMMIT"
    CREATING_BRANCH = "CREATING_BRANCH"
    CREATING_PR = "CREATING_PR"
    PR_CREATED = "PR_CREATED"
    FAILED = "FAILED"


class ChangeAnalysisStatus(str, Enum):
    """Lifecycle status of a revision-to-revision change analysis."""

    PENDING = "PENDING"
    ACQUIRING = "ACQUIRING"
    DIFFING = "DIFFING"
    ANALYZING = "ANALYZING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ChangeImpactType(str, Enum):
    """Evidence-backed taxonomy of semantic impact categories."""

    SYMBOL_CHANGE = "SYMBOL_CHANGE"
    CALLER_IMPACT = "CALLER_IMPACT"
    API_CONTRACT_CHANGE = "API_CONTRACT_CHANGE"
    SCHEMA_CHANGE = "SCHEMA_CHANGE"
    DEPENDENCY_CHANGE = "DEPENDENCY_CHANGE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SECURITY_SENSITIVE_CHANGE = "SECURITY_SENSITIVE_CHANGE"


class ImpactVerificationStatus(str, Enum):
    """Epistemic certainty status of an impact record, distinguishing deterministic facts from inferences."""

    FACT = "FACT"
    INFERENCE = "INFERENCE"
    ASSUMPTION = "ASSUMPTION"


class ChangeRiskLevel(str, Enum):
    """Aggregate risk rating for a change set."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class UserRole(str, Enum):
    """Role-based access control roles for RepoLens users."""

    USER = "USER"
    OPERATOR = "OPERATOR"


class UsageOperation(str, Enum):
    """Taxonomy of quota-tracked expensive operations."""

    SCAN_CREATE = "SCAN_CREATE"
    CHANGE_ANALYSIS_CREATE = "CHANGE_ANALYSIS_CREATE"
    PATCH_GENERATE = "PATCH_GENERATE"


