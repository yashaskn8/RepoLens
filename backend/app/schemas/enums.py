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
