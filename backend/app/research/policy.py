"""Domain authority classification, evidence ranking, and prompt injection defenses for research."""

import re
from typing import List
from urllib.parse import urlparse

from app.research.schemas import ResearchEvidence, SourceTier

# Canonical Domain Rule Sets
_OFFICIAL_DOC_DOMAINS = {
    "fastapi.tiangolo.com",
    "docs.python.org",
    "react.dev",
    "reactjs.org",
    "expressjs.com",
    "docs.pydantic.dev",
    "pydantic-docs.helpmanual.io",
    "nextjs.org",
    "docs.sqlalchemy.org",
    "typescriptlang.org",
    "nodejs.org",
    "flask.palletsprojects.com",
    "docs.djangoproject.com",
    "networkx.org",
    "vitest.dev",
    "jestjs.io",
    "pkg.go.dev",
    "golang.org",
    "docs.rs",
    "rust-lang.org",
}

_ADVISORY_DOMAINS = {
    "osv.dev",
    "nvd.nist.gov",
    "cve.mitre.org",
    "cve.org",
    "security.snyk.io",
    "vulncheck.com",
}

_VENDOR_DOC_DOMAINS = {
    "developer.mozilla.org",
    "cloud.google.com",
    "aws.amazon.com",
    "learn.microsoft.com",
    "v8.dev",
    "web.dev",
}


def classify_source_url(url: str) -> SourceTier:
    """Classify a source URL into an authoritative source tier."""
    if not url or not isinstance(url, str):
        return SourceTier.COMMUNITY

    try:
        parsed = urlparse(url.strip())
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()

        # 1. Official Documentation Domains
        if any(hostname == d or hostname.endswith("." + d) for d in _OFFICIAL_DOC_DOMAINS):
            return SourceTier.OFFICIAL_DOCS

        # 2. Release Notes & Changelogs
        if hostname == "github.com" and any(token in path for token in ["/releases", "/changelog", "/releases/tag"]):
            return SourceTier.RELEASE_NOTES
        if (hostname == "pypi.org" and "#history" in url) or (hostname == "npmjs.com" and "/v/" in path):
            return SourceTier.RELEASE_NOTES

        # 3. Security Advisories
        if hostname == "github.com" and "/advisories" in path:
            return SourceTier.SECURITY_ADVISORY
        if any(hostname == d or hostname.endswith("." + d) for d in _ADVISORY_DOMAINS):
            return SourceTier.SECURITY_ADVISORY

        # 4. Vendor Engineering Docs
        if any(hostname == d or hostname.endswith("." + d) for d in _VENDOR_DOC_DOMAINS):
            return SourceTier.VENDOR_DOCS

        return SourceTier.COMMUNITY
    except Exception:
        return SourceTier.COMMUNITY


def rank_and_filter_evidences(evidences: List[ResearchEvidence]) -> List[ResearchEvidence]:
    """Sort research citations by authoritative tier (1 -> 5), then by confidence descending."""
    classified: List[ResearchEvidence] = []
    seen_urls = set()

    for ev in evidences:
        clean_url = ev.source_url.strip()
        if not clean_url or clean_url in seen_urls:
            continue
        seen_urls.add(clean_url)

        tier = classify_source_url(clean_url)
        classified.append(
            ResearchEvidence(
                source_url=clean_url,
                source_title=ev.source_title,
                retrieved_date=ev.retrieved_date,
                supported_claim=ev.supported_claim,
                confidence=ev.confidence,
                source_tier=tier,
            )
        )

    # Sort primarily by source_tier (lower number = higher authority), secondarily by confidence descending
    classified.sort(key=lambda item: (item.source_tier.value, -item.confidence, item.source_url))
    return classified


def sanitize_untrusted_web_text(text: str) -> str:
    """Sanitize and fence external web snippet text to prevent prompt injection."""
    if not text:
        return ""
    # Strip potential raw control instructions attempting to override system role
    cleaned = re.sub(r"(?i)(ignore previous instructions|system prompt|disregard all)", "[filtered]", text)
    return f"<untrusted_external_evidence>\n{cleaned.strip()}\n</untrusted_external_evidence>"
