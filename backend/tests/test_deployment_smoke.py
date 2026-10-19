"""Deployment smoke stays non-destructive unless two explicit controls agree."""

import httpx

from app.cli.deployment_smoke import StagingSmoke


def test_staging_smoke_default_reaches_previews_without_external_writes():
    calls = []
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        path = request.url.path
        if path == "/health/ready":
            return httpx.Response(200, json={"status": "ready"})
        if path.endswith("/auth/login"):
            return httpx.Response(200, headers=[("set-cookie", "repolens_session=session; Path=/; HttpOnly"),
                ("set-cookie", "repolens_csrf=csrf; Path=/")], json={"id": "user-1"})
        if path.endswith("/scans") and request.method == "POST":
            return httpx.Response(202, json={"id": "scan-1"})
        if path.endswith("/scans/scan-1"):
            return httpx.Response(200, json={"id": "scan-1", "status": "COMPLETED", "commit_sha": "a" * 40})
        if path.endswith("/scans/scan-1/reports"):
            return httpx.Response(202, json={"id": "report-1", "status": "READY"})
        if path.endswith("/change-analyses/from-pr"):
            return httpx.Response(202, json={"id": "analysis-1"})
        if path.endswith("/change-analyses/analysis-1"):
            return httpx.Response(200, json={"id": "analysis-1", "status": "COMPLETED"})
        if path.endswith("/scans/scan-1/findings"):
            return httpx.Response(200, json=[{"id": "finding-1"}])
        if path.endswith("/findings/finding-1/patch"):
            return httpx.Response(202, json={"job_id": "job-1", "state": "QUEUED",
                "status_url": "/api/v1/jobs/job-1", "result_url": "/api/v1/jobs/job-1/result",
                "reused": False})
        if path.endswith("/jobs/job-1/result"):
            return httpx.Response(200, json={"proposal": {"id": "patch-1"}})
        if path.endswith("/jobs/job-1"):
            return httpx.Response(200, json={"id": "job-1", "state": "SUCCEEDED"})
        if path.endswith("/patches/patch-1/approve"):
            return httpx.Response(200, json={"id": "patch-1", "status": "APPROVED"})
        if path.endswith("/patches/patch-1/delivery-preview"):
            return httpx.Response(200, json={"eligible": True})
        if path.endswith("/review-publication/preview"):
            return httpx.Response(200, json={"status": "PREVIEWED", "review_event": "COMMENT",
                                             "preview_digest": "digest"})
        return httpx.Response(500, json={"unexpected": path})

    smoke = StagingSmoke("https://staging.invalid", "operator@example.com", "long-password")
    smoke.client.close()
    smoke.client = httpx.Client(base_url="https://staging.invalid", transport=httpx.MockTransport(handler))
    try:
        result = smoke.run(repository_url="https://github.com/example/repo",
                           pr_url="https://github.com/example/repo/pull/1")
    finally:
        smoke.client.close()
    assert result["write_boundary"]["review_event"] == "COMMENT"
    assert not any(path.endswith(("/deliver", "/publish", "/review-publication/approve")) for _, path in calls)


def test_external_smoke_requires_environment_interlock(monkeypatch):
    monkeypatch.delenv("REPOLENS_SMOKE_ALLOW_EXTERNAL_WRITES", raising=False)
    try:
        StagingSmoke("https://staging.invalid", "operator@example.com", "long-password",
                     allow_external_writes=True)
    except ValueError as exc:
        assert "REPOLENS_SMOKE_ALLOW_EXTERNAL_WRITES" in str(exc)
    else:
        raise AssertionError("external smoke was enabled without the environment interlock")


def test_staging_smoke_rejects_malformed_origins_and_embedded_credentials():
    invalid = (
        "ftp://localhost:8000", "http://attacker.example",
        "https://user:password@staging.invalid", "https://staging.invalid/path",
        "https://staging.invalid/?debug=1", "https://staging.invalid/#fragment",
    )
    for origin in invalid:
        try:
            StagingSmoke(origin, "operator@example.com", "password")
        except ValueError:
            pass
        else:
            raise AssertionError(f"StagingSmoke accepted malformed origin {origin!r}")


def test_staging_smoke_rejects_timed_out_job_and_sanitizes_errors():
    smoke = StagingSmoke("https://staging.invalid", "operator@example.com", "password")
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jobs/123"):
            return httpx.Response(200, json={"state": "TIMED_OUT", "failure_code": "PRIVATE_TOKEN"})
        return httpx.Response(503, text="secret://hidden.internal/credential")
    smoke.client.close()
    smoke.client = httpx.Client(base_url="https://staging.invalid", transport=httpx.MockTransport(handler))
    try:
        try:
            smoke._wait("/api/v1/jobs/123", {"SUCCEEDED", "FAILED", "TIMED_OUT"}, stage="job")
        except RuntimeError as exc:
            assert "TIMED_OUT" in str(exc)
            assert "PRIVATE_TOKEN" not in str(exc)
        else:
            raise AssertionError("Timed out job accepted as successful")
        try:
            smoke._require(smoke.client.get("/internal"), {200}, "health")
        except RuntimeError as exc:
            assert "503" in str(exc)
            assert "secret://" not in str(exc)
        else:
            raise AssertionError("Invalid health response was accepted")
    finally:
        smoke.client.close()


def test_staging_smoke_requires_ready_before_authentication():
    calls = []
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(503, json={"status": "not_ready"})
    smoke = StagingSmoke("https://staging.invalid", "operator@example.com", "password")
    smoke.client.close()
    smoke.client = httpx.Client(base_url="https://staging.invalid", transport=httpx.MockTransport(handler))
    try:
        try:
            smoke.run(repository_url="https://github.com/example/repo", pr_url="https://github.com/example/repo/pull/1")
        except RuntimeError as exc:
            assert "readiness" in str(exc)
        else:
            raise AssertionError("Smoke attempted work while service was not ready")
        assert calls == ["/health/ready"]
    finally:
        smoke.client.close()
