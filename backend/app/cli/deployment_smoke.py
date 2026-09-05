"""Safe release smoke: deterministic sandbox by default, explicit staging HTTP mode."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from urllib.parse import urlparse
from uuid import uuid4

import httpx


SANDBOX_TESTS = (
    "tests/test_phase8_release_gate.py::test_phase8_comprehensive_release_gate",
    "tests/test_e2e_correctness_release_gate.py::test_repolens_end_to_end_correctness_acceptance_gate",
    "tests/test_pdf_reports.py::test_report_pipeline_is_deterministic_bounded_and_tenant_safe",
    "tests/test_phase5_github_delivery_release_gate.py::test_phase5_e2e_full_route_level_lifecycle_gate",
    "tests/test_phase7_release_gate.py::test_e2e_c_no_approval_blocks_publish",
)


def run_sandbox() -> int:
    """Exercise real application paths with existing network/write boundary fakes."""
    return subprocess.run([sys.executable, "-m", "pytest", *SANDBOX_TESTS, "-q", "--tb=short"],
                          check=False).returncode


class StagingSmoke:
    def __init__(self, base_url: str, email: str, password: str, *, timeout_seconds: int = 600,
                 allow_external_writes: bool = False):
        parsed = urlparse(base_url)
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise ValueError("staging smoke requires HTTPS except on loopback")
        if allow_external_writes and os.environ.get("REPOLENS_SMOKE_ALLOW_EXTERNAL_WRITES") != "1":
            raise ValueError("external writes require REPOLENS_SMOKE_ALLOW_EXTERNAL_WRITES=1")
        self.client = httpx.Client(base_url=base_url.rstrip("/"), timeout=30, follow_redirects=False)
        self.email, self.password = email, password
        self.timeout_seconds = timeout_seconds
        self.allow_external_writes = allow_external_writes

    def _csrf_headers(self) -> dict[str, str]:
        token = self.client.cookies.get("repolens_csrf")
        if not token:
            raise RuntimeError("login did not establish the CSRF cookie")
        return {"X-CSRF-Token": token}

    @staticmethod
    def _require(response: httpx.Response, allowed: set[int], stage: str) -> dict:
        if response.status_code not in allowed:
            raise RuntimeError(f"{stage} failed with HTTP {response.status_code}: {response.text[:500]}")
        if not response.content:
            return {}
        value = response.json()
        if not isinstance(value, dict):
            raise RuntimeError(f"{stage} returned a non-object response")
        return value

    def _wait(self, path: str, terminal: set[str], *, stage: str) -> dict:
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            value = self._require(self.client.get(path), {200}, stage)
            state = str(value.get("status") or value.get("state") or "").upper()
            if state in terminal:
                if state in {"FAILED", "CANCELLED", "REJECTED"}:
                    raise RuntimeError(f"{stage} terminalized as {state}: {value.get('failure_code')}")
                return value
            time.sleep(2)
        raise RuntimeError(f"{stage} exceeded {self.timeout_seconds}s")

    def run(self, *, repository_url: str, pr_url: str, register: bool = False,
            finding_id: str | None = None) -> dict:
        result: dict = {"mode": "STAGING", "external_writes": self.allow_external_writes}
        if register:
            registration = self.client.post("/api/v1/auth/register",
                json={"email": self.email, "password": self.password})
            self._require(registration, {201, 409}, "register")
            result["register"] = registration.status_code
        login = self._require(self.client.post("/api/v1/auth/login",
            json={"email": self.email, "password": self.password}), {200}, "login")
        result["login"] = login.get("id")
        headers = self._csrf_headers()
        scan = self._require(self.client.post("/api/v1/scans", headers=headers,
            json={"repository_url": repository_url}), {202}, "submit repository")
        scan = self._wait(f"/api/v1/scans/{scan['id']}", {"COMPLETED", "FAILED", "CANCELLED"}, stage="scan")
        result["scan"] = {"id": scan["id"], "status": scan["status"], "commit": scan.get("commit_sha") or scan.get("commit_hash")}
        report = self._require(self.client.post(f"/api/v1/scans/{scan['id']}/reports", headers={**headers,
            "Idempotency-Key": f"smoke-report-{scan['id']}"}), {200, 202}, "report")
        if report.get("status") not in {"READY", "FAILED"}:
            report = self._wait(f"/api/v1/reports/{report['id']}", {"READY", "FAILED"}, stage="report")
        result["report"] = {"id": report["id"], "status": report["status"]}
        analysis = self._require(self.client.post("/api/v1/change-analyses/from-pr", headers={**headers,
            "Idempotency-Key": "smoke-pr-" + uuid4().hex}, json={"pr_url": pr_url}), {202}, "PR analysis")
        analysis = self._wait(f"/api/v1/change-analyses/{analysis['id']}",
            {"COMPLETED", "FAILED", "CANCELLED"}, stage="PR analysis")
        result["change_analysis"] = {"id": analysis["id"], "status": analysis["status"]}
        if finding_id is None:
            findings = self.client.get(f"/api/v1/scans/{scan['id']}/findings")
            if findings.status_code != 200 or not isinstance(findings.json(), list) or not findings.json():
                raise RuntimeError("smoke scan produced no finding eligible for remediation; pass --finding-id")
            finding_id = findings.json()[0]["id"]
        remediation_response = self.client.post(f"/api/v1/findings/{finding_id}/patch", headers=headers)
        remediation = self._require(remediation_response, {200, 202}, "remediation")
        if remediation_response.status_code == 202:
            status_url = remediation.get("status_url")
            result_url = remediation.get("result_url")
            if not status_url or not result_url:
                raise RuntimeError("queued remediation did not expose job resources")
            self._wait(status_url, {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT"},
                       stage="remediation job")
            remediation = self._require(self.client.get(result_url), {200}, "remediation result")
        proposal = remediation.get("proposal", remediation)
        patch_id = proposal.get("id")
        if not patch_id:
            raise RuntimeError("remediation did not return a patch proposal")
        approved = self._require(self.client.post(f"/api/v1/patches/{patch_id}/approve", headers=headers,
            json={"approved_by": "staging-smoke", "notes": "Explicit staging smoke authorization"}), {200}, "approval")
        result["remediation"] = {"patch_id": patch_id, "status": approved["status"]}
        delivery = self._require(self.client.get(f"/api/v1/patches/{patch_id}/delivery-preview"), {200}, "delivery preview")
        publication = self._require(self.client.post(
            f"/api/v1/change-analyses/{analysis['id']}/review-publication/preview", headers=headers), {200}, "publication preview")
        result["write_boundary"] = {"delivery_eligible": delivery.get("eligible"),
            "publication_status": publication.get("status"), "review_event": publication.get("review_event")}
        if self.allow_external_writes:
            delivered = self._require(self.client.post(f"/api/v1/patches/{patch_id}/deliver", headers=headers,
                json={"requested_by": "staging-smoke", "notes": "Explicit external smoke"}), {200, 202}, "delivery")
            digest = publication["preview_digest"]
            self._require(self.client.post(f"/api/v1/change-analyses/{analysis['id']}/review-publication/approve",
                headers=headers, json={"expected_preview_digest": digest}), {200}, "publication approval")
            published = self._require(self.client.post(
                f"/api/v1/change-analyses/{analysis['id']}/review-publication/publish", headers=headers,
                json={"expected_preview_digest": digest}), {200, 202}, "publication")
            result["external"] = {"delivery_status": delivered.get("status"),
                                  "publication_status": published.get("status")}
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="RepoLens deployment smoke")
    parser.add_argument("mode", nargs="?", choices=("sandbox", "staging"), default="sandbox")
    parser.add_argument("--base-url", default=os.environ.get("REPOLENS_SMOKE_BASE_URL", ""))
    parser.add_argument("--email", default=os.environ.get("REPOLENS_SMOKE_EMAIL", ""))
    parser.add_argument("--repository-url", default=os.environ.get("REPOLENS_SMOKE_REPOSITORY_URL", ""))
    parser.add_argument("--pr-url", default=os.environ.get("REPOLENS_SMOKE_PR_URL", ""))
    parser.add_argument("--finding-id")
    parser.add_argument("--register", action="store_true")
    parser.add_argument("--allow-external-writes", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    if args.mode == "sandbox":
        return run_sandbox()
    password = os.environ.get("REPOLENS_SMOKE_PASSWORD", "")
    required = {"base URL": args.base_url, "email": args.email, "REPOLENS_SMOKE_PASSWORD": password,
                "repository URL": args.repository_url, "PR URL": args.pr_url}
    missing = [name for name, value in required.items() if not value]
    if missing:
        parser.error("staging mode requires " + ", ".join(missing))
    runner = StagingSmoke(args.base_url, args.email, password, timeout_seconds=args.timeout,
                          allow_external_writes=args.allow_external_writes)
    try:
        print(json.dumps(runner.run(repository_url=args.repository_url, pr_url=args.pr_url,
            register=args.register, finding_id=args.finding_id), indent=2, sort_keys=True))
    finally:
        runner.client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
