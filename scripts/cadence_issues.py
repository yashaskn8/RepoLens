"""Issue-only automation for monitored regressions and annual planning.

No code generation, deployment, auto-approval or merging is performed.
Uses a short-lived workflow token with job-scoped issues:write permission.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def api(method: str, url: str, token: str, body: dict | None = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(
        url,
        method=method,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "RepoLens-quality-cadence",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read())
    except (HTTPError, URLError) as exc:
        # Do not print HTTP response bodies or authorization headers.
        raise RuntimeError(f"GitHub issue API request failed: {type(exc).__name__}") from None


def exists(base: str, token: str, title: str, *, state: str) -> bool:
    # Bounded deterministic pagination; fail closed if enumeration is incomplete.
    for page in range(1, 21):
        issues = api("GET", f"{base}/issues?state={state}&per_page=100&page={page}", token)
        if not isinstance(issues, list):
            raise RuntimeError("Unexpected GitHub issue API response.")
        if any(item.get("title") == title for item in issues):
            return True
        if len(issues) < 100:
            return False
    raise RuntimeError("Too many issues to verify deduplication safely.")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"annual", "hourly-failure"}:
        raise SystemExit("Expected annual or hourly-failure mode.")
    token = os.getenv("GH_ISSUE_TOKEN", "")
    repository = os.getenv("GH_ISSUE_REPOSITORY", "")
    run_id = os.getenv("GH_ISSUE_RUN_ID", "")
    sha = os.getenv("GH_ISSUE_SHA", "")
    if not token or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise RuntimeError("Missing GitHub issue authorization or invalid repository.")
    if not run_id.isdigit() or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("Missing validated workflow provenance.")

    mode = sys.argv[1]
    year = datetime.now(timezone.utc).year
    if mode == "annual":
        title = f"[RepoLens annual feature tournament] {year}"
        state = "all"
        body = (
            f"Annual human-reviewed feature discovery for {year}.\n\n"
            "1. Refresh the 100-candidate inventory against current official sources: "
            f"https://github.com/{repository}/blob/main/docs/FEATURE_TOURNAMENT.md\n"
            "2. Identify already shipped capabilities and remove duplicates.\n"
            "3. Conduct separate engineering, security, operations, and UX reviews; "
            "record contrary evidence, alternatives, and measurable acceptance criteria.\n"
            "4. Compare at least three architectures and run security and regression gates.\n"
            "5. Build the winner on a new isolated branch and request human PR review. "
            "Never auto-merge or deploy.\n\n"
            f"Scheduled workflow: https://github.com/{repository}/actions/runs/{run_id}\n"
        )
    else:
        title = "[RepoLens hourly quality] Regression detected"
        state = "open"
        body = (
            "The focused SARIF regression gate failed. Investigation required.\n\n"
            f"- Failed workflow: https://github.com/{repository}/actions/runs/{run_id}\n"
            f"- Tested commit: {sha}\n"
            "- Reproduce by running the focused SARIF pytest module in backend.\n"
            "- Identify root cause, add a regression test, propose a reviewed fix PR.\n"
            "- Close this issue only after verified recovery. No automated patch or deploy occurs.\n"
        )

    base = f"https://api.github.com/repos/{repository}"
    if exists(base, token, title, state=state):
        print("Matching issue already exists; no duplicate created.")
        return 0
    issue = api("POST", f"{base}/issues", token, {"title": title, "body": body})
    print(f"Created issue: {issue.get('html_url', '(URL unavailable)')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
