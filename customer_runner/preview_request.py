"""Send a same-repository PR event from a pinned, read-only GitHub workflow."""

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    env = os.environ
    origin = env["V2_PREVIEW_API_ORIGIN"]
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("A pinned HTTPS API origin is required.")
    workspace, project = (UUID(env[field]) for field in ("V2_PREVIEW_WORKSPACE_ID", "V2_PREVIEW_PROJECT_ID"))
    address = f"{origin}/api/automation-preview/{workspace}/{project}"
    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    head = event["pull_request"]["head"]
    if env["GITHUB_EVENT_NAME"] != "pull_request" or head["repo"]["id"] != event["repository"]["id"]:
        raise ValueError("Only same-repository pull requests may report previews.")
    payload = json.dumps({"pull_request": event["number"], "event": event["action"], "head_sha": head["sha"],
                          "head_repository_id": head["repo"]["id"]}, sort_keys=True).encode()
    token_url = env["ACTIONS_ID_TOKEN_REQUEST_URL"]
    if urlsplit(token_url).scheme != "https":
        raise ValueError("GitHub OIDC requires HTTPS.")
    join = "&" if "?" in token_url else "?"
    oauth = Request(token_url + join + "audience=" + quote(address, safe=""),
                    headers={"Authorization": "Bearer " + env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    opener = build_opener(NoRedirect())
    with opener.open(oauth, timeout=20) as response:
        token = json.loads(response.read(32768))["value"]
    key = hashlib.sha256(f"{env['GITHUB_RUN_ID']}:{env['GITHUB_RUN_ATTEMPT']}".encode() + payload).hexdigest()
    callback = Request(address, data=payload, method="POST", headers={"Content-Type": "application/json",
        "Authorization": "Bearer " + token, "Idempotency-Key": key})
    with opener.open(callback, timeout=20) as response:
        result = json.loads(response.read(65536))
    if result.get("status") not in {"requested", "cleanup_requested"}:
        raise RuntimeError("Unexpected preview receipt.")
    print("V2 recorded the approved-scope preview lifecycle request.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("V2 did not accept the preview lifecycle event.") from None
