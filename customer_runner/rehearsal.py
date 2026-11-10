"""Read approved artifacts inside the customer runner; never perform apply."""
from datetime import datetime, timezone
from email.utils import format_datetime
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, build_opener
from uuid import UUID
from backend.contracts import golden_customer_plan as golden
from customer_runner import preflight, plan as planner
from customer_runner.preflight import PreflightError

MODE = "read-only-rehearsal"
LIMIT = 32 * 1024 * 1024


def child_environment(environ, root):
    allowed = {"PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG", "LC_ALL"}
    child = {key: value for key, value in environ.items() if key in allowed}
    child.update({"TF_IN_AUTOMATION": "true", "TF_CLI_CONFIG_FILE": str(root / "empty.tfrc"), "AZURE_CONFIG_DIR": str(root / "empty-azure")})
    return child


def download(manifest, artifact, access):
    p = manifest["input"]
    if not re.fullmatch(r"[a-z][a-z0-9]{2,23}", p["storage_account"]) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", p["plans_container"]): raise PreflightError("ARTIFACT_MISMATCH")
    if not re.fullmatch(r"plans/[0-9a-f-]{36}/(?:what-if|saved-plan|bundle|image-provenance)-[0-9a-f]{64}", artifact["blob_name"]): raise PreflightError("ARTIFACT_MISMATCH")
    if type(artifact["size_bytes"]) is not int or not 0 < artifact["size_bytes"] <= LIMIT: raise PreflightError("ARTIFACT_MISMATCH")
    url = f"https://{p['storage_account']}.blob.core.windows.net/{p['plans_container']}/{artifact['blob_name']}?versionid={quote(artifact['version_id'], safe='')}"
    headers = {"Authorization": "Bearer " + access, "x-ms-version": "2023-11-03", "If-Match": artifact["etag"],
        "x-ms-date": format_datetime(datetime.now(timezone.utc), usegmt=True)}
    try:
        with build_opener(preflight.NoRedirect()).open(Request(url, headers=headers, method="GET"), timeout=30) as response:
            if response.status != 200 or response.headers.get("ETag") != artifact["etag"] or response.headers.get("x-ms-version-id") != artifact["version_id"] or response.headers.get("x-ms-server-encrypted", "").lower() != "true" or int(response.headers.get("Content-Length", "0")) != artifact["size_bytes"]:
                raise PreflightError("ARTIFACT_MISMATCH")
            raw = response.read(LIMIT + 1)
        if len(raw) != artifact["size_bytes"] or golden.sha(raw) != artifact["sha256"]: raise PreflightError("ARTIFACT_MISMATCH")
        return raw
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        raise PreflightError("ARTIFACT_MISMATCH") from None


def inspect_plan(shown):
    try:
        config = shown["configuration"]
        module = config["root_module"]
        resources = module["resources"]
        if set(config["provider_config"]) != {"azurerm"} or module.get("module_calls") or len(resources) != 1 or resources[0].get("address") != "azurerm_linux_web_app.app": raise ValueError()
        def visit(value):
            if isinstance(value, dict):
                if any(value.get(key) for key in ("provisioners", "provisioner", "module_calls")): raise ValueError()
                for child in value.values(): visit(child)
            elif isinstance(value, list):
                for child in value: visit(child)
        visit(config)
    except (KeyError, TypeError, ValueError):
        raise PreflightError("PLAN_REJECTED") from None


def check(proofs, trusted, *, environ=os.environ, issue=preflight.oidc, request=preflight.request_json,
          execute=planner.command, fetch=download, checkpoint=lambda: None):
    r = proofs["request"]["payload"]
    m, report = proofs["plan_manifest"], proofs["plan_report"]
    with tempfile.TemporaryDirectory(prefix="v2-rehearsal-") as folder:
        root = Path(folder); root.chmod(0o700)
        child = child_environment(environ, root)
        (root / "empty.tfrc").write_text("", encoding="utf-8")
        proof_path, key_path = root / "proofs.json", root / "trusted.json"
        proof_path.write_bytes(golden.encode(proofs)); key_path.write_bytes(golden.encode(trusted))
        proof_path.chmod(0o600); key_path.chmod(0o600)
        try:
            verified = execute(["node", str(Path(__file__).with_name("verify_rehearsal.mjs")), str(proof_path), str(key_path)], folder, child)
            if verified.strip() != b"verified": raise PreflightError("TRUST_REJECTED")
        except PreflightError as error:
            raise PreflightError("TOOLS_UNAVAILABLE" if error.code == "TOOLS_UNAVAILABLE" else "TRUST_REJECTED") from None
        checkpoint()
        reader = {**m, "client_id": r["reader_client_id"], "principal_id": r["reader_principal_id"]}
        checks = preflight.azure_checks(reader, request=request, oidc_request=issue)
        if checks["outcome"] != "passed": raise PreflightError("FEDERATION_REJECTED")
        adapted = {**m, "input": {**m["input"], "planning_client_id": r["reader_client_id"], "planning_principal_id": r["reader_principal_id"]}}
        try:
            access = planner.exchange(adapted, "https://storage.azure.com/.default", issue, request)
        except PreflightError:
            raise PreflightError("FEDERATION_REJECTED") from None
        artifacts = report["artifacts"]
        if set(artifacts) != {"what-if", "saved-plan", "bundle", "image-provenance"} or golden.sha(golden.encode(artifacts)) != r["artifact_set_sha256"]:
            raise PreflightError("ARTIFACT_MISMATCH")
        blobs = {}
        for kind, artifact in artifacts.items():
            if artifact["blob_name"] != f"plans/{m['plan_id']}/{kind}-{artifact['sha256']}": raise PreflightError("ARTIFACT_MISMATCH")
            raw = fetch(m, artifact, access)
            if len(raw) != artifact["size_bytes"] or golden.sha(raw) != artifact["sha256"]: raise PreflightError("ARTIFACT_MISMATCH")
            blobs[kind] = raw
        expected_bundle = golden.bundle(m, planner.LOCK.read_bytes())
        if blobs["bundle"] != expected_bundle or golden.sha(expected_bundle) != m["bundle_sha256"]:
            raise PreflightError("ARTIFACT_MISMATCH")
        for name, text in json.loads(expected_bundle)["files"].items():
            target = root / name; target.write_text(text, encoding="utf-8"); target.chmod(0o600)
        saved = root / "saved.tfplan"; saved.write_bytes(blobs["saved-plan"]); saved.chmod(0o600)
        checkpoint()
        try:
            if json.loads(execute(["tofu", "version", "-json"], folder, child)).get("terraform_version") != golden.ENGINE_VERSION:
                raise PreflightError("TOOLS_UNAVAILABLE")
            execute(["tofu", "init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"], folder, child)
            shown = json.loads(execute(["tofu", "show", "-json", "-plan=saved.tfplan"], folder, child))
            inspect_plan(shown)
            golden.summarize(json.loads(blobs["what-if"]), shown, m)
        except PreflightError as error:
            raise PreflightError("TOOLS_UNAVAILABLE" if error.code == "TOOLS_UNAVAILABLE" else "PLAN_REJECTED") from None
        except (ValueError, KeyError, TypeError):
            raise PreflightError("PLAN_REJECTED") from None
        checkpoint()
    return {"outcome": "verified", "no_apply": True, "artifact_set_sha256": r["artifact_set_sha256"]}


def run(environ=os.environ, *, request=preflight.request_json, issue=None, inspect=check):
    issue = issue or (lambda aud: preflight.oidc(aud, environ, request))
    origin = environ.get("V2_API_ORIGIN", "")
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port not in {None, 443}:
        raise PreflightError("TRUST_REJECTED")
    tenant, identifier = str(UUID(environ["V2_WORKSPACE_ID"])), str(UUID(environ["V2_REHEARSAL_ID"]))
    expected = environ.get("V2_REQUEST_SHA256", "")
    keys_raw = environ.get("V2_TRUSTED_PUBLIC_KEYS", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or not 1 <= len(keys_raw) <= 8192: raise PreflightError("TRUST_REJECTED")
    trusted = json.loads(keys_raw)
    if not isinstance(trusted, dict) or not 1 <= len(trusted) <= 8: raise PreflightError("TRUST_REJECTED")
    base = f"{origin}/api/customer-rehearsals/{tenant}/{identifier}"
    token = issue(base + "/start"); metadata = preflight.token_metadata(token)
    identity = f"{identifier}:{metadata.get('run_id')}:{metadata.get('run_attempt')}"
    def send(operation, body, assertion):
        return request(base + "/" + operation, method="POST", token=assertion, body=body,
            idempotency_key=golden.sha((identity + ":" + operation).encode()))
    started = send("start", {"request_sha256": expected}, token)
    envelope = started.get("request", {}); p = envelope.get("payload", {})
    if started.get("mode") != MODE or started.get("azure_writes") is not False or started.get("execution") != "unavailable" or started.get("status") != "authenticated" or envelope.get("sha256") != expected or golden.sha(golden.encode(p)) != expected or p.get("mode") != MODE or p.get("azure_writes") is not False:
        raise PreflightError("TRUST_REJECTED")
    workflow = p.get("rehearsal_workflow_ref", "")
    expected_metadata = {"repository": p.get("repository"), "repository_id": p.get("repository_id"), "repository_owner_id": p.get("repository_owner_id"),
        "sha": p.get("source_sha"), "sub": p.get("oidc_subject"), "environment": p.get("environment"), "job_workflow_ref": workflow}
    if p.get("tenant_id") != tenant or p.get("rehearsal_id") != identifier or p.get("api_origin") != origin or p.get("trusted_keys_sha256") != golden.sha(golden.encode(trusted)) or any(metadata.get(k) != v for k, v in expected_metadata.items()) or started.get("run_id") != metadata.get("run_id") or started.get("run_attempt") != metadata.get("run_attempt") or environ.get("V2_JOB_WORKFLOW_SHA") != workflow.rsplit("@", 1)[-1] or environ.get("V2_JOB_WORKFLOW_REPOSITORY") != workflow.split("/.github/workflows/")[0]:
        raise PreflightError("TRUST_REJECTED")
    supplied = started.get("proofs", {})
    if not isinstance(supplied, dict) or set(supplied) != {"plan_manifest", "plan_report", "approval_challenge", "decision", "evidence"}:
        raise PreflightError("TRUST_REJECTED")
    proof = {**supplied, "request": envelope}
    count = 0
    def checkpoint():
        nonlocal count
        # One callback receipt per checkpoint, with a distinct request key.
        count += 1
        assertion = issue(base + "/checkpoint")
        ack = request(base + "/checkpoint", method="POST", token=assertion, body={"request_sha256": expected},
            idempotency_key=golden.sha((identity + ":checkpoint:" + str(count)).encode()))
        if ack.get("status") != "continue-read-only" or ack.get("mode") != MODE or ack.get("azure_writes") is not False or ack.get("execution") != "unavailable":
            raise PreflightError("API_UNAVAILABLE")
    try:
        result = inspect(proof, trusted, environ=environ, request=request, issue=issue, checkpoint=checkpoint)
    except PreflightError as error:
        allowed = {"TRUST_REJECTED", "FEDERATION_REJECTED", "ARTIFACT_MISMATCH", "PLAN_REJECTED", "TOOLS_UNAVAILABLE", "API_UNAVAILABLE"}
        code = error.code if error.code in allowed else "API_UNAVAILABLE"
        result = {"outcome": "unavailable" if code in {"TOOLS_UNAVAILABLE", "API_UNAVAILABLE"} else "failed", "failure_code": code, "no_apply": True}
    result["request_sha256"] = expected
    ack = send("report", result, issue(base + "/report"))
    if ack.get("mode") != MODE or ack.get("azure_writes") is not False or ack.get("execution") != "unavailable": raise PreflightError("TRUST_REJECTED")
    return result["outcome"] == "verified"


if __name__ == "__main__":
    try:
        ok = run()
        print("V2 read-only artifact checks reported. No apply occurred; release health is unverified.")
        sys.exit(0 if ok else 1)
    except Exception:
        print("V2 execution rehearsal unavailable. No apply was authorized.", file=sys.stderr)
        sys.exit(1)
