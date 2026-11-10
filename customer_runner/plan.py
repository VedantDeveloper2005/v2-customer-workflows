"""Create a golden plan inside the customer runner. Never apply or log payloads.

Only Python stdlib, Azure CLI and a pinned OpenTofu binary are used. The
customer application is never checked out. Sensitive artifacts remain in
customer-owned, private, versioned Blob Storage; V2 receives metadata only.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, build_opener
from uuid import UUID
from backend.contracts import golden_customer_plan as golden
from customer_runner import image_evidence
from customer_runner.preflight import (ARM, AZURE_AUDIENCE, NoRedirect, PreflightError,
    oidc, request_json, token_metadata)

LIMIT = 32 * 1024 * 1024
LOCK = Path(__file__).resolve().parents[1] / "backend" / "contracts" / "customer_plan.lock.hcl"


def command(args, cwd, environ, *, timeout=240):
    """Capture every byte privately; never echo commands, stderr or credentials."""
    try:
        # Temporary files bound memory use and avoid inherited stdout/stderr.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            completed = subprocess.run(args, cwd=cwd, env=environ, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, timeout=timeout, check=False)
            if completed.returncode != 0: raise PreflightError("PLAN_FAILED")
            out.seek(0); raw = out.read(LIMIT + 1)
            if len(raw) > LIMIT: raise PreflightError("PLAN_FAILED")
            return raw
    except FileNotFoundError:
        raise PreflightError("TOOLS_UNAVAILABLE") from None
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightError("PLAN_FAILED") from None


def exchange(manifest, scope, issue, request):
    p = manifest["input"]
    value = request(f"https://login.microsoftonline.com/{manifest['azure_tenant_id']}/oauth2/v2.0/token", method="POST", form={
        "client_id": p["planning_client_id"], "grant_type": "client_credentials", "scope": scope,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": issue(AZURE_AUDIENCE)})
    token = value.get("access_token")
    if not isinstance(token, str) or not 32 <= len(token) <= 32768 or value.get("token_type", "").casefold() != "bearer": raise PreflightError("IDENTITY_MISMATCH")
    claims = token_metadata(token)
    if claims.get("tid") != manifest["azure_tenant_id"] or claims.get("oid") != p["planning_principal_id"] or claims.get("appid", claims.get("azp")) != p["planning_client_id"] or type(claims.get("exp")) is not int or claims["exp"] <= time.time() + 60:
        raise PreflightError("IDENTITY_MISMATCH")
    return token


def prerequisites(manifest, access, request):
    ids, p = golden.resource_ids(manifest), manifest["input"]
    def get(kind, version):
        value = request(ARM + ids[kind] + "?api-version=" + version, token=access)
        if value.get("id", "").casefold() != ids[kind].casefold(): raise PreflightError("AZURE_UNAVAILABLE")
        return value
    plan = get("service_plan", "2023-12-01")
    # Always-on requires a paid, Linux service plan; no new plan/SKU is created.
    if plan.get("properties", {}).get("reserved") is not True or str(plan.get("sku", {}).get("tier", "")).casefold() in {"", "free", "shared"} or plan.get("location", "").replace(" ", "").casefold() != p["location"]:
        raise PreflightError("PLAN_REJECTED")
    identity = get("identity", "2023-01-31")
    if identity.get("properties", {}).get("clientId") != p["runtime_client_id"]: raise PreflightError("IDENTITY_MISMATCH")
    registry = get("registry", "2023-07-01")
    if registry.get("properties", {}).get("loginServer") != p["registry_name"] + ".azurecr.io" or registry.get("properties", {}).get("adminUserEnabled") is not False:
        raise PreflightError("PLAN_REJECTED")
    storage = get("storage", "2023-05-01")
    props = storage.get("properties", {})
    if props.get("allowBlobPublicAccess") is not False or props.get("supportsHttpsTrafficOnly") is not True or props.get("minimumTlsVersion") not in {"TLS1_2", "TLS1_3"} or props.get("allowSharedKeyAccess") is not False:
        raise PreflightError("STORAGE_REJECTED")
    service = request(ARM + ids["storage"] + "/blobServices/default?api-version=2023-05-01", token=access)
    if service.get("properties", {}).get("isVersioningEnabled") is not True: raise PreflightError("STORAGE_REJECTED")
    for name in (p["state_container"], p["plans_container"]):
        container = request(ARM + ids["storage"] + "/blobServices/default/containers/" + name + "?api-version=2023-05-01", token=access)
        if container.get("properties", {}).get("publicAccess") not in {None, "None"}: raise PreflightError("STORAGE_REJECTED")
    sku, capacity = plan.get("sku", {}).get("name"), plan.get("sku", {}).get("capacity")
    if not isinstance(sku, str) or not re.fullmatch(r"(?:B[1-3]|S[1-3]|P[1-3]v[2-4])", sku) or type(capacity) is not int or not 1 <= capacity <= 30:
        return None
    return {"service_plan_id": ids["service_plan"], "sku": sku, "instances": capacity,
        "location": p["location"], "captured_at": datetime.now(timezone.utc).isoformat()}


def upload(manifest, kind, raw, access):
    if not 0 < len(raw) <= LIMIT: raise PreflightError("STORAGE_REJECTED")
    p = manifest["input"]
    digest = golden.sha(raw)
    name = f"plans/{manifest['plan_id']}/{kind}-{digest}"
    url = f"https://{p['storage_account']}.blob.core.windows.net/{p['plans_container']}/{name}"
    headers = {"Authorization": "Bearer " + access, "x-ms-version": "2023-11-03", "x-ms-blob-type": "BlockBlob",
        "Content-Type": "application/octet-stream", "If-None-Match": "*", "x-ms-blob-content-disposition": "attachment"}
    try:
        with build_opener(NoRedirect()).open(Request(url, data=raw, headers=headers, method="PUT"), timeout=60) as response:
            version, etag = response.headers.get("x-ms-version-id", ""), response.headers.get("ETag", "")
            if response.status != 201 or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,24}Z", version) or not re.fullmatch(r'"0x[0-9A-Fa-f]{8,32}"', etag) or response.headers.get("x-ms-request-server-encrypted", "").casefold() != "true":
                raise PreflightError("STORAGE_REJECTED")
    except (HTTPError, URLError, OSError, TimeoutError):
        raise PreflightError("STORAGE_REJECTED") from None
    return {"sha256": digest, "size_bytes": len(raw), "blob_name": name, "version_id": version, "etag": etag}


def produce(manifest, *, environ=os.environ, issue=oidc, request=request_json, execute=command, store=upload):
    expected_bundle = golden.bundle(manifest, LOCK.read_bytes())
    if golden.sha(expected_bundle) != manifest["bundle_sha256"] or golden.POLICY_VERSION != manifest["policy_version"] or golden.sha(LOCK.read_bytes()) != manifest["lock_sha256"]:
        raise PreflightError("PLAN_REJECTED")
    access = exchange(manifest, ARM + "/.default", issue, request)
    hosting = prerequisites(manifest, access, request)
    with tempfile.TemporaryDirectory(prefix="v2-plan-") as folder:
        root = Path(folder); root.chmod(0o700)
        for name, content in json.loads(expected_bundle)["files"].items():
            (root / name).write_text(content, encoding="utf-8"); (root / name).chmod(0o600)
        child = dict(environ)
        gh_token = child.pop("V2_GH_TOKEN", "")
        gh_ready = child.pop("V2_GH_VERIFIER_READY", "")
        # Disable user CLI configuration, credentials, logging, argument hooks,
        # provider overrides and cloud credentials inherited from the host.
        for name in list(child):
            if name.startswith(("ARM_", "AZURE_", "TF_", "TOFU_", "GH_", "ACTIONS_ID_TOKEN_")) or name == "GITHUB_TOKEN": child.pop(name)
        child.update({"AZURE_CONFIG_DIR": str(root / "azure"), "AZURE_CORE_ONLY_SHOW_ERRORS": "true", "AZURE_CORE_COLLECT_TELEMETRY": "false", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no", "ARM_USE_OIDC": "true", "ARM_USE_AZUREAD": "true",
            "ARM_CLIENT_ID": manifest["input"]["planning_client_id"], "ARM_TENANT_ID": manifest["azure_tenant_id"], "ARM_SUBSCRIPTION_ID": manifest["subscription_id"],
            "TF_IN_AUTOMATION": "true", "TF_CLI_CONFIG_FILE": str(root / "empty.tfrc")})
        (root / "empty.tfrc").write_text("", encoding="utf-8")
        if json.loads(execute(["tofu", "version", "-json"], folder, child)).get("terraform_version") != golden.ENGINE_VERSION: raise PreflightError("TOOLS_UNAVAILABLE")
        # 'az login --output json' is captured privately; it is never logged.
        assertion = issue(AZURE_AUDIENCE)
        execute(["az", "login", "--service-principal", "--username", child["ARM_CLIENT_ID"], "--tenant", child["ARM_TENANT_ID"], "--federated-token", assertion, "--output", "json"], folder, child)
        execute(["az", "account", "set", "--subscription", child["ARM_SUBSCRIPTION_ID"], "--output", "json"], folder, child)
        image, image_output = image_evidence.verify(manifest, folder, {**child, "V2_GH_TOKEN": gh_token, "V2_GH_VERIFIER_READY": gh_ready}, execute)
        what_if = execute(["az", "deployment", "group", "what-if", "--subscription", child["ARM_SUBSCRIPTION_ID"], "--resource-group", manifest["resource_group"],
            "--name", "v2-plan-" + manifest["plan_id"], "--template-file", "what-if.json", "--result-format", "FullResourcePayloads", "--no-pretty-print", "--output", "json"], folder, child)
        child["ARM_OIDC_TOKEN"] = issue(AZURE_AUDIENCE)
        execute(["tofu", "init", "-input=false", "-lockfile=readonly", "-no-color"], folder, child)
        child["ARM_OIDC_TOKEN"] = issue(AZURE_AUDIENCE)
        execute(["tofu", "plan", "-input=false", "-no-color", "-lock-timeout=30s", "-out=saved.tfplan"], folder, child)
        shown = execute(["tofu", "show", "-json", "saved.tfplan"], folder, child)
        try:
            summary = golden.summarize(json.loads(what_if), json.loads(shown), manifest)
        except (ValueError, KeyError, TypeError):
            raise PreflightError("PLAN_REJECTED") from None
        path = root / "saved.tfplan"
        if not path.is_file() or not 0 < path.stat().st_size <= LIMIT: raise PreflightError("PLAN_FAILED")
        saved = path.read_bytes()
        blob_access = exchange(manifest, "https://storage.azure.com/.default", issue, request)
        artifacts = {kind: store(manifest, kind, raw, blob_access) for kind, raw in
            (("what-if", what_if), ("saved-plan", saved), ("bundle", expected_bundle))}
        if image_output is not None:
            artifacts["image-provenance"] = store(manifest, "image-provenance", image_output, blob_access)
    return {"outcome": "reviewable", "artifacts": artifacts, "hosting": hosting, "image": image,
        "bundle_sha256": manifest["bundle_sha256"], **summary}


def run(environ=os.environ, *, request=request_json, issue=None, build=produce):
    issue = issue or (lambda aud: oidc(aud, environ, request))
    origin = environ.get("V2_API_ORIGIN", "")
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port not in {None, 443}: raise PreflightError("IDENTITY_MISMATCH")
    tenant, plan_id = str(UUID(environ["V2_WORKSPACE_ID"])), str(UUID(environ["V2_PLAN_ID"]))
    expected = environ.get("V2_REQUEST_SHA256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected): raise PreflightError("IDENTITY_MISMATCH")
    base = f"{origin}/api/customer-plans/{tenant}/{plan_id}"
    token = issue(base + "/start"); metadata = token_metadata(token)
    identity = f"{plan_id}:{metadata.get('run_id')}:{metadata.get('run_attempt')}"
    def send(operation, body, assertion):
        return request(base + "/" + operation, method="POST", token=assertion, body=body,
            idempotency_key=golden.sha((identity + ":" + operation).encode()))
    started = send("start", {"request_sha256": expected}, token)
    manifest = started.get("manifest")
    if not isinstance(manifest, dict) or golden.sha(golden.encode(manifest)) != expected or started.get("request_sha256") != expected or started.get("status") != "authenticated" or started.get("execution") != "unavailable": raise PreflightError("IDENTITY_MISMATCH")
    if manifest.get("workspace_id") != tenant or manifest.get("plan_id") != plan_id or manifest.get("api_origin") != origin or manifest.get("mode") not in {"app-service-create-plan", "app-service-update-plan"} or manifest.get("source_sha") != metadata.get("sha") or manifest.get("oidc_subject") != metadata.get("sub") or manifest.get("planning_workflow_ref") != metadata.get("job_workflow_ref") or manifest.get("input", {}).get("environment") != metadata.get("environment"):
        raise PreflightError("IDENTITY_MISMATCH")
    ref = manifest["planning_workflow_ref"]
    if environ.get("V2_JOB_WORKFLOW_SHA") != ref.rsplit("@", 1)[1] or environ.get("V2_JOB_WORKFLOW_REPOSITORY") != ref.split("/.github/workflows/")[0] or started.get("run_id") != metadata.get("run_id") or started.get("run_attempt") != metadata.get("run_attempt") or datetime.fromisoformat(manifest["expires_at"]) <= datetime.now(timezone.utc): raise PreflightError("IDENTITY_MISMATCH")
    try:
        report = build(manifest, environ=environ, issue=issue, request=request)
        report["execution_request_sha256"] = golden.execution_digest(expected, manifest["bundle_sha256"], report["artifacts"])
    except PreflightError as error:
        code = error.code if error.code in {"TOOLS_UNAVAILABLE", "IDENTITY_MISMATCH", "AZURE_UNAVAILABLE", "STORAGE_REJECTED", "PLAN_REJECTED", "PLAN_FAILED"} else "PLAN_FAILED"
        report = {"outcome": "unavailable" if code in {"TOOLS_UNAVAILABLE", "AZURE_UNAVAILABLE"} else "failed", "failure_code": code}
    report["request_sha256"] = expected
    acknowledgment = send("report", report, issue(base + "/report"))
    if acknowledgment.get("execution") != "unavailable": raise PreflightError("IDENTITY_MISMATCH")
    return report["outcome"] == "reviewable"


if __name__ == "__main__":
    try:
        ok = run()
        print("V2 planning report sent. Verify evidence before human approval; execution remains unavailable.")
        sys.exit(0 if ok else 1)
    except Exception:
        print("V2 exact planning unavailable. No execution was authorized.", file=sys.stderr)
        sys.exit(1)
