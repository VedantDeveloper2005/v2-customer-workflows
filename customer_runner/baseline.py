"""Observe an existing customer app; no apply, uploads or workload mutations."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlparse
from uuid import UUID
from backend.contracts import golden_customer_plan as golden
from customer_runner import preflight, plan as planner, rehearsal, image_evidence, release_health
from customer_runner.preflight import PreflightError

MODE = "read-only-baseline"


def observe(envelope, trusted, *, environ=os.environ, issue=preflight.oidc, request=preflight.request_json,
            execute=planner.command, checkpoint=lambda: None, health_observer=release_health.observe):
    m, p = envelope["payload"], envelope["payload"]["input"]
    with tempfile.TemporaryDirectory(prefix="v2-baseline-") as folder:
        root = Path(folder); root.chmod(0o700)
        child = rehearsal.child_environment(environ, root)
        (root / "empty.tfrc").write_text("", encoding="utf-8")
        proof, keys = root / "request.json", root / "trusted.json"
        proof.write_bytes(golden.encode(envelope)); keys.write_bytes(golden.encode(trusted))
        proof.chmod(0o600); keys.chmod(0o600)
        try:
            verified = execute(["node", str(Path(__file__).with_name("verify_baseline.mjs")), str(proof), str(keys)], folder, child)
            if verified.strip() != b"verified": raise PreflightError("TRUST_REJECTED")
        except PreflightError as error: raise PreflightError("TOOLS_UNAVAILABLE" if error.code == "TOOLS_UNAVAILABLE" else "TRUST_REJECTED") from None
        checkpoint()
        reader = {**m, "client_id": p["reader_client_id"], "principal_id": p["reader_principal_id"]}
        if preflight.azure_checks(reader, request=request, oidc_request=issue)["outcome"] != "passed": raise PreflightError("FEDERATION_REJECTED")
        adapted = {**m, "input": {**p, "planning_client_id": p["reader_client_id"], "planning_principal_id": p["reader_principal_id"]}}
        access = planner.exchange(adapted, preflight.ARM + "/.default", issue, request)
        # The observation identity must also be separate from the app's runtime
        # identities, including assignments that are invisible to the API.
        target = request(preflight.ARM + golden.app_resource_id(m) + "?api-version=2023-12-01", token=access)
        identity = target.get("identity", {})
        identities = list(identity.get("userAssignedIdentities", {}).values()) + [identity]
        if any(i.get("principalId", "").casefold() == p["reader_principal_id"].casefold() or i.get("clientId", "").casefold() == p["reader_client_id"].casefold() for i in identities): raise PreflightError("FEDERATION_REJECTED")
        child.update({"AZURE_CONFIG_DIR": str(root / "azure"), "AZURE_CORE_ONLY_SHOW_ERRORS": "true", "AZURE_CORE_COLLECT_TELEMETRY": "false", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no"})
        execute(["az", "login", "--service-principal", "--username", p["reader_client_id"], "--tenant", m["azure_tenant_id"], "--federated-token", issue(preflight.AZURE_AUDIENCE), "--output", "json"], folder, child)
        execute(["az", "account", "set", "--subscription", m["subscription_id"], "--output", "json"], folder, child)
        image, raw = image_evidence.verify({**m, "source_sha": p["image_source_sha"]}, folder,
            {**child, "V2_GH_TOKEN": environ.get("V2_GH_TOKEN", ""), "V2_GH_VERIFIER_READY": environ.get("V2_GH_VERIFIER_READY", "")}, execute)
        if image["status"] == "unavailable": raise PreflightError("TOOLS_UNAVAILABLE" if image.get("failure_code") == "TOOLS_UNAVAILABLE" else "API_UNAVAILABLE")
        if image["status"] != "verified" or not raw or golden.sha(raw) != image.get("output_sha256"): raise PreflightError("IMAGE_UNVERIFIED")
        checkpoint()
        result = health_observer(m, m["release_policy"]["contract"], p["image_sha256"], access, request=request,
            observation_id=m["health_observation_id"], checkpoint=checkpoint)
        if result["outcome"] != "verified":
            code = "HEALTH_FAILED" if result["outcome"] == "failed" else "HEALTH_UNAVAILABLE"
            return {"outcome": "failed" if code == "HEALTH_FAILED" else "unavailable", "failure_code": code, "no_apply": True}
        checkpoint()
        return {"outcome": "observed", "no_apply": True, "health": result, "image": image}


def run(environ=os.environ, *, request=preflight.request_json, issue=None, inspect=observe):
    issue = issue or (lambda audience: preflight.oidc(audience, environ, request))
    origin = environ.get("V2_API_ORIGIN", "")
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port not in {None, 443}: raise PreflightError("TRUST_REJECTED")
    tenant, identifier = str(UUID(environ["V2_WORKSPACE_ID"])), str(UUID(environ["V2_BASELINE_ID"]))
    expected, raw_keys = environ.get("V2_REQUEST_SHA256", ""), environ.get("V2_TRUSTED_PUBLIC_KEYS", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or not 1 <= len(raw_keys) <= 8192: raise PreflightError("TRUST_REJECTED")
    trusted = json.loads(raw_keys)
    if not isinstance(trusted, dict) or not 1 <= len(trusted) <= 8: raise PreflightError("TRUST_REJECTED")
    base = f"{origin}/api/customer-baselines/{tenant}/{identifier}"
    token = issue(base + "/start"); meta = preflight.token_metadata(token)
    identity = f"{identifier}:{meta.get('run_id')}:{meta.get('run_attempt')}"
    def send(operation, body, assertion):
        return request(base + "/" + operation, method="POST", token=assertion, body=body, idempotency_key=golden.sha((identity+":"+operation).encode()))
    started = send("start", {"request_sha256": expected}, token)
    envelope = started.get("request", {}); m = envelope.get("payload", {})
    workflow = m.get("baseline_workflow_ref", "")
    expected_meta = {"repository": m.get("repository"), "repository_id": m.get("repository_id"), "repository_owner_id": m.get("repository_owner_id"),
        "sha": m.get("source_sha"), "sub": m.get("oidc_subject"), "environment": m.get("input", {}).get("environment"), "job_workflow_ref": workflow}
    if started.get("status") != "authenticated" or started.get("mode") != MODE or started.get("azure_writes") is not False or started.get("execution") != "unavailable" or envelope.get("sha256") != expected or golden.sha(golden.encode(m)) != expected or m.get("workspace_id") != tenant or m.get("baseline_id") != identifier or m.get("api_origin") != origin or m.get("trusted_keys_sha256") != golden.sha(golden.encode(trusted)) or any(meta.get(k) != v for k, v in expected_meta.items()) or started.get("run_id") != meta.get("run_id") or started.get("run_attempt") != meta.get("run_attempt") or environ.get("V2_JOB_WORKFLOW_SHA") != workflow.rsplit("@", 1)[-1] or environ.get("V2_JOB_WORKFLOW_REPOSITORY") != workflow.split("/.github/workflows/")[0]: raise PreflightError("TRUST_REJECTED")
    counter = 0
    def checkpoint():
        nonlocal counter
        counter += 1
        ack = request(base+"/checkpoint", method="POST", token=issue(base+"/checkpoint"), body={"request_sha256": expected}, idempotency_key=golden.sha((identity+":checkpoint:"+str(counter)).encode()))
        if ack.get("status") != "continue-read-only" or ack.get("mode") != MODE or ack.get("azure_writes") is not False or ack.get("execution") != "unavailable": raise PreflightError("API_UNAVAILABLE")
    try: result = inspect(envelope, trusted, environ=environ, issue=issue, request=request, checkpoint=checkpoint)
    except PreflightError as error:
        allowed = {"TRUST_REJECTED", "FEDERATION_REJECTED", "IMAGE_UNVERIFIED", "API_UNAVAILABLE", "TOOLS_UNAVAILABLE"}
        code = error.code if error.code in allowed else "API_UNAVAILABLE"
        result = {"outcome": "unavailable" if code in {"API_UNAVAILABLE", "TOOLS_UNAVAILABLE"} else "failed", "failure_code": code, "no_apply": True}
    result["request_sha256"] = expected
    # Match the strict API model's explicit null fields before hashing the
    # acknowledged report. Omitted defaults must not look like different facts.
    for field in ("failure_code", "health", "image"): result.setdefault(field, None)
    ack = send("report", result, issue(base+"/report"))
    if ack.get("mode") != MODE or ack.get("azure_writes") is not False or ack.get("execution") != "unavailable": raise PreflightError("TRUST_REJECTED")
    if result["outcome"] == "observed" and (ack.get("status") != "OBSERVED" or ack.get("observation", {}).get("payload", {}).get("request_sha256") != expected or ack["observation"]["payload"].get("report_sha256") != golden.sha(golden.encode(result))): raise PreflightError("API_UNAVAILABLE")
    return result["outcome"] == "observed"


if __name__ == "__main__":
    try:
        ok = run()
        print("V2 existing-app observation reported. No deployment or rollback occurred; independent review is required.")
        sys.exit(0 if ok else 1)
    except Exception:
        print("V2 baseline observation unavailable. No apply was authorized.", file=sys.stderr); sys.exit(1)
