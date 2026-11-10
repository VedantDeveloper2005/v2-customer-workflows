"""Guarded exact saved-plan execution inside the customer's GitHub runner.

No application checkout, replan, import, shell command or credential brokerage.
The write adapter deliberately requires strong configuration ETags; deployment
stays disabled until customer staging proves the provider's conditional writes.
"""
from datetime import datetime, timezone
import copy
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener
from uuid import UUID, uuid4
from backend.contracts import golden_customer_plan as golden, release_safety, customer_timing as timing
from backend.contracts import customer_execution_capability as capability
from customer_runner import preflight, plan as planner, rehearsal, release_health, release_recovery
from customer_runner.preflight import PreflightError

MODE = capability.MODE
VERSION = capability.API_VERSION


def verify(proofs, trusted, root, child, execute):
    proof_path, keys_path = root / "proofs.json", root / "trusted.json"
    proof_path.write_bytes(golden.encode(proofs)); keys_path.write_bytes(golden.encode(trusted))
    proof_path.chmod(0o600); keys_path.chmod(0o600)
    try:
        if execute(["node", str(Path(__file__).with_name("verify_execution.mjs")), str(proof_path), str(keys_path)], str(root), child).strip() != b"verified":
            raise PreflightError("TRUST_REJECTED")
    except PreflightError as error:
        raise PreflightError("TOOLS_UNAVAILABLE" if error.code == "TOOLS_UNAVAILABLE" else "TRUST_REJECTED") from None


def read_configuration(url, access):
    """Keep the strong ETag from the same bounded ARM GET as its body."""
    pattern = r"https://management\.azure\.com/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Za-z0-9_.()\-]{1,90}/providers/Microsoft\.Web/sites/[A-Za-z0-9-]{2,60}/config/web\?api-version=" + VERSION
    if not re.fullmatch(pattern, url): raise PreflightError("CURRENT_IMAGE_CHANGED")
    try:
        with build_opener(preflight.NoRedirect()).open(Request(url, headers={"Authorization": "Bearer " + access, "Accept": "application/json"}, method="GET"), timeout=30) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity").casefold() != "identity": raise ValueError()
            raw = response.read(131073)
            etag = response.headers.get("ETag", "")
        if len(raw) > 131072 or not re.fullmatch(r'"[A-Za-z0-9_:.\-/]{1,180}"', etag): raise ValueError()
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value: raise ValueError()
                value[key] = item
            return value
        def invalid(_): raise ValueError()
        body = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
        if not isinstance(body, dict) or ("etag" in body and body["etag"] != etag): raise ValueError()
        return {**body, "etag": etag}
    except PreflightError: raise
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError):
        raise PreflightError("ROLLBACK_UNAVAILABLE") from None


def configuration(manifest, access, request, *, digest=None):
    """Read the exact target and all settings; refuse unsupported golden drift."""
    target, p = golden.app_resource_id(manifest), manifest["input"]
    app = request(preflight.ARM + target + "?api-version=" + VERSION, token=access)
    config_url = preflight.ARM + target + "/config/web?api-version=" + VERSION
    config = read_configuration(config_url, access) if request is preflight.request_json else request(config_url, token=access)
    settings = request(preflight.ARM + target + "/config/appsettings/list?api-version=" + VERSION, method="POST", token=access, body={})
    try:
        if app["id"].casefold() != target.casefold() or config["id"].casefold() != (target + "/config/web").casefold() or settings["id"].casefold() != (target + "/config/appsettings").casefold(): raise ValueError()
        a, c, s = app["properties"], config["properties"], settings["properties"]
        ids = golden.resource_ids(manifest)
        identity = app["identity"]
        if a["serverFarmId"].casefold() != ids["service_plan"].casefold() or a.get("reserved") is not True or a.get("httpsOnly") is not True or a.get("clientAffinityEnabled") is not False or identity.get("type") != "UserAssigned" or {i.casefold() for i in identity["userAssignedIdentities"]} != {ids["identity"].casefold()}: raise ValueError()
        if app["location"].replace(" ", "").casefold() != p["location"] or not all(c.get(k) == v for k, v in {"acrUseManagedIdentityCreds": True, "acrUserManagedIdentityID": p["runtime_client_id"], "alwaysOn": True, "minTlsVersion": "1.2", "ftpsState": "Disabled", "http20Enabled": True}.items()): raise ValueError()
        image = c["linuxFxVersion"]
        prefix = f"DOCKER|{p['registry_name']}.azurecr.io/{p['image_repository']}@sha256:"
        current = image[len(prefix):] if isinstance(image, str) and image.startswith(prefix) else ""
        if not re.fullmatch(r"[0-9a-f]{64}", current) or (digest is not None and current != digest): raise ValueError()
        if s != {"WEBSITES_PORT": str(p["container_port"]), "WEBSITES_ENABLE_APP_SERVICE_STORAGE": "false", "V2_IMAGE_SHA256": current}: raise ValueError()
        if c.get("appSettings") is not None:
            repeated = c["appSettings"]
            if not isinstance(repeated, list) or len(repeated) != 3 or {item["name"]: item["value"] for item in repeated} != s: raise ValueError()
        # A missing/weak ETag cannot protect the approved recovery operation.
        etag = config.get("etag")
        if not isinstance(etag, str) or not re.fullmatch(r'"[A-Za-z0-9_:.\-/]{1,180}"', etag): raise PreflightError("ROLLBACK_UNAVAILABLE")
        return {"digest": current, "etag": etag, "properties": copy.deepcopy(c), "settings": copy.deepcopy(s),
            "app": {"location": app["location"], "identity": copy.deepcopy(identity), "serverFarmId": a["serverFarmId"], "reserved": a["reserved"], "httpsOnly": a["httpsOnly"], "clientAffinityEnabled": a["clientAffinityEnabled"]}}
    except PreflightError: raise
    except (ValueError, KeyError, TypeError, AttributeError): raise PreflightError("CURRENT_IMAGE_CHANGED") from None


def stable(snapshot):
    value = copy.deepcopy(snapshot)
    for name in ("digest", "etag"): value.pop(name, None)
    value["properties"].pop("linuxFxVersion", None)
    # Some provider responses repeat settings on config/web; normalize them
    # only after independently checking the authoritative appsettings endpoint.
    value["properties"].pop("appSettings", None)
    value["settings"].pop("V2_IMAGE_SHA256", None)
    return value


def conditional_restore(manifest, action, snapshot, access, *, request, write=None):
    """One conditional narrow PATCH; never retry an ambiguous cloud write."""
    if not capability.supported(): raise PreflightError(capability.FAILURE_CODE)
    if action["resource_id"].casefold() != golden.app_resource_id(manifest).casefold() or snapshot["digest"] != action["candidate_image_sha256"]:
        raise PreflightError("CURRENT_IMAGE_CHANGED")
    p = manifest["input"]
    previous = action["restore_image_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", previous): raise PreflightError("TRUST_REJECTED")
    settings = {**snapshot["settings"], "V2_IMAGE_SHA256": previous}
    body = {"properties": {"linuxFxVersion": f"DOCKER|{p['registry_name']}.azurecr.io/{p['image_repository']}@sha256:{previous}",
        "appSettings": [{"name": k, "value": v} for k, v in sorted(settings.items())]}}
    url = preflight.ARM + golden.app_resource_id(manifest) + "/config/web?api-version=" + VERSION
    if write:
        write(url, token=access, body=body, etag=snapshot["etag"])
    else:
        headers = {"Authorization": "Bearer " + access, "Content-Type": "application/json", "If-Match": snapshot["etag"], "Accept": "application/json"}
        try:
            with build_opener(preflight.NoRedirect()).open(Request(url, data=golden.encode(body), headers=headers, method="PATCH"), timeout=60) as response:
                if response.status != 200 or len(response.read(131073)) > 131072: raise ValueError()
        except (HTTPError, URLError, OSError, TimeoutError, ValueError): raise PreflightError("ROLLBACK_FAILED") from None
    after = configuration(manifest, access, request, digest=previous)
    if stable(after) != stable(snapshot): raise PreflightError("CURRENT_IMAGE_CHANGED")
    return True


def verify_hosting(manifest, report, actual, now):
    """An approved historical observation cannot substitute for a live SKU read."""
    expected = report.get("hosting")
    try:
        if not isinstance(expected, dict) or not isinstance(actual, dict): raise ValueError()
        for name in ("service_plan_id", "sku", "instances", "location"):
            if name == "instances" and (type(actual[name]) is not int or type(expected[name]) is not int): raise ValueError()
            if actual[name] != expected[name]: raise ValueError()
        if actual["service_plan_id"] != golden.resource_ids(manifest)["service_plan"]: raise ValueError()
        captured = release_health.timestamp(actual["captured_at"])
        if not -5 <= (now - captured).total_seconds() <= 60: raise ValueError()
    except (KeyError, ValueError, TypeError): raise PreflightError("CURRENT_IMAGE_CHANGED") from None


def execute(proofs, trusted, *, environ=os.environ, issue=preflight.oidc, request=preflight.request_json,
            command=planner.command, fetch=rehearsal.download, authorize=lambda *args, **kwargs: None,
            checkpoint=lambda: None, observer=release_health.observe, restore=conditional_restore,
            now=lambda: datetime.now(timezone.utc)):
    """Apply once; inspect partial failure and recover only the approved image."""
    if not capability.supported(): raise PreflightError(capability.FAILURE_CODE)
    m, r, report = proofs["plan_manifest"], proofs["request"]["payload"], proofs["plan_report"]
    applied = "not-started"
    result = {"status": "FAILED", "apply_outcome": applied, "artifact_set_sha256": r["artifact_set_sha256"],
        "health": None, "recovery_health": None, "recovery": "not-needed", "serving_image_sha256": None, "failure_code": None}
    with tempfile.TemporaryDirectory(prefix="v2-execute-") as folder:
        root = Path(folder); root.chmod(0o700)
        child = rehearsal.child_environment(environ, root)
        (root / "empty.tfrc").write_text("", encoding="utf-8")
        verify(proofs, trusted, root, child, command)
        def grant(operation, current, **extras):
            if not capability.supported(): raise PreflightError(capability.FAILURE_CODE)
            value = authorize(operation, current, **extras)
            if not isinstance(value, dict) or not value.get("payload") or value["payload"].get("operation") != operation:
                raise PreflightError("AUTHORITY_REJECTED")
            verify({**proofs, "authorization": value}, trusted, root, rehearsal.child_environment(environ, root), command)
            return value
        try:
            policy = m["release_policy"]["contract"]
            timing_policy = timing.from_manifest(m)
            if r["minimum_before_apply_seconds"] != timing.minimum_budget(m): raise PreflightError("TRUST_REJECTED")
            compatibility = proofs["approval_challenge"]["payload"]["binding"]["release_authorization"]["compatibility"]
            action = proofs["approval_challenge"]["payload"]["binding"]["release_authorization"]["rollback_action"]
            known = [m["baseline"]["attestation"], compatibility, proofs["approval_challenge"], proofs["decision"]]
            trusted_envelopes = {golden.sha(golden.encode(value)) for value in known}
            def eligible():
                eligibility = release_recovery.assess(m, policy, r["candidate_image_sha256"], m["baseline"]["attestation"], compatibility=compatibility,
                    approval={"challenge": proofs["approval_challenge"], "decision": proofs["decision"]}, verify=lambda value: golden.sha(golden.encode(value)) in trusted_envelopes, now=now())
                if eligibility["status"] != "eligible" or eligibility["action"] != action: raise PreflightError("AUTHORITY_REJECTED")
            eligible()
            checkpoint()
            access = planner.exchange(m, preflight.ARM + "/.default", issue, request)
            from customer_runner.execution_permissions import check as permission_check
            permission_check(m, access, request=request)
            eligible()
            verify_hosting(m, report, planner.prerequisites(m, access, request), now())
            before = configuration(m, access, request, digest=r["previous_image_sha256"])
            blobs = {}
            storage = planner.exchange(m, "https://storage.azure.com/.default", issue, request)
            artifacts = report["artifacts"]
            if set(artifacts) != {"what-if", "saved-plan", "bundle", "image-provenance"} or golden.sha(golden.encode(artifacts)) != r["artifact_set_sha256"]: raise PreflightError("ARTIFACT_MISMATCH")
            for kind, artifact in artifacts.items():
                if artifact["blob_name"] != f"plans/{m['plan_id']}/{kind}-{artifact['sha256']}": raise PreflightError("ARTIFACT_MISMATCH")
                raw = fetch(m, artifact, storage)
                if len(raw) != artifact["size_bytes"] or golden.sha(raw) != artifact["sha256"]: raise PreflightError("ARTIFACT_MISMATCH")
                blobs[kind] = raw
            bundle = golden.bundle(m, planner.LOCK.read_bytes())
            if bundle != blobs["bundle"] or golden.sha(bundle) != m["bundle_sha256"]: raise PreflightError("ARTIFACT_MISMATCH")
            files = json.loads(bundle)["files"]
            if set(files) != {"main.tf.json", "what-if.json", ".terraform.lock.hcl"}: raise PreflightError("ARTIFACT_MISMATCH")
            for name, content in files.items():
                path = root / name; path.write_text(content, encoding="utf-8"); path.chmod(0o600)
            saved = root / "saved.tfplan"; saved.write_bytes(blobs["saved-plan"]); saved.chmod(0o600)
            if json.loads(command(["tofu", "version", "-json"], folder, child)).get("terraform_version") != golden.ENGINE_VERSION: raise PreflightError("TOOLS_UNAVAILABLE")
            command(["tofu", "init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"], folder, child)
            shown = json.loads(command(["tofu", "show", "-json", "saved.tfplan"], folder, child))
            rehearsal.inspect_plan(shown)
            golden.summarize(json.loads(blobs["what-if"]), shown, m)
            checkpoint()
            child.update({"AZURE_CONFIG_DIR": str(root / "azure"), "AZURE_CORE_ONLY_SHOW_ERRORS": "true", "AZURE_CORE_COLLECT_TELEMETRY": "false", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
                "ARM_USE_OIDC": "true", "ARM_USE_AZUREAD": "true", "ARM_CLIENT_ID": m["input"]["planning_client_id"], "ARM_TENANT_ID": m["azure_tenant_id"], "ARM_SUBSCRIPTION_ID": m["subscription_id"]})
            command(["az", "login", "--service-principal", "--username", child["ARM_CLIENT_ID"], "--tenant", child["ARM_TENANT_ID"], "--federated-token", issue(preflight.AZURE_AUDIENCE), "--output", "json"], folder, child)
            command(["az", "account", "set", "--subscription", m["subscription_id"], "--output", "json"], folder, child)
            # This replays only the immutable ARM read-only assessment. The
            # approved artifacts and saved OpenTofu binary never change.
            fresh = json.loads(command(["az", "deployment", "group", "what-if", "--subscription", m["subscription_id"], "--resource-group", m["resource_group"], "--name", "v2-plan-" + m["plan_id"], "--template-file", "what-if.json", "--result-format", "FullResourcePayloads", "--no-pretty-print", "--output", "json"], folder, child))
            if fresh != json.loads(blobs["what-if"]): raise PreflightError("CURRENT_IMAGE_CHANGED")
            golden.summarize(fresh, shown, m)
            child["ARM_OIDC_TOKEN"] = issue(preflight.AZURE_AUDIENCE)
            command(["tofu", "init", "-reconfigure", "-input=false", "-lockfile=readonly", "-no-color"], folder, child)
            current = configuration(m, access, request, digest=r["previous_image_sha256"])
            if stable(current) != stable(before) or current["etag"] != before["etag"]: raise PreflightError("CURRENT_IMAGE_CHANGED")
            if golden.sha(saved.read_bytes()) != artifacts["saved-plan"]["sha256"]: raise PreflightError("ARTIFACT_MISMATCH")
            if (release_health.timestamp(r["expires_at"]) - now()).total_seconds() < r["minimum_before_apply_seconds"]: raise PreflightError("AUTHORITY_REJECTED")
            access = planner.exchange(m, preflight.ARM + "/.default", issue, request)
            lifetime = preflight.token_metadata(access).get("exp")
            if type(lifetime) is not int or lifetime <= now().timestamp() + r["minimum_before_apply_seconds"] + 60:
                raise PreflightError("FEDERATION_REJECTED")
            permission_check(m, access, request=request)
            eligible()
            verify_hosting(m, report, planner.prerequisites(m, access, request), now())
            child["ARM_OIDC_TOKEN"] = issue(preflight.AZURE_AUDIENCE)
            grant("apply", r["previous_image_sha256"], artifact_set_sha256=r["artifact_set_sha256"])
            applied = "failed"  # A timeout/nonzero exit can already mutate Azure.
            try:
                command(["tofu", "apply", "-input=false", "-no-color", "-lock-timeout=30s", "saved.tfplan"], folder, child, timeout=timing_policy["apply_timeout_seconds"])
                applied = "applied"
            except PreflightError:
                pass
            result["apply_outcome"] = applied
            current = configuration(m, access, request)
            if stable(current) != stable(before): raise PreflightError("CURRENT_IMAGE_CHANGED")
            candidate, previous = r["candidate_image_sha256"], r["previous_image_sha256"]
            if current["digest"] != candidate:
                if current["digest"] == previous and applied == "failed":
                    result.update(status="MANUAL_INTERVENTION", failure_code="APPLY_FAILED", recovery="unverified")
                    return result
                raise PreflightError("CURRENT_IMAGE_CHANGED")
            eligible()
            def health(digest):
                identifier = uuid4().hex
                def authorized():
                    grant("verify", digest, observation_id=identifier)
                authorized()
                value = observer(m, policy, digest, access, request=request, checkpoint=authorized, observation_id=identifier)
                authorized()
                return value
            if applied == "applied":
                result["health"] = health(candidate)
                if release_safety.verified_health(result["health"], policy, candidate):
                    if configuration(m, access, request, digest=candidate)["digest"] != candidate: raise PreflightError("CURRENT_IMAGE_CHANGED")
                    result.update(status="SUCCEEDED", serving_image_sha256=candidate)
                    return result
                result["failure_code"] = "HEALTH_FAILED" if result["health"].get("outcome") == "failed" else "HEALTH_UNAVAILABLE"
            else:
                result["failure_code"] = "APPLY_FAILED"
            access = planner.exchange(m, preflight.ARM + "/.default", issue, request)
            permission_check(m, access, request=request)
            eligible()
            current = configuration(m, access, request, digest=candidate)
            if stable(current) != stable(before): raise PreflightError("CURRENT_IMAGE_CHANGED")
            grant("rollback", candidate, rollback_action_sha256=action["sha256"])
            if restore(m, action, current, access, request=request) is not True: raise PreflightError("ROLLBACK_FAILED")
            result["recovery_health"] = health(previous)
            recovered = release_safety.verified_health(result["recovery_health"], policy, previous)
            if recovered and configuration(m, access, request, digest=previous)["digest"] == previous:
                result.update(recovery="verified", serving_image_sha256=previous)
            else:
                result.update(status="MANUAL_INTERVENTION", recovery="unverified", failure_code="ROLLBACK_FAILED")
            return result
        except (PreflightError, ValueError, KeyError, TypeError) as error:
            result.update(status="MANUAL_INTERVENTION" if applied != "not-started" else "FAILED", apply_outcome=applied,
                recovery="unverified" if applied != "not-started" else "not-needed", failure_code=error.code if isinstance(error, PreflightError) else "PLAN_REJECTED")
            return result


def run(environ=os.environ, *, request=preflight.request_json, issue=None, executor=execute, command=planner.command):
    if not capability.supported(): raise PreflightError(capability.FAILURE_CODE)
    issue = issue or (lambda audience: preflight.oidc(audience, environ, request))
    origin = environ.get("V2_API_ORIGIN", "")
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port not in {None, 443}: raise PreflightError("TRUST_REJECTED")
    tenant, identifier = str(UUID(environ["V2_WORKSPACE_ID"])), str(UUID(environ["V2_EXECUTION_ID"]))
    expected, raw_keys = environ.get("V2_REQUEST_SHA256", ""), environ.get("V2_TRUSTED_PUBLIC_KEYS", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or not 1 <= len(raw_keys) <= 8192: raise PreflightError("TRUST_REJECTED")
    trusted = json.loads(raw_keys)
    if not isinstance(trusted, dict) or not 1 <= len(trusted) <= 8: raise PreflightError("TRUST_REJECTED")
    base = f"{origin}/api/customer-executions/{tenant}/{identifier}"
    token = issue(base + "/start"); meta = preflight.token_metadata(token)
    identity = f"{identifier}:{meta.get('run_id')}:{meta.get('run_attempt')}"
    started = request(base + "/start", method="POST", token=token, body={"request_sha256": expected}, idempotency_key=golden.sha((identity + ":start").encode()))
    envelope = started.get("request", {}); r = envelope.get("payload", {})
    workflow = r.get("execution_workflow_ref", "")
    expected_meta = {"repository": r.get("repository"), "repository_id": r.get("repository_id"), "repository_owner_id": r.get("repository_owner_id"), "sha": r.get("source_sha"), "sub": r.get("oidc_subject"), "environment": r.get("environment"), "job_workflow_ref": workflow}
    if started.get("status") != "authenticated" or started.get("mode") != MODE or started.get("azure_writes") is not True or envelope.get("sha256") != expected or golden.sha(golden.encode(r)) != expected or r.get("tenant_id") != tenant or r.get("execution_id") != identifier or r.get("api_origin") != origin or r.get("trusted_keys_sha256") != golden.sha(golden.encode(trusted)) or any(meta.get(k) != v for k, v in expected_meta.items()) or started.get("run_id") != meta.get("run_id") or started.get("run_attempt") != meta.get("run_attempt") or environ.get("V2_JOB_WORKFLOW_SHA") != workflow.rsplit("@", 1)[-1] or environ.get("V2_JOB_WORKFLOW_REPOSITORY") != workflow.split("/.github/workflows/")[0]: raise PreflightError("TRUST_REJECTED")
    supplied = started.get("proofs")
    if not isinstance(supplied, dict) or set(supplied) != {"plan_manifest", "plan_report", "approval_challenge", "decision", "evidence"}: raise PreflightError("TRUST_REJECTED")
    proofs = {**supplied, "request": envelope}
    sequence = 0
    write_started = False
    def authorize(operation, current=None, **extras):
        nonlocal sequence, write_started
        operation_id = str(uuid4())
        body = {"request_sha256": expected, "operation_id": operation_id, **extras}
        if current is not None: body["current_image_sha256"] = current
        # A lost response can follow a committed one-shot server grant. Treat
        # the write boundary as uncertain rather than claiming no authority.
        if operation in {"apply", "rollback"}: write_started = True
        ack = request(base + "/" + operation, method="POST", token=issue(base + "/" + operation), body=body,
            idempotency_key=golden.sha((identity + ":" + operation + ":" + operation_id).encode()))
        grant = ack.get("authorization", {}); p = grant.get("payload", {})
        if ack.get("status") != "authorized" or p.get("operation") != operation or p.get("operation_id") != operation_id or p.get("run_id") != meta.get("run_id") or p.get("run_attempt") != meta.get("run_attempt") or p.get("request_sha256") != expected or type(p.get("sequence")) is not int or p["sequence"] <= sequence or (current is not None and p.get("current_image_sha256") != current) or any(p.get(key) != value for key, value in extras.items()): raise PreflightError("AUTHORITY_REJECTED")
        sequence = p["sequence"]
        return grant
    def checkpoint():
        # The executor verifies every signed authorization using the same
        # offline verifier. These read checkpoints never carry write authority.
        grant = authorize("checkpoint")
        with tempfile.TemporaryDirectory(prefix="v2-execute-check-") as folder:
            root = Path(folder)
            verify({**proofs, "authorization": grant}, trusted, root, rehearsal.child_environment(environ, root), command)
    try:
        result = executor(proofs, trusted, environ=environ, issue=issue, request=request, command=command, authorize=authorize, checkpoint=checkpoint)
    except (PreflightError, ValueError, KeyError, TypeError) as error:
        result = {"status": "MANUAL_INTERVENTION" if write_started else "FAILED", "apply_outcome": "failed" if write_started else "not-started",
            "artifact_set_sha256": r["artifact_set_sha256"], "health": None, "recovery_health": None,
            "recovery": "unverified" if write_started else "not-needed", "serving_image_sha256": None,
            "failure_code": error.code if isinstance(error, PreflightError) else "PLAN_REJECTED"}
    allowed_codes = {"TRUST_REJECTED", "FEDERATION_REJECTED", "ARTIFACT_MISMATCH", "PLAN_REJECTED", "TOOLS_UNAVAILABLE", "API_UNAVAILABLE", "APPLY_FAILED", "HEALTH_FAILED", "HEALTH_UNAVAILABLE", "ROLLBACK_UNAVAILABLE", "AUTHORITY_REJECTED", "CURRENT_IMAGE_CHANGED", "ROLLBACK_FAILED", "ATOMIC_WRITE_UNAVAILABLE"}
    if write_started and result["apply_outcome"] == "not-started":
        result.update(status="MANUAL_INTERVENTION", apply_outcome="failed", recovery="unverified", serving_image_sha256=None)
    if result.get("failure_code") and result["failure_code"] not in allowed_codes: result["failure_code"] = "API_UNAVAILABLE"
    result["request_sha256"] = expected
    ack = request(base + "/report", method="POST", token=issue(base + "/report"), body=result, idempotency_key=golden.sha((identity + ":report").encode()))
    if ack.get("status") != result["status"] or ack.get("mode") != MODE: raise PreflightError("API_UNAVAILABLE")
    return result["status"] == "SUCCEEDED"


if __name__ == "__main__":
    try:
        ok = run()
        print("V2 customer execution reported. Review the recorded outcome and any state-reconciliation requirement.")
        sys.exit(0 if ok else 1)
    except Exception:
        print("V2 customer execution unavailable or unverified. Inspect the customer run before any retry.", file=sys.stderr)
        sys.exit(1)
