"""Verify a signed customer job and change only the exact Azure Blob pointer."""

from datetime import datetime, timezone
import json
import os
import re
import sys
from urllib.parse import urlsplit
from uuid import uuid4

from backend.contracts import conditional_release as contract, golden_customer_plan as golden
from customer_runner import plan, preflight, rehearsal, release_health
from customer_runner.conditional_release_rehearsal import verify_signatures
from customer_runner.release_pointer import PointerBlob, ReleasePointer, Snapshot, StalePointer, StorageUnavailable


WEB_VERSION = "2023-12-01"


def require(value, reason="TRUST_REJECTED"):
    if not value:
        raise preflight.PreflightError(reason)


def snapshot(value):
    return {**vars(value.pointer), "etag": value.etag, "version": value.version}


def expected_snapshot(value):
    contract.pointer(value)
    return Snapshot(ReleasePointer(value["generation"], value["release"], value["image_digest"]),
                    value["etag"], value["version"])


def live_origins(p, binding, access, request):
    expected = contract.origin_requirements(p["scope"], binding, p["baseline"]["image_digest"], p["candidate"]["image_digest"])
    require(contract.digest(expected) == p["origin_evidence_sha256"])

    def resource(path, version):
        value = request(preflight.ARM + path + "?api-version=" + version, token=access)
        require(value["id"].casefold() == path.casefold(), "TARGET_CHANGED")
        return value["properties"]

    hosts = {}
    for name, item in expected.items():
        path = item["resource_id"]
        app = resource(path, WEB_VERSION)
        web = resource(path + "/config/web", WEB_VERSION)
        lock = resource(path + "/providers/Microsoft.Authorization/locks/" + item["lock"], "2016-09-01")
        scm = resource(path + "/basicPublishingCredentialsPolicies/scm", WEB_VERSION)
        ftp = resource(path + "/basicPublishingCredentialsPolicies/ftp", WEB_VERSION)
        require(app["httpsOnly"] is True and app["state"].casefold() == "running"
                and web["linuxFxVersion"] == "DOCKER|" + item["image"]
                and web["scmIpSecurityRestrictionsDefaultAction"].casefold() == "deny"
                and web["ftpsState"].casefold() == "disabled" and lock["level"] == "ReadOnly"
                and scm["allow"] is False and ftp["allow"] is False, "TARGET_CHANGED")
        host = app["defaultHostName"]
        require(isinstance(host, str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.azurewebsites\.net", host)
                and ".." not in host, "TARGET_CHANGED")
        hosts[name] = host
    require(len(set(hosts.values())) == 3, "TARGET_CHANGED")
    return hosts


def verify_storage(scope, access, request):
    resource = (f"/subscriptions/{scope['subscription_id']}/resourceGroups/{scope['resource_group']}"
                f"/providers/Microsoft.Storage/storageAccounts/{scope['storage_account']}")
    for suffix, expected in (
        ("", {"allowSharedKeyAccess": False, "allowBlobPublicAccess": False, "supportsHttpsTrafficOnly": True}),
        ("/blobServices/default", {"isVersioningEnabled": True}),
    ):
        path = resource + suffix
        item = request(preflight.ARM + path + "?api-version=2023-05-01", token=access)
        require(item["id"].casefold() == path.casefold()
                and all(item["properties"].get(key) is value for key, value in expected.items()), "STORAGE_REJECTED")


def observe(p, binding, current, blob, access, request):
    scope = p["scope"]
    manifest = {"subscription_id": scope["subscription_id"], "resource_group": scope["resource_group"],
                "input": {"app_name": scope["gateway_site"]}}
    policy = binding["health_policy"]
    expected = current.pointer

    def resolve(_manifest, _digest, _request, _access):
        if blob.read() != current:
            raise release_health.HealthError("ACTIVE_IMAGE_CHANGED", "failed")
        return live_origins(p, binding, access, request)["gateway"]

    def probe(host, path, challenge):
        if blob.read() != current:
            raise release_health.HealthError("ACTIVE_IMAGE_CHANGED", "failed")
        body = release_health.probe(host, path, challenge)
        if (body.get("image_digest") != expected.image_digest or body.get("release") != expected.release
                or type(body.get("generation")) is not int or body["generation"] != expected.generation):
            raise release_health.HealthError("PROBE_RESPONSE_REJECTED", "failed")
        return {**body, "image_sha256": expected.image_digest.removeprefix("sha256:")}

    return release_health.observe(manifest, policy, expected.image_digest.removeprefix("sha256:"), access,
        request=request, fetch_probe=probe, resolve_site=resolve)


def execute(api, trusted, environ, *, issue, request, make_blob=PointerBlob, health_observer=observe,
            clock=lambda: datetime.now(timezone.utc)):
    started = api("start")
    proofs = {"plan": started["plan"], "decision": started["decision"]}
    verify_signatures(proofs, trusted)
    p, decision, binding = proofs["plan"]["payload"], proofs["decision"]["payload"], started["runtime_binding"]
    now = clock()
    contract.plan_payload(p, now)
    contract.decision_payload(decision, p, proofs["plan"]["sha256"], now)
    require(p["schema_version"] == contract.LIVE_PLAN and p["runtime_sha256"] == contract.digest(binding)
            and started["status"] == "authenticated")
    scope, source = p["scope"], p["source"]
    require(p["write_control_generation"] == started["write_control_generation"])
    workflow_repo = source["workflow_ref"].split("/.github/", 1)[0]
    workflow_sha = source["workflow_ref"].rsplit("@", 1)[1]
    require(binding["trusted_keys_sha256"] == contract.digest(trusted) and binding["api_origin"] == environ["V2_API_ORIGIN"]
            and binding["release_id"] == environ["V2_RELEASE_ID"] and scope["workspace_id"] == environ["V2_WORKSPACE_ID"]
            and proofs["plan"]["sha256"] == environ["V2_REQUEST_SHA256"]
            and workflow_repo == environ["V2_JOB_WORKFLOW_REPOSITORY"] and workflow_sha == environ["V2_JOB_WORKFLOW_SHA"]
            and source["repository"] == environ["GITHUB_REPOSITORY"] and source["source_sha"] == environ["GITHUB_SHA"]
            and "refs/heads/" + binding["branch"] == environ["GITHUB_REF"])
    run_id, run_attempt = environ["GITHUB_RUN_ID"], int(environ["GITHUB_RUN_ATTEMPT"])

    def token(client, principal, resource):
        identity = {"azure_tenant_id": scope["azure_tenant_id"], "input": {
            "planning_client_id": client, "planning_principal_id": principal}}
        return plan.exchange(identity, resource + "/.default", issue, request)

    reader = (binding["reader_client_id"], binding["reader_principal_id"])
    arm_access = token(*reader, preflight.ARM)
    artifact_access = token(*reader, "https://storage.azure.com")
    verify_storage(scope, arm_access, request)
    artifact_manifest = {"input": {"storage_account": scope["storage_account"], "plans_container": binding["plans_container"]}}
    hashes = {kind.replace("-", "_") + "_sha256": golden.sha(rehearsal.download(
        artifact_manifest, binding["artifacts"][kind], artifact_access)) for kind in ("what-if", "saved-plan")}
    require(all(hashes[name] == p["artifacts"][name] for name in hashes), "ARTIFACT_MISMATCH")
    require(binding["plan_binding"]["execution_request_sha256"] == p["artifacts"]["execution_request_sha256"], "ARTIFACT_MISMATCH")
    access = token(scope["client_id"], scope["principal_id"], "https://storage.azure.com")
    blob = make_blob(scope["storage_account"], lambda: access)
    require(blob.url == scope["pointer_url"])
    original = expected_snapshot(p["baseline"])

    def authorize(operation, expected):
        live_origins(p, binding, arm_access, request)
        actual = blob.read()
        require(actual == expected, "POINTER_STALE")
        operation_id = str(uuid4())
        evidence = {"pointer": snapshot(actual), "origin_evidence_sha256": p["origin_evidence_sha256"],
                    "execution_request_sha256": p["artifacts"]["execution_request_sha256"], **hashes}
        result = api(operation, operation_id=operation_id, **evidence)
        require(result["status"] == "authorized")
        proofs["grant"] = result["grant"]
        verify_signatures(proofs, trusted)
        grant = proofs["grant"]["payload"]
        require(grant["operation"] == operation and grant["operation_id"] == operation_id)
        live_origins(p, binding, arm_access, request)
        require(blob.read() == actual, "POINTER_STALE")
        observation = {**{key: evidence[key] for key in ("pointer", "origin_evidence_sha256", "execution_request_sha256")},
            "scope": scope, "source": source, "run_id": run_id, "run_attempt": run_attempt,
            "write_control_generation": started["write_control_generation"], "blocked": False}
        contract.check_rehearsal_bindings(proofs, observation, hashes, now=clock())

    authorize("promote", original)
    candidate = p["candidate"]
    promoted = blob.promote(original, candidate["release"], candidate["image_digest"])
    require(blob.read() == promoted, "POINTER_STALE")
    report = api("promotion-report", grant_sha256=proofs["grant"]["sha256"], pointer=snapshot(promoted))
    proofs["promotion_grant"] = proofs["grant"]
    proofs["promotion_receipt"] = report["promotion_receipt"]
    require(proofs["promotion_receipt"]["payload"]["pointer"] == snapshot(promoted))
    health = health_observer(p, binding, promoted, blob, arm_access, request)
    require(blob.read() == promoted, "POINTER_STALE")
    outcome = api("candidate-health", pointer=snapshot(promoted), health=health)
    if outcome["status"] == "SUCCEEDED":
        require(health["outcome"] == "verified")
        return "SUCCEEDED"
    require(outcome["status"] == "ROLLBACK_PENDING" and health["outcome"] != "verified")
    authorize("rollback", promoted)
    recovered = blob.rollback(promoted, original)
    require(blob.read() == recovered, "POINTER_STALE")
    recovery = health_observer(p, binding, recovered, blob, arm_access, request)
    require(blob.read() == recovered, "POINTER_STALE")
    result = api("recovery-health", pointer=snapshot(recovered), health=recovery)
    require(result["status"] == "FAILED")
    return "RECOVERED" if recovery["outcome"] == "verified" and result["report"]["recovery"] == "verified" else "RECOVERY_UNVERIFIED"


def run(environ=os.environ, *, request=preflight.request_json, issue=preflight.oidc):
    origin = environ["V2_API_ORIGIN"]
    url = urlsplit(origin)
    require(url.scheme == "https" and url.hostname and not (url.username or url.password or url.path or url.query or url.fragment)
            and url.port in (None, 443) and not any(c.isspace() for c in origin))
    workspace, identifier, sha = (environ[name] for name in ("V2_WORKSPACE_ID", "V2_RELEASE_ID", "V2_REQUEST_SHA256"))
    contract.identifier(workspace)
    contract.identifier(identifier)
    contract.text(sha, contract.SHA256)
    raw_keys = environ["V2_TRUSTED_PUBLIC_KEYS"]
    require(0 < len(raw_keys) <= 8192)
    trusted = json.loads(raw_keys)

    def api(operation, **payload):
        address = f"{origin}/api/customer-conditional-releases/{workspace}/{identifier}/{operation}"
        body = {"action": operation, "request_sha256": sha, **payload}
        key = contract.digest({"body": body, "run": environ["GITHUB_RUN_ID"], "attempt": environ["GITHUB_RUN_ATTEMPT"]})
        return request(address, method="POST", token=issue(address), body=body, idempotency_key=key)

    return execute(api, trusted, environ, issue=issue, request=request)


if __name__ == "__main__":
    try:
        result = run()
        print("Conditional release outcome: " + result)
        sys.exit(0 if result == "SUCCEEDED" else 1)
    except (ValueError, KeyError, TypeError, AttributeError, OSError, preflight.PreflightError, StalePointer, StorageUnavailable):
        print("Conditional release rejected or requires state reconciliation.", file=sys.stderr)
        sys.exit(1)
