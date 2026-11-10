"""Operator-only App Service concurrency probe for an isolated disposable app.

The default mode performs reads only. Mutable mode requires an exact exclusive
disposable-target confirmation and nonce tags. No customer image, identity,
hosting, database or execution-enable setting is changed. Settings stay only
in process memory; the printed report contains bounded outcomes and hashes.
"""
import copy
from datetime import datetime, timezone
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener
from uuid import UUID
from backend.contracts import golden_customer_plan as golden
from customer_runner import preflight, plan as planner

VERSION = "2023-12-01"
LIMIT = 131072
PURPOSE = "disposable-concurrency-probe"
SETTING = "V2_STAGING_PROBE"
STRONG = re.compile(r'^"[A-Za-z0-9_:.\-/]{1,180}"$')
FIELDS = {"azure_tenant_id", "client_id", "principal_id", "subscription_id", "resource_group", "app_name", "expected_resource_id", "probe_nonce", "allow_mutations", "confirmation"}


class ProbeError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def options(value):
    """Parse explicit operator intent without an ambient credential fallback."""
    if not isinstance(value, dict) or set(value) != FIELDS: raise ProbeError("INPUT_REJECTED")
    p = copy.deepcopy(value)
    try:
        for key in ("azure_tenant_id", "client_id", "principal_id", "subscription_id"):
            if str(UUID(p[key])) != p[key]: raise ValueError()
        if not re.fullmatch(r"[A-Za-z0-9_.()\-]{1,90}", p["resource_group"]) or not re.fullmatch(r"[a-z][a-z0-9-]{1,58}[a-z0-9]", p["app_name"]) or not re.fullmatch(r"[0-9a-f]{32}", p["probe_nonce"]): raise ValueError()
        target = f"/subscriptions/{p['subscription_id']}/resourceGroups/{p['resource_group']}/providers/Microsoft.Web/sites/{p['app_name']}"
        if p["expected_resource_id"] != target or type(p["allow_mutations"]) is not bool: raise ValueError()
        if p["allow_mutations"] and p["confirmation"] != "DISPOSABLE EXCLUSIVE " + target: raise ValueError()
        if not isinstance(p["confirmation"], str) or len(p["confirmation"]) > 400: raise ValueError()
    except (TypeError, ValueError, KeyError): raise ProbeError("INPUT_REJECTED") from None
    return p


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError()
            value[key] = item
        return value
    def invalid(_): raise ValueError()
    result = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    if not isinstance(result, dict): raise ValueError()
    return result


class Arm:
    """Fixed URLs, no redirects/retries, and same-response strong ETags."""
    def __init__(self, p, access):
        self.p, self.access = p, access
        self.base = preflight.ARM + p["expected_resource_id"]
        self.write_attempts = 0

    def call(self, kind, *, method="GET", body=None, etag=None):
        paths = {"app": "", "config": "/config/web", "settings": "/config/appsettings/list", "settings-write": "/config/appsettings"}
        allowed = {("app", "GET"), ("config", "GET"), ("settings", "POST"), ("config", "PATCH"), ("settings-write", "PUT")}
        if (kind, method) not in allowed: raise ProbeError("REQUEST_REJECTED")
        writing = method in {"PATCH", "PUT"}
        if writing and (not self.p["allow_mutations"] or not isinstance(etag, str) or not STRONG.fullmatch(etag)): raise ProbeError("WRITE_NOT_AUTHORIZED")
        url = self.base + paths[kind] + "?api-version=" + VERSION
        headers = {"Authorization": "Bearer " + self.access, "Accept": "application/json"}
        data = None
        if body is not None:
            data = golden.encode(body); headers["Content-Type"] = "application/json"
            if len(data) > LIMIT: raise ProbeError("RESPONSE_REJECTED")
        if writing:
            headers["If-Match"] = etag
            self.write_attempts += 1
        try:
            with build_opener(preflight.NoRedirect()).open(Request(url, headers=headers, data=data, method=method), timeout=30) as response:
                if response.headers.get("Content-Encoding", "identity").casefold() != "identity": raise ValueError()
                raw = response.read(LIMIT + 1)
                if len(raw) > LIMIT: raise ValueError()
                if response.status != 200: raise ValueError()
                if writing: return {"status": 200}
                value = decode(raw)
                if kind == "config":
                    tag = response.headers.get("ETag", "")
                    if not STRONG.fullmatch(tag) or ("etag" in value and value["etag"] != tag): raise ProbeError("STRONG_ETAG_UNAVAILABLE")
                    value["etag"] = tag
                return value
        except HTTPError as error:
            if writing and error.code == 412: return {"status": 412}
            raise ProbeError("AZURE_UNAVAILABLE") from None
        except preflight.PreflightError:
            raise ProbeError("REDIRECT_REJECTED") from None
        except (URLError, OSError, TimeoutError, ValueError, TypeError):
            raise ProbeError("RESPONSE_REJECTED") from None


def snapshot(arm, p):
    app, config, settings = arm.call("app"), arm.call("config"), arm.call("settings", method="POST", body={})
    target = p["expected_resource_id"]
    try:
        if app["id"].casefold() != target.casefold() or config["id"].casefold() != (target + "/config/web").casefold() or settings["id"].casefold() != (target + "/config/appsettings").casefold(): raise ValueError()
        a, c, s = app["properties"], config["properties"], settings["properties"]
        if a.get("reserved") is not True or "linux" not in app.get("kind", "").casefold().split(",") or "functionapp" in app.get("kind", "").casefold(): raise ValueError()
        if type(c.get("http20Enabled")) is not bool or not isinstance(c.get("linuxFxVersion"), str): raise ValueError()
        if not isinstance(s, dict) or len(s) > 100 or any(not isinstance(k, str) or not 1 <= len(k) <= 256 or not isinstance(v, str) or len(v) > 32768 for k,v in s.items()): raise ValueError()
        if c.get("appSettings") is not None:
            values = c["appSettings"]
            if not isinstance(values, list) or len(values) != len(s) or {v["name"]: v["value"] for v in values} != s: raise ValueError()
        c = {k: copy.deepcopy(v) for k,v in c.items() if k != "appSettings"}
        tag = config["etag"]
        if not isinstance(tag, str) or not STRONG.fullmatch(tag): raise ProbeError("STRONG_ETAG_UNAVAILABLE")
        protected = {k: copy.deepcopy(app.get(k)) for k in ("id", "name", "type", "location", "kind", "identity", "tags")}
        protected["properties"] = {k: copy.deepcopy(a.get(k)) for k in ("serverFarmId", "reserved", "httpsOnly", "clientAffinityEnabled", "keyVaultReferenceIdentity", "virtualNetworkSubnetId", "publicNetworkAccess", "hostingEnvironmentProfile")}
        if p["allow_mutations"]:
            tags = app.get("tags", {})
            if not isinstance(tags, dict) or tags.get("v2-purpose") != PURPOSE or tags.get("v2-probe-nonce") != p["probe_nonce"]: raise ProbeError("DISPOSABLE_TARGET_NOT_CONFIRMED")
        return {"app": protected, "config": c, "settings": copy.deepcopy(s), "etag": tag}
    except ProbeError: raise
    except (ValueError, KeyError, TypeError, AttributeError): raise ProbeError("TARGET_REJECTED") from None


def material(value):
    return {k:v for k,v in value.items() if k != "etag"}


def current(arm, p, expected):
    observed = snapshot(arm, p)
    if observed != expected: raise ProbeError("CONCURRENT_CHANGE")
    return observed


def settings_body(values):
    return {"properties": {"appSettings": [{"name": k, "value": v} for k,v in sorted(values.items())]}}


def probe(p, arm):
    """Return only bounded observations, never raw app settings or tokens."""
    p = options(p)
    checks = {"strong_etag": "unavailable", "config_stale_if_match": "not-run", "config_settings_fence": "not-run", "put_settings_fence": "not-run"}
    result = {"schema_version": "v2.customer-staging-probe.v1", "mode": "disposable-mutation" if p["allow_mutations"] else "read-only",
        "target_sha256": golden.sha(p["expected_resource_id"].encode()), "probe_nonce_sha256": golden.sha(p["probe_nonce"].encode()),
        "outcome": "unavailable", "checks": checks, "cleanup": "not-needed", "cleanup_required": False,
        "azure_write_attempts": 0, "failure_code": None, "before_sha256": None, "after_sha256": None,
        "execution_enabled": False, "image_digest_restore_tested": False, "identity_wide_permission_audit": False}
    original, owned = None, None
    pending = False
    try:
        original = snapshot(arm, p)
        result["before_sha256"] = golden.sha(golden.encode(material(original)))
        checks["strong_etag"] = "observed"
        if not p["allow_mutations"]:
            result.update(outcome="read-only", after_sha256=result["before_sha256"])
            return result
        if SETTING in original["settings"]: raise ProbeError("PROBE_SETTING_ALREADY_PRESENT")

        def patch(expected, body, intended):
            nonlocal owned, pending
            current(arm, p, expected)
            pending = True
            response = arm.call("config", method="PATCH", body=body, etag=expected["etag"])
            if response["status"] != 200: raise ProbeError("CONCURRENT_CHANGE")
            observed = snapshot(arm, p)
            if material(observed) != material(intended) or observed["etag"] == expected["etag"]: raise ProbeError("CONFIGURATION_FENCE_UNVERIFIED")
            owned = observed
            return observed

        def stale(expected, old_tag):
            # The stale request only toggles this benign configuration flag.
            # A provider that ignores the precondition must not pass the probe.
            current(arm, p, expected)
            response = arm.call("config", method="PATCH", body={"properties": {"http20Enabled": not expected["config"]["http20Enabled"]}}, etag=old_tag)
            observed = snapshot(arm, p)
            if response["status"] != 412 or observed != expected: raise ProbeError("STALE_IF_MATCH_NOT_ENFORCED")

        def restore(expected, body):
            nonlocal owned, pending
            current(arm, p, expected)
            response = arm.call("config", method="PATCH", body=body, etag=expected["etag"])
            if response["status"] != 200: raise ProbeError("CLEANUP_UNVERIFIED")
            observed = snapshot(arm, p)
            if material(observed) != material(original): raise ProbeError("CLEANUP_UNVERIFIED")
            pending = False; owned = None
            return observed

        changed = copy.deepcopy(original); changed["config"]["http20Enabled"] = not original["config"]["http20Enabled"]
        changed = patch(original, {"properties": {"http20Enabled": changed["config"]["http20Enabled"]}}, changed)
        stale(changed, original["etag"])
        checks["config_stale_if_match"] = "observed-412"
        baseline = restore(changed, {"properties": {"http20Enabled": original["config"]["http20Enabled"]}})

        # Same endpoint used by the narrow release restore adapter.
        changed = copy.deepcopy(baseline); changed["settings"][SETTING] = p["probe_nonce"]
        changed = patch(baseline, settings_body(changed["settings"]), changed)
        stale(changed, baseline["etag"])
        checks["config_settings_fence"] = "observed-412"
        baseline = restore(changed, settings_body(original["settings"]))

        # The separate appsettings PUT endpoint is an independent writer. Its
        # mutation must invalidate the earlier config/web tag as well.
        current(arm, p, baseline)
        pending = True
        values = {**original["settings"], SETTING: p["probe_nonce"]}
        response = arm.call("settings-write", method="PUT", body={"properties": values}, etag=baseline["etag"])
        if response["status"] != 200: raise ProbeError("SETTINGS_PUT_UNAVAILABLE")
        observed = snapshot(arm, p)
        intended = copy.deepcopy(baseline); intended["settings"] = values
        if material(observed) != material(intended) or observed["etag"] == baseline["etag"]: raise ProbeError("SETTINGS_FENCE_UNVERIFIED")
        owned = observed
        stale(observed, baseline["etag"])
        checks["put_settings_fence"] = "observed-412"
        final = restore(observed, settings_body(original["settings"]))
        result.update(outcome="passed", cleanup="restored", after_sha256=golden.sha(golden.encode(material(final))))
    except ProbeError as error:
        result["failure_code"] = error.code
        # No emergency broad replay: if the observed provider ignored a fence
        # or any target data changed, automatic cleanup could overwrite a
        # concurrent writer. Leave an explicit manual-cleanup requirement.
        if pending:
            result.update(outcome="manual-intervention", cleanup="manual-required", cleanup_required=True)
        else:
            result.update(outcome="unavailable", cleanup="restored" if original and arm.write_attempts else "not-needed")
    except Exception:
        result.update(outcome="manual-intervention" if pending else "unavailable", failure_code="PROBE_UNAVAILABLE",
            cleanup="manual-required" if pending else "not-needed", cleanup_required=pending)
    finally:
        result["azure_write_attempts"] = arm.write_attempts
    return result


def run(environ=os.environ, *, request=preflight.request_json, issue=None, client=Arm):
    names = {k: "V2_PROBE_" + k.upper() for k in FIELDS}
    value = {key: environ.get(name, "") for key,name in names.items()}
    raw_mutations = environ.get("V2_PROBE_ALLOW_MUTATIONS", "false")
    if raw_mutations not in {"true", "false"}: raise ProbeError("INPUT_REJECTED")
    value["allow_mutations"] = raw_mutations == "true"
    p = options(value)
    issue = issue or (lambda audience: preflight.oidc(audience, environ, request))
    manifest = {"azure_tenant_id": p["azure_tenant_id"], "subscription_id": p["subscription_id"], "input": {"planning_client_id": p["client_id"], "planning_principal_id": p["principal_id"]}}
    try:
        access = planner.exchange(manifest, preflight.ARM + "/.default", issue, request)
    except preflight.PreflightError: raise ProbeError("FEDERATION_UNAVAILABLE") from None
    return probe(p, client(p, access))


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
        sys.exit(0 if result["outcome"] in {"read-only", "passed"} else 1)
    except Exception:
        print('{"outcome":"unavailable","failure_code":"PROBE_UNAVAILABLE","execution_enabled":false}')
        sys.exit(1)
