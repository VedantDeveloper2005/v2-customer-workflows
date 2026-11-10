"""Run only on the customer's GitHub-hosted runner. Python standard library.

Azure assertions/access tokens never leave this process for V2. No shell,
customer code, installs, artifacts, cloud writes, or raw provider logs.
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse, quote
from urllib.request import Request, HTTPRedirectHandler, build_opener
from uuid import UUID

ARM = "https://management.azure.com"
AZURE_AUDIENCE = "api://AzureADTokenExchange"


class PreflightError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise PreflightError("AZURE_UNAVAILABLE")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def request_json(url, *, method="GET", token=None, body=None, form=None, idempotency_key=None):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in {None, 443}:
        raise PreflightError("AZURE_UNAVAILABLE")
    headers = {"Accept": "application/json"}
    if idempotency_key:
        if not re.fullmatch(r"[0-9a-f]{64}", idempotency_key): raise PreflightError("IDENTITY_MISMATCH")
        headers["Idempotency-Key"] = idempotency_key
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"; data = json.dumps(body).encode()
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"; data = urlencode(form).encode()
    try:
        with build_opener(NoRedirect()).open(Request(url, data=data, headers=headers, method=method), timeout=15) as response:
            raw = response.read(131073)
            if len(raw) > 131072 or response.status != 200:
                raise ValueError()
        result = json.loads(raw)
        if not isinstance(result, dict): raise ValueError()
        return result
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        raise PreflightError("AZURE_UNAVAILABLE") from None


def oidc(audience, environ=os.environ, request=request_json):
    url = environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    parsed = urlparse(url)
    request_token = environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".actions.githubusercontent.com") or parsed.username or parsed.password or parsed.fragment or not request_token:
        raise PreflightError("AZURE_UNAVAILABLE")
    query = [(key, value) for key, value in parse_qsl(parsed.query) if key != "audience"] + [("audience", audience)]
    url = urlunparse(parsed._replace(query=urlencode(query)))
    value = request(url, token=request_token).get("value")
    if not isinstance(value, str) or not 32 <= len(value) <= 16384 or any(c.isspace() for c in value):
        raise PreflightError("AZURE_UNAVAILABLE")
    return value


def token_metadata(token):
    # This is metadata from a token acquired directly from Entra/GitHub, never
    # authentication of a caller-provided token. ARM/V2 verify its signature.
    try:
        part = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        if not isinstance(value, dict): raise ValueError()
        return value
    except (IndexError, ValueError, TypeError):
        raise PreflightError("IDENTITY_MISMATCH") from None


def azure_checks(manifest, *, request=request_json, oidc_request=oidc):
    checks = {"identity_match": False, "scope_match": False, "reader_only": False, "permissions_sha256": None}
    try:
        assertion = oidc_request(AZURE_AUDIENCE)
        tenant = str(UUID(manifest["azure_tenant_id"]))
        client = str(UUID(manifest["client_id"]))
        token_response = request(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", method="POST", form={
            "client_id": client, "grant_type": "client_credentials", "scope": ARM + "/.default",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": assertion})
        access = token_response.get("access_token")
        if not isinstance(access, str) or not 32 <= len(access) <= 32768 or token_response.get("token_type", "").casefold() != "bearer":
            raise PreflightError("IDENTITY_MISMATCH")
        claims = token_metadata(access)
        if claims.get("tid") != tenant or claims.get("oid") != manifest["principal_id"] or claims.get("appid", claims.get("azp")) != client or type(claims.get("exp")) is not int or claims["exp"] <= time.time() + 30:
            raise PreflightError("IDENTITY_MISMATCH")
        checks["identity_match"] = True
        group = manifest["resource_group"]
        if not isinstance(group, str) or not re.fullmatch(r"[A-Za-z0-9_.()\-]{1,90}", group): raise PreflightError("SCOPE_MISMATCH")
        scope = f"/subscriptions/{UUID(manifest['subscription_id'])}/resourceGroups/{quote(group, safe='')}"
        permissions = request(ARM + scope + "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01", token=access)
        values = permissions.get("value")
        if permissions.get("nextLink") or not isinstance(values, list) or not 1 <= len(values) <= 100: raise PreflightError("PERMISSIONS_REJECTED")
        actions = []
        for row in values:
            if not isinstance(row, dict) or not isinstance(row.get("actions"), list) or any(not isinstance(row.get(k, []), list) or row.get(k) for k in ("notActions", "dataActions", "notDataActions")) or row.get("condition"): raise PreflightError("PERMISSIONS_REJECTED")
            actions.extend(row["actions"])
        if not actions or any(not isinstance(a, str) or not re.fullmatch(r"[A-Za-z0-9.*_/-]+/read", a, re.IGNORECASE) for a in actions) or "*/read" not in [a.casefold() for a in actions]: raise PreflightError("PERMISSIONS_REJECTED")
        checks["reader_only"] = True
        checks["permissions_sha256"] = digest(sorted(set(actions)))
        group_result = request(ARM + scope + "?api-version=2021-04-01", token=access)
        expected_scope = f"/subscriptions/{manifest['subscription_id']}/resourceGroups/{group}"
        if not isinstance(group_result.get("id"), str) or group_result["id"].casefold() != expected_scope.casefold() or not isinstance(group_result.get("properties"), dict) or group_result["properties"].get("provisioningState") != "Succeeded": raise PreflightError("SCOPE_MISMATCH")
        checks["scope_match"] = True
        return {"outcome": "passed", **checks, "failure_code": None}
    except PreflightError as error:
        return {"outcome": "unavailable" if error.code == "AZURE_UNAVAILABLE" else "failed", **checks, "failure_code": error.code}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {"outcome": "unavailable", **checks, "failure_code": "AZURE_UNAVAILABLE"}


def run(environ=os.environ, *, request=request_json, oidc_request=None):
    issue = oidc_request or (lambda audience: oidc(audience, environ, request))
    origin = environ.get("V2_API_ORIGIN", "")
    parsed = urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PreflightError("AZURE_UNAVAILABLE")
    workspace, connection = str(UUID(environ["V2_WORKSPACE_ID"])), str(UUID(environ["V2_CONNECTION_ID"]))
    generation = environ["V2_GENERATION"]
    expected_digest = environ["V2_CONFIGURATION_SHA256"]
    if not re.fullmatch(r"[1-9][0-9]{0,9}", generation) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest): raise PreflightError("IDENTITY_MISMATCH")
    base = f"{origin}/api/customer-runners/{workspace}/{connection}/{generation}"
    token = issue(base + "/attest")
    github = token_metadata(token)
    identity = f"{connection}:{generation}:{github.get('run_id')}:{github.get('run_attempt')}"
    def send(operation, body, token):
        # Keep idempotency metadata in headers; never in a query or logs.
        return request(base + "/" + operation, method="POST", token=token, body=body,
            idempotency_key=hashlib.sha256((identity + ":" + operation).encode()).hexdigest())
    result = send("attest", {"configuration_sha256": expected_digest}, token)
    manifest = result.get("configuration")
    if result.get("status") != "authenticated" or result.get("execution") != "unavailable" or not isinstance(manifest, dict) or digest(manifest) != expected_digest or manifest.get("mode") != "reader-preflight" or manifest.get("api_origin") != origin or manifest.get("workspace_id") != workspace:
        raise PreflightError("IDENTITY_MISMATCH")
    publisher = manifest["trusted_workflow_ref"].split("/.github/workflows/", 1)[0]
    if environ.get("V2_JOB_WORKFLOW_SHA") != manifest["trusted_workflow_ref"].rsplit("@", 1)[1] or environ.get("V2_JOB_WORKFLOW_REPOSITORY") != publisher or result.get("run_id") != github.get("run_id") or result.get("run_attempt") != github.get("run_attempt") or result.get("source_sha") != github.get("sha"):
        raise PreflightError("IDENTITY_MISMATCH")
    report = azure_checks(manifest, request=request, oidc_request=issue)
    report["configuration_sha256"] = expected_digest
    acknowledgment = send("report", report, issue(base + "/report"))
    if acknowledgment.get("execution") != "unavailable": raise PreflightError("IDENTITY_MISMATCH")
    return report["outcome"] == "passed"


if __name__ == "__main__":
    try:
        passed = run()
        print("V2 Reader preflight reported. Deployment remains unavailable.")
        sys.exit(0 if passed else 1)
    except Exception:
        print("V2 Reader preflight unavailable. No deployment was authorized.", file=sys.stderr)
        sys.exit(1)
