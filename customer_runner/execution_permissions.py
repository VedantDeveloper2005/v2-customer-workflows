"""Bounded effective-rights inspection inside the customer's runner.

The Azure token is verified by ``plan.exchange`` before this helper is called.
No assignment is created and no permission response or token is sent to V2.
These fixed-scope queries do not inventory grants in other resource groups,
subscriptions, tenants, groups or delegated identities. Real Azure scope and
federation proof remains a rollout gate; this is not an identity-wide audit.
The subscription permission query must itself be authorized: a separately
reviewed subscription role containing only Microsoft.Authorization/permissions/read
may be needed for an otherwise RG-scoped principal. A 403 fails closed; this
module never adds that role or substitutes subscription Reader. The permissions
API does not expose assignment conditions/provenance, so absence of condition
fields here does not prove that an identity has no conditional assignments.
"""
import re
from uuid import UUID

from backend.contracts import golden_customer_plan as golden
from customer_runner.preflight import ARM, PreflightError

VERSION = "2022-04-01"
PERMISSION_KEYS = {"actions", "notActions", "dataActions", "notDataActions"}
MANAGEMENT_WRITES = frozenset({
    "microsoft.web/sites/write",
    "microsoft.web/sites/config/write",
    "microsoft.web/sites/config/list/action",
    "microsoft.resources/deployments/whatif/action",
})
REQUIRED_APP = MANAGEMENT_WRITES - {"microsoft.resources/deployments/whatif/action"}
BLOB_READ = "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"
BLOB_WRITE = "microsoft.storage/storageaccounts/blobservices/containers/blobs/write"
OPERATION = re.compile(r"^[A-Za-z0-9_.*/-]{3,256}$")


def _rights(response):
    """Reject partial, conditional or unfamiliar permission representations."""
    if not isinstance(response, dict) or set(response) - {"value", "nextLink"} or response.get("nextLink") not in {None, ""}:
        raise ValueError()
    rows = response.get("value")
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError()
    management, data = set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - PERMISSION_KEYS or "actions" not in row:
            raise ValueError()
        normalized = {}
        for key in PERMISSION_KEYS:
            items = row.get(key, [])
            if not isinstance(items, list) or len(items) > 256 or any(not isinstance(item, str) or not OPERATION.fullmatch(item) for item in items):
                raise ValueError()
            normalized[key] = {item.casefold() for item in items}
        # Exclusions/conditional rights need a fuller evaluator. Treating them
        # as unconditional effective grants could falsely authorize a write.
        if normalized["notActions"] or normalized["notDataActions"]:
            raise ValueError()
        management.update(normalized["actions"])
        data.update(normalized["dataActions"])
    return management, data


def _read(operation):
    return operation.endswith("/read")


def _scopes(manifest):
    """Construct only fixed ARM permission URLs from signed identifiers."""
    subscription = str(UUID(manifest["subscription_id"]))
    p = manifest["input"]
    if subscription != manifest["subscription_id"]:
        raise ValueError()
    for value, pattern in (
        (manifest["resource_group"], r"[A-Za-z0-9_.()\-]{1,90}"),
        (p["app_name"], r"[a-z][a-z0-9-]{1,58}[a-z0-9]"),
        (p["storage_account"], r"[a-z][a-z0-9]{2,23}"),
        (p["state_container"], r"[a-z0-9]+(?:-[a-z0-9]+)*"),
        (p["plans_container"], r"[a-z0-9]+(?:-[a-z0-9]+)*"),
    ):
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError()
    if any(not 3 <= len(p[key]) <= 63 for key in ("state_container", "plans_container")) or p["state_container"] == p["plans_container"]:
        raise ValueError()
    group = f"/subscriptions/{subscription}/resourceGroups/{manifest['resource_group']}"
    storage = group + "/providers/Microsoft.Storage/storageAccounts/" + p["storage_account"]
    return {
        "subscription": f"/subscriptions/{subscription}",
        "resource_group": group,
        "app": group + "/providers/Microsoft.Web/sites/" + p["app_name"],
        "storage_account": storage,
        "state_container": storage + "/blobServices/default/containers/" + p["state_container"],
        "plans_container": storage + "/blobServices/default/containers/" + p["plans_container"],
    }


def check(manifest, access, *, request):
    """Require explicit app writes and container-only Blob read/write rights.

    The original planning principal also uploads protected plan artifacts, so
    both exact containers permit Blob read/write. Delete, wildcard data rights,
    shared-key/delegation-key access, role assignment and unrelated writes are
    unsupported. Exact version/ETag/SHA checks still protect approved bytes.
    """
    try:
        scopes = _scopes(manifest)
        inspected = {}
        for kind, scope in scopes.items():
            response = request(ARM + scope + "/providers/Microsoft.Authorization/permissions?api-version=" + VERSION, token=access)
            management, data = _rights(response)
            allowed = frozenset() if kind == "subscription" else MANAGEMENT_WRITES
            if any(not _read(operation) and operation not in allowed for operation in management):
                raise ValueError()
            if kind in {"state_container", "plans_container"}:
                if data != {BLOB_READ, BLOB_WRITE}:
                    raise ValueError()
            elif any(not _read(operation) for operation in data):
                raise ValueError()
            if kind == "resource_group" and not management:
                raise ValueError()
            if kind == "app" and not REQUIRED_APP.issubset(management):
                raise ValueError()
            inspected[kind] = {"scope": scope, "actions": sorted(management), "data_actions": sorted(data)}
        return {"status": "verified", "scope": "fixed-workload-and-container-permissions",
            "permissions_sha256": golden.sha(golden.encode(inspected)), "identity_wide_audit": False}
    except Exception:
        # Includes transport failure/403 and unfamiliar payloads. Do not infer
        # that access denied is an empty permission set, or expose raw errors.
        raise PreflightError("FEDERATION_REJECTED") from None
