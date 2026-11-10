"""Portable release safety contract shared with the credential-free API."""
import re
from datetime import datetime
from backend.contracts.golden_customer_plan import encode, sha, app_resource_id

SCHEMA = "v2.release-policy.v1"
FIELDS = {"schema_version", "synthetic_path", "dependency_path", "dependencies", "stabilization_minutes",
    "poll_seconds", "telemetry_grace_seconds", "min_requests_per_minute", "max_5xx_basis_points",
    "database_change", "automatic_rollback", "first_release"}


def rollback_action(manifest, policy_sha, previous, baseline_sha, compatibility_sha):
    context = {k: v for k, v in manifest.items() if k != "rollback_action_sha256"}
    value = {"schema_version": "v2.image-rollback.v1", "tenant_id": manifest["workspace_id"], "project_id": manifest["project_id"],
        "plan_id": manifest["plan_id"], "plan_context_sha256": sha(encode(context)), "resource_id": app_resource_id(manifest),
        "candidate_image_sha256": manifest["input"]["image_sha256"], "restore_image_sha256": previous,
        "baseline_sha256": baseline_sha, "compatibility_sha256": compatibility_sha, "policy_sha256": policy_sha,
        "registry_name": manifest["input"]["registry_name"], "image_repository": manifest["input"]["image_repository"]}
    return {**value, "sha256": sha(encode(value))}


def validate(value):
    if not isinstance(value, dict) or set(value) != FIELDS or value["schema_version"] != SCHEMA:
        raise ValueError("Invalid release policy schema")
    for name in ("synthetic_path", "dependency_path"):
        path = value[name]
        if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", path) or len(path) > 100:
            raise ValueError("Use a dedicated absolute health path without a query or fragment")
    if value["synthetic_path"] == value["dependency_path"]:
        raise ValueError("Synthetic and dependency probes require separate paths")
    deps = value["dependencies"]
    if not isinstance(deps, list) or not 1 <= len(deps) <= 8 or any(not isinstance(d, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", d) for d in deps) or len(set(deps)) != len(deps):
        raise ValueError("Name one to eight distinct dependencies")
    for name, low, high in (("stabilization_minutes", 2, 10), ("poll_seconds", 15, 30),
            ("telemetry_grace_seconds", 60, 180), ("min_requests_per_minute", 1, 60), ("max_5xx_basis_points", 0, 100)):
        if type(value[name]) is not int or not low <= value[name] <= high:
            raise ValueError("Release threshold is outside the supported range")
    if value["database_change"] != "none" or value["automatic_rollback"] is not True or value["first_release"] != "blocked":
        raise ValueError("This path requires no database migrations, automatic rollback and a verified previous release")
    return value


def digest(value):
    return sha(encode(validate(value)))


def verified_health(value, policy, image):
    """A verified label alone cannot establish a known-good release."""
    try:
        if value["outcome"] != "verified" or value["image_sha256"] != image or value["policy_sha256"] != digest(policy) or value["checks"] != ["synthetic", "dependencies", "azure-monitor"]: return False
        start = datetime.fromisoformat(value["window_start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(value["window_end"].replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None or start.timestamp() % 60 or end.timestamp() % 60 or (end - start).total_seconds() != policy["stabilization_minutes"] * 60: return False
        if type(value["samples"]) is not int or not policy["stabilization_minutes"] * 60 // policy["poll_seconds"] + 1 <= value["samples"] <= 1000: return False
        t = value["telemetry"]
        if type(t["requests"]) is not int or type(t["http_5xx"]) is not int or type(t["minutes"]) is not int or t["minutes"] != policy["stabilization_minutes"] or t["requests"] < policy["min_requests_per_minute"] * t["minutes"] or not 0 <= t["http_5xx"] <= t["requests"] or t["http_5xx"] * 10000 > t["requests"] * policy["max_5xx_basis_points"]: return False
        return bool(re.fullmatch(r"[0-9a-f]{32}", value["observation_id"])) and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in (t["response_sha256"], value["probe_chain_sha256"]))
    except (KeyError, ValueError, TypeError, AttributeError): return False
