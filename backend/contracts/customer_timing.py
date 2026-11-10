"""Immutable review and execution timing for newly issued customer plans.

This is a versioned approval policy, not a renewal mechanism. Existing plans
and signed envelopes never receive a longer deadline from this module.
"""
from datetime import datetime
from backend.contracts.golden_customer_plan import encode, sha
from backend.contracts import release_safety

POLICY = {
    "schema_version": "v2.customer-timing.v1",
    "plan_ttl_seconds": 7200,
    "evidence_ttl_seconds": 3600,
    "compatibility_ttl_seconds": 3600,
    "approval_ttl_seconds": 3600,
    "hosting_max_age_seconds": 7200,
    "operation_grant_seconds": 60,
    "apply_timeout_seconds": 240,
    "restore_timeout_seconds": 60,
    "dispatch_floor_seconds": 600,
}

# The GitHub job is an outer process limit, not another authorization window.
# A request predates its job, so the full approval ceiling plus report margin
# prevents GitHub from terminating an otherwise approved recovery early. Keep
# these outside POLICY: no issued signature, TTL, or consent hash is renewed.
EXECUTION_REPORT_MARGIN_SECONDS = 300
EXECUTION_JOB_TIMEOUT_SECONDS = POLICY["approval_ttl_seconds"] + EXECUTION_REPORT_MARGIN_SECONDS


def execution_job_timeout_minutes():
    return (EXECUTION_JOB_TIMEOUT_SECONDS + 59) // 60


def snapshot():
    contract = dict(POLICY)
    return {"contract": contract, "sha256": sha(encode(contract))}


def validate_snapshot(value):
    if not isinstance(value, dict) or set(value) != {"contract", "sha256"}:
        raise ValueError("The approved timing policy is missing or malformed")
    contract = value["contract"]
    if not isinstance(contract, dict) or set(contract) != set(POLICY):
        raise ValueError("Unsupported customer timing policy")
    if any(type(contract[name]) is not int for name in POLICY if name != "schema_version") or contract != POLICY or value["sha256"] != sha(encode(contract)):
        raise ValueError("The approved timing policy changed")
    return dict(contract)


def from_manifest(manifest):
    return validate_snapshot(manifest.get("timing_policy"))


def valid_interval(manifest, issued_at, expires_at, ttl_key, now):
    """Check signed historical issuance and deadline; never refresh either."""
    try:
        policy = from_manifest(manifest)
        if ttl_key not in {"evidence_ttl_seconds", "compatibility_ttl_seconds", "approval_ttl_seconds"}:
            return False
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        plan_expires = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
        return all(value.tzinfo is not None for value in (issued, expires, plan_expires, now)) and issued <= now < expires <= plan_expires and 0 < (expires - issued).total_seconds() <= policy[ttl_key]
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def minimum_budget(manifest, *, include_dispatch=False):
    timing = from_manifest(manifest)
    health = release_safety.validate(manifest["release_policy"]["contract"])
    windows = 2 * (health["stabilization_minutes"] * 60 + health["telemetry_grace_seconds"] + 60)
    return windows + timing["apply_timeout_seconds"] + timing["restore_timeout_seconds"] + (timing["dispatch_floor_seconds"] if include_dispatch else 0)
