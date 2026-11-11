"""Exact signed authority for a conditional release rehearsal.

The caller verifies each signature before invoking this contract. Observations
must come from the authenticated job and Azure before this can guard a write.
"""

from datetime import datetime, timedelta, timezone
import re
from uuid import UUID

from backend.contracts import customer_timing as timing
from backend.contracts.golden_customer_plan import encode, sha


PLAN = "v2.conditional-release-plan.v1"
LIVE_PLAN = "v2.conditional-release-plan.v2"
DECISION = "v2.conditional-release-decision.v1"
LIVE_DECISION = "v2.conditional-release-decision.v2"
GRANT = "v2.conditional-release-grant.v1"
PROMOTION = "v2.conditional-release-promotion.v1"
SHA256 = r"[a-f0-9]{64}"
TAG = r'"0x[0-9A-Fa-f]{8,32}"'
VERSION = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z"
SITE = r"[a-z][a-z0-9-]{1,58}[a-z0-9]"
RELEASE = r"[a-z][a-z0-9-]{0,39}"
REPOSITORY = r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
WORKFLOW = REPOSITORY + r"/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[a-f0-9]{40}"
UTC = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)"


class RehearsalRejected(ValueError):
    """A bounded, non-secret reason for rejecting the rehearsal."""


def require(condition, reason="MALFORMED_PROOF"):
    if not condition:
        raise RehearsalRejected(reason)


def fields(value, *names):
    require(isinstance(value, dict) and set(value) == set(names))


def text(value, pattern, limit=256):
    require(isinstance(value, str) and len(value) <= limit and re.fullmatch(pattern, value) is not None)


def identifier(value):
    text(value, r"[a-f0-9-]{36}", 36)
    try:
        parsed = UUID(value)
    except ValueError:
        raise RehearsalRejected("MALFORMED_PROOF") from None
    require(str(parsed) == value and parsed.int != 0)


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value < 2**53)


def timestamp(value):
    text(value, UTC, 32)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RehearsalRejected("MALFORMED_PROOF") from None


def digest(value):
    return sha(encode(value))


def origin_requirements(scope, binding, before, after):
    root = f"/subscriptions/{scope['subscription_id']}/resourceGroups/{scope['resource_group']}/providers/Microsoft.Web/sites/"
    images = {"gateway": binding["gateway_image"], "baseline": binding["baseline_image"], "candidate": binding["candidate_image"]}
    result = {role: {"resource_id": root + scope[f"{role}_site"], "image": images[role], "https_only": True,
                     "lock": "v2-release-readonly", "scm_denied": True, "ftps_disabled": True, "basic_auth_disabled": True}
              for role in ("gateway", "baseline", "candidate")}
    result["baseline"]["digest"] = before
    result["candidate"]["digest"] = after
    return result


def interval(payload, now, seconds, *, parent=None):
    issued = timestamp(payload["issued_at"])
    expires = timestamp(payload["expires_at"])
    require(issued <= now < expires and expires - issued <= timedelta(seconds=seconds), "EXPIRED_AUTHORITY")
    if parent is not None:
        require(timestamp(parent["issued_at"]) <= issued and expires <= timestamp(parent["expires_at"]),
                "AUTHORITY_WINDOW_CHANGED")


def pointer(value):
    fields(value, "generation", "release", "image_digest", "etag", "version")
    integer(value["generation"], 1)
    text(value["release"], RELEASE)
    text(value["image_digest"], "sha256:" + SHA256)
    text(value["etag"], TAG)
    text(value["version"], VERSION)
    try:
        datetime.fromisoformat(value["version"].replace("Z", "+00:00"))
    except ValueError:
        raise RehearsalRejected("MALFORMED_PROOF") from None


def scope(value):
    fields(value, "workspace_id", "project_id", "plan_id", "azure_tenant_id", "subscription_id", "resource_group",
           "storage_account", "pointer_url", "gateway_site", "baseline_site", "candidate_site", "client_id", "principal_id")
    for name in ("workspace_id", "project_id", "plan_id", "azure_tenant_id", "subscription_id", "client_id", "principal_id"):
        identifier(value[name])
    text(value["resource_group"], r"[A-Za-z0-9_.()-]{1,89}[A-Za-z0-9_()-]|[A-Za-z0-9_()-]", 90)
    text(value["storage_account"], r"[a-z][a-z0-9]{2,23}")
    require(value["pointer_url"] == f"https://{value['storage_account']}.blob.core.windows.net/pointer/release.json")
    for name in ("gateway_site", "baseline_site", "candidate_site"):
        text(value[name], SITE)
    require(len({value["gateway_site"], value["baseline_site"], value["candidate_site"]}) == 3)


def source(value):
    fields(value, "repository", "repository_id", "repository_owner_id", "source_sha", "workflow_ref", "environment")
    text(value["repository"], REPOSITORY)
    text(value["repository_id"], r"[1-9][0-9]{0,19}")
    text(value["repository_owner_id"], r"[1-9][0-9]{0,19}")
    text(value["source_sha"], r"[a-f0-9]{40}")
    text(value["workflow_ref"], WORKFLOW)
    text(value["environment"], r"[A-Za-z0-9_-]{1,64}")


def plan_payload(value, now):
    live = isinstance(value, dict) and value.get("schema_version") == LIVE_PLAN
    fields(value, "schema_version", "key_id", "scope", "source", "created_by", "requested_by", "write_control_generation",
           "baseline", "candidate", "artifacts", "origin_evidence_sha256", "issued_at", "expires_at",
           *(("runtime_sha256",) if live else ()))
    require(value["schema_version"] in (PLAN, LIVE_PLAN))
    if live:
        text(value["runtime_sha256"], SHA256)
    scope(value["scope"])
    source(value["source"])
    identifier(value["created_by"])
    identifier(value["requested_by"])
    integer(value["write_control_generation"])
    pointer(value["baseline"])
    require(value["baseline"]["generation"] < 2**53 - 2)
    fields(value["candidate"], "release", "image_digest")
    text(value["candidate"]["release"], RELEASE)
    text(value["candidate"]["image_digest"], "sha256:" + SHA256)
    require(value["candidate"]["release"] != value["baseline"]["release"])
    require(value["candidate"]["image_digest"] != value["baseline"]["image_digest"])
    text(value["origin_evidence_sha256"], SHA256)
    fields(value["artifacts"], "what_if_sha256", "saved_plan_sha256", "execution_request_sha256")
    for value_hash in value["artifacts"].values():
        text(value_hash, SHA256)
    interval(value, now, timing.POLICY["plan_ttl_seconds"])


def decision_payload(value, plan, plan_sha, now):
    live = plan["schema_version"] == LIVE_PLAN
    fields(value, "schema_version", "key_id", "plan_sha256", "decision", "actor_user_id", "actor_role", "issued_at", "expires_at",
           *(("database_compatibility_acknowledged",) if live else ()))
    require(value["schema_version"] == (LIVE_DECISION if live else DECISION)
            and value["decision"] == "approve" and value["plan_sha256"] == plan_sha
            and (not live or value["database_compatibility_acknowledged"] is True),
            "APPROVAL_CHANGED")
    identifier(value["actor_user_id"])
    require(value["actor_role"] in ("owner", "admin")
            and value["actor_user_id"] not in (plan["requested_by"], plan["created_by"]), "APPROVAL_CHANGED")
    interval(value, now, timing.POLICY["approval_ttl_seconds"], parent=plan)


def grant_payload(value, plan_sha, decision, decision_sha, now):
    fields(value, "schema_version", "key_id", "plan_sha256", "decision_sha256", "operation", "operation_id", "run_id",
           "run_attempt", "expected_pointer_sha256", "issued_at", "expires_at")
    require(value["schema_version"] == GRANT and value["plan_sha256"] == plan_sha and value["decision_sha256"] == decision_sha,
            "AUTHORITY_CHANGED")
    require(value["operation"] in ("promote", "rollback"))
    identifier(value["operation_id"])
    text(value["run_id"], r"[1-9][0-9]{0,19}")
    integer(value["run_attempt"], 1)
    text(value["expected_pointer_sha256"], SHA256)
    interval(value, now, timing.POLICY["operation_grant_seconds"], parent=decision)


def recovered_precondition(proofs, plan, decision, grant):
    receipt = proofs["promotion_receipt"]["payload"]
    fields(receipt, "schema_version", "key_id", "promotion_grant_sha256", "pointer", "observed_at")
    previous_grant = proofs["promotion_grant"]["payload"]
    observed = timestamp(receipt["observed_at"])
    grant_payload(previous_grant, proofs["plan"]["sha256"], decision, proofs["decision"]["sha256"], observed)
    require(receipt["schema_version"] == PROMOTION and receipt["promotion_grant_sha256"] == proofs["promotion_grant"]["sha256"]
            and previous_grant["operation"] == "promote" and previous_grant["operation_id"] != grant["operation_id"]
            and all(previous_grant[k] == grant[k] for k in ("run_id", "run_attempt"))
            and observed <= timestamp(grant["issued_at"]), "PROMOTION_RECEIPT_CHANGED")
    baseline, candidate = plan["baseline"], plan["candidate"]
    promoted = receipt["pointer"]
    pointer(promoted)
    require(previous_grant["expected_pointer_sha256"] == digest(baseline)
            and promoted["generation"] == baseline["generation"] + 1
            and promoted["release"] == candidate["release"] and promoted["image_digest"] == candidate["image_digest"]
            and promoted["etag"] != baseline["etag"] and promoted["version"] != baseline["version"],
            "PROMOTION_RECEIPT_CHANGED")
    return promoted


def check_rehearsal_bindings(proofs, observation, artifact_hashes, *, now=None):
    """Compare a verified proof chain with the observed request, without writing."""
    now = datetime.now(timezone.utc) if now is None else now
    require(now.tzinfo is not None)
    require(isinstance(proofs, dict) and {"plan", "decision", "grant"} <= set(proofs))
    plan, decision, grant = (proofs[name]["payload"] for name in ("plan", "decision", "grant"))
    plan_sha, decision_sha = proofs["plan"]["sha256"], proofs["decision"]["sha256"]
    plan_payload(plan, now)
    decision_payload(decision, plan, plan_sha, now)
    grant_payload(grant, plan_sha, decision, decision_sha, now)
    if grant["operation"] == "promote":
        fields(proofs, "plan", "decision", "grant")
        expected = plan["baseline"]
    else:
        fields(proofs, "plan", "decision", "grant", "promotion_grant", "promotion_receipt")
        expected = recovered_precondition(proofs, plan, decision, grant)

    fields(observation, "scope", "source", "run_id", "run_attempt", "write_control_generation", "blocked",
           "pointer", "execution_request_sha256", "origin_evidence_sha256")
    scope(observation["scope"])
    source(observation["source"])
    integer(observation["run_attempt"], 1)
    integer(observation["write_control_generation"])
    pointer(observation["pointer"])
    require(observation["blocked"] is False and observation["write_control_generation"] == plan["write_control_generation"],
            "WORKSPACE_STOPPED_OR_STALE")
    require(observation["scope"] == plan["scope"] and observation["source"] == plan["source"]
            and all(observation[k] == grant[k] for k in ("run_id", "run_attempt")), "TARGET_OR_JOB_CHANGED")
    require(observation["origin_evidence_sha256"] == plan["origin_evidence_sha256"], "ORIGIN_EVIDENCE_CHANGED")
    require(observation["execution_request_sha256"] == plan["artifacts"]["execution_request_sha256"]
            and artifact_hashes == {name: plan["artifacts"][name] for name in ("what_if_sha256", "saved_plan_sha256")},
            "ARTIFACT_MISMATCH")
    require(observation["pointer"] == expected and grant["expected_pointer_sha256"] == digest(expected), "POINTER_STALE")
    return {"operation": grant["operation"], "plan_sha256": plan_sha, "grant_sha256": proofs["grant"]["sha256"],
            "expected_pointer_sha256": grant["expected_pointer_sha256"]}
