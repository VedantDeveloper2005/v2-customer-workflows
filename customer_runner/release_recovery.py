"""Verification/rollback orchestration; production write adapter is unavailable.

The future pinned executor must supply fresh authorization, exact image reads,
an approved restore adapter and a trusted signature verifier. No default
callback grants authority or obtains credentials.
"""
from datetime import datetime, timedelta, timezone
import re
from uuid import uuid4
from backend.contracts import golden_customer_plan as golden, release_safety, customer_timing as timing
from customer_runner.release_health import timestamp
from backend.contracts.release_safety import rollback_action


def assess(manifest, policy, candidate, baseline, *, compatibility=None, approval=None, verify=lambda _: False, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        policy_sha = release_safety.digest(policy)
        if manifest.get("release_policy", {}).get("sha256") != policy_sha or manifest["release_policy"].get("contract") != policy or candidate != manifest["input"]["image_sha256"]:
            return {"status": "blocked", "reason": "APPROVED_POLICY_OR_IMAGE_MISMATCH"}
        if not baseline: return {"status": "blocked", "reason": "NO_KNOWN_GOOD_RELEASE"}
        if verify(baseline) is not True: raise ValueError()
        p = baseline["payload"]
        if p.get("kind") != "known-good-release" or p.get("tenant_id") != manifest["workspace_id"] or p.get("project_id") != manifest["project_id"] or p.get("resource_id", "").casefold() != golden.resource_ids(manifest)["app"].casefold() or p.get("policy_sha256") != policy_sha or p.get("database_change") != "none": raise ValueError()
        if not timestamp(p["verified_at"]) <= now < timestamp(p["expires_at"]) or (timestamp(p["expires_at"]) - timestamp(p["verified_at"])).total_seconds() > 86400: raise ValueError()
        previous = p["image_sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", previous) or not re.fullmatch(r"[0-9a-f]{64}", candidate) or previous == candidate or p.get("registry_name") != manifest["input"]["registry_name"] or p.get("image_repository") != manifest["input"]["image_repository"]: raise ValueError()
        h = p["health"]
        if not release_safety.verified_health(h, policy, previous) or not timestamp(h["window_end"]) <= timestamp(p["verified_at"]) or golden.sha(golden.encode(h)) != p.get("health_evidence_sha256"): raise ValueError()
        if not compatibility or verify(compatibility) is not True: return {"status": "blocked", "reason": "DATABASE_COMPATIBILITY_UNVERIFIED"}
        c = compatibility["payload"]
        compatibility_ttl = 900
        if manifest.get("execution_gate_version") == "customer-execution.v2":
            compatibility_ttl = timing.from_manifest(manifest)["compatibility_ttl_seconds"]
            if c.get("timing_policy_sha256") != manifest["timing_policy"]["sha256"] or c.get("timing_policy_acknowledged") is not True: raise ValueError()
        expected = {"kind": "database-compatibility", "tenant_id": manifest["workspace_id"], "project_id": manifest["project_id"], "plan_id": manifest["plan_id"],
            "resource_id": golden.resource_ids(manifest)["app"], "candidate_image_sha256": candidate, "previous_image_sha256": previous,
            "source_sha": manifest["source_sha"], "policy_sha256": policy_sha, "baseline_sha256": baseline["sha256"], "database_change": "none"}
        if any(c.get(k) != v for k, v in expected.items()) or not timestamp(c["issued_at"]) <= now < timestamp(c["expires_at"]) or not 0 < (timestamp(c["expires_at"]) - timestamp(c["issued_at"])).total_seconds() <= compatibility_ttl or c.get("reviewed_by") == manifest["created_by"] or c.get("reviewer_role") not in {"owner", "admin"} or not re.fullmatch(r"[0-9a-f]{64}", c.get("evidence_sha256", "")): raise ValueError()
        from uuid import UUID
        UUID(c["reviewed_by"])
        action = rollback_action(manifest, policy_sha, previous, baseline["sha256"], compatibility["sha256"])
        if manifest.get("mode") == "app-service-update-plan":
            if not approval or verify(approval["challenge"]) is not True or verify(approval["decision"]) is not True: return {"status": "blocked", "reason": "ROLLBACK_ACTION_NOT_APPROVED"}
            a, d = approval["challenge"]["payload"], approval["decision"]["payload"]
            if manifest.get("execution_gate_version") == "customer-execution.v2":
                if a.get("timing_policy_sha256") != manifest["timing_policy"]["sha256"] or d.get("timing_policy_sha256") != manifest["timing_policy"]["sha256"] or d.get("timing_policy_acknowledged") is not True or not timing.valid_interval(manifest, a["issued_at"], a["expires_at"], "approval_ttl_seconds", now): raise ValueError()
            release = a["binding"]["release_authorization"]
            for value in (a, d):
                if any(value.get(k) != v for k, v in {"tenant_id": manifest["workspace_id"], "project_id": manifest["project_id"], "plan_id": manifest["plan_id"]}.items()): raise ValueError()
            if d.get("actor_role") not in {"owner", "admin"} or not isinstance(d.get("actor_user_id"), str) or not isinstance(a.get("requested_by"), str) or not now < timestamp(d["expires_at"]) <= timestamp(a["expires_at"]) or d.get("review_sha256") != a["binding"]["review_sha256"] or d.get("execution_request_sha256") != a["binding"]["execution_request_sha256"]: raise ValueError()
            e = a["binding"]["evidence"]
            if d.get("cost_scope_acknowledged") is not True or d.get("cost_scope_sha256") != e["cost"]["scope_sha256"] or d.get("evidence_sha256") != e["evidence_sha256"] or c.get("cost_image_evidence_sha256") != e["evidence_sha256"] or c.get("request_sha256") != golden.sha(golden.encode(manifest)) or c.get("method") != "independent-source-review" or c.get("automated_database_tests") != "not-run" or not all(c.get(k) is True for k in ("source_reviewed", "no_database_changes", "both_images_compatible")): raise ValueError()
            if a.get("kind") != "challenge" or d.get("kind") != "decision" or d.get("decision") != "approve" or d.get("challenge_sha256") != approval["challenge"]["sha256"] or a["binding"]["request_sha256"] != golden.sha(golden.encode(manifest)) or a["binding"]["review_sha256"] != c.get("review_sha256") or a["binding"]["execution_request_sha256"] != c.get("execution_request_sha256") or d.get("release_authorization_sha256") != golden.sha(golden.encode(release)) or release.get("compatibility") != compatibility or release.get("rollback_action") != action or not now < timestamp(a["expires_at"]) <= timestamp(c["expires_at"]) or d.get("actor_user_id") in {a.get("requested_by"), manifest["created_by"]}: raise ValueError()
        elif manifest.get("rollback_action_sha256") != action["sha256"]: return {"status": "blocked", "reason": "ROLLBACK_ACTION_NOT_APPROVED"}
        return {"status": "eligible", "previous_image_sha256": previous, "policy_sha256": policy_sha, "baseline_sha256": baseline["sha256"], "compatibility_sha256": compatibility["sha256"], "action": action}
    except Exception:
        return {"status": "blocked", "reason": "BASELINE_OR_DATABASE_COMPATIBILITY_UNVERIFIED"}


def verify_release(manifest, policy, candidate, baseline, *, observe, authorize=None, current_image=None,
                   restore=None, compatibility=None, approval=None, verify_baseline=lambda _: False, now=None):
    """A failed release stays FAILED even when its previous image recovers."""
    def fresh():
        return assess(manifest, policy, candidate, baseline, compatibility=compatibility, approval=approval, verify=verify_baseline, now=now() if callable(now) else now)
    eligibility = fresh()
    if eligibility["status"] != "eligible": return {"status": "BLOCKED", "recovery": "unavailable", "reason": eligibility["reason"], "events": []}
    if any(fn is None for fn in (authorize, current_image, restore)):
        return {"status": "BLOCKED", "recovery": "unavailable", "reason": "WRITE_EXECUTOR_UNAVAILABLE", "events": []}
    events = ["VERIFYING"]
    try:
        def observe_fresh(digest):
            began = now() if callable(now) else now or datetime.now(timezone.utc)
            identifier = uuid4().hex
            result = observe(digest, identifier)
            ended = now() if callable(now) else now or datetime.now(timezone.utc)
            if result.get("outcome") == "verified" and (not release_safety.verified_health(result, policy, digest) or result.get("observation_id") != identifier or timestamp(result["window_start"]) < began or timestamp(result["window_end"]) > ended + timedelta(seconds=5)):
                raise ValueError()
            return result
        if authorize("verify", candidate) is not True or current_image() != candidate: raise ValueError()
        health = observe_fresh(candidate)
        if health.get("outcome") == "verified":
            if not release_safety.verified_health(health, policy, candidate) or fresh()["status"] != "eligible" or authorize("verify", candidate) is not True or current_image() != candidate: raise ValueError()
            return {"status": "SUCCEEDED", "recovery": "not-needed", "serving_image_sha256": candidate, "health": health, "events": events + ["SUCCEEDED"]}
        events.append("ROLLBACK_PENDING")
        previous = eligibility["previous_image_sha256"]
        # The write adapter must enforce this exact approved rollback action.
        # An absent/revoked approval or changed image must stop cloud writes.
        action = eligibility["action"]
        if fresh()["status"] != "eligible" or authorize("rollback", action) is not True or current_image() != candidate: raise ValueError()
        if restore(action) is not True or current_image() != previous: raise ValueError()
        recovered = observe_fresh(previous)
        verified = release_safety.verified_health(recovered, policy, previous) and authorize("verify", previous) is True and current_image() == previous
        return {"status": "FAILED", "recovery": "verified" if verified else "unverified", "serving_image_sha256": previous if verified else None,
            "health": health, "recovery_health": recovered, "events": events + ["FAILED"]}
    except Exception:
        return {"status": "MANUAL_INTERVENTION", "recovery": "unverified", "reason": "AUTHORITY_IMAGE_OR_RECOVERY_UNVERIFIED", "events": events + ["MANUAL_INTERVENTION"]}
