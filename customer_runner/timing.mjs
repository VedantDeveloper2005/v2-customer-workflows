// Exact timing contract for newly issued plans; this never renews a signature.
import { createHash } from "node:crypto";
const ordered = value => Array.isArray(value) ? value.map(ordered) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, ordered(value[key])])) : value;
const digest = value => createHash("sha256").update(JSON.stringify(ordered(value))).digest("hex");
const check = value => { if (!value) throw new Error("Timing binding rejected"); };
export const POLICY = Object.freeze({ schema_version: "v2.customer-timing.v1", plan_ttl_seconds: 7200,
  evidence_ttl_seconds: 3600, compatibility_ttl_seconds: 3600, approval_ttl_seconds: 3600,
  hosting_max_age_seconds: 7200, operation_grant_seconds: 60, apply_timeout_seconds: 240,
  restore_timeout_seconds: 60, dispatch_floor_seconds: 600 });

export function policyFromManifest(manifest) {
  const snapshot = manifest.timing_policy;
  check(snapshot && Object.keys(snapshot).sort().join() === "contract,sha256" && digest(snapshot.contract) === snapshot.sha256 && digest(snapshot.contract) === digest(POLICY));
  check(manifest.execution_gate_version === "customer-execution.v2" && manifest.evidence_policy_version === "customer-evidence.v2");
  return POLICY;
}

export function verifyTiming(proofs) {
  const m = proofs.plan_manifest, policy = policyFromManifest(m), hash = m.timing_policy.sha256;
  const r = proofs.request.payload, a = proofs.approval_challenge.payload, d = proofs.decision.payload, e = proofs.evidence.payload;
  const now = Date.now(), planExpiry = Date.parse(m.expires_at);
  const interval = (value, began, max) => {
    const start = Date.parse(value[began]), end = Date.parse(value.expires_at);
    check(Number.isFinite(start) && Number.isFinite(end) && start <= now + 5000 && now < end && start < end && end - start <= max * 1000 && end <= planExpiry);
  };
  for (const value of [r, a, d, e]) check(value.timing_policy_sha256 === hash);
  check(a.binding.timing_policy_sha256 === hash && a.binding.policy.version === "v2.customer-approval-policy.v3" && a.binding.policy.ttl_seconds === policy.approval_ttl_seconds);
  check(e.schema_version === "v2.customer-evidence.v2" && d.timing_policy_acknowledged === true && d.expires_at === a.expires_at);
  interval(e, "captured_at", policy.evidence_ttl_seconds);
  interval(a, "issued_at", policy.approval_ttl_seconds);
  interval(d, "decided_at", policy.approval_ttl_seconds);
  check(Date.parse(a.expires_at) <= Date.parse(e.expires_at) && Date.parse(a.issued_at) >= Date.parse(e.captured_at) && Date.parse(d.decided_at) >= Date.parse(a.issued_at));
  const hosting = proofs.plan_report.hosting;
  check(hosting && Number.isFinite(Date.parse(hosting.captured_at)) && Date.parse(hosting.captured_at) <= now + 120000 && now - Date.parse(hosting.captured_at) <= policy.hosting_max_age_seconds * 1000 && Date.parse(e.expires_at) <= Date.parse(hosting.captured_at) + policy.hosting_max_age_seconds * 1000);
  if (m.mode === "app-service-update-plan") {
    const c = a.binding.release_authorization.compatibility.payload;
    check(c.timing_policy_acknowledged === true && c.timing_policy_sha256 === hash);
    interval(c, "issued_at", policy.compatibility_ttl_seconds);
    check(Date.parse(a.expires_at) <= Date.parse(c.expires_at) && Date.parse(c.expires_at) <= Date.parse(e.expires_at));
  }
  if (proofs.authorization) check(proofs.authorization.payload.timing_policy_sha256 === hash);
  return policy;
}
