// Offline verification using Node's built-in Ed25519 implementation only.
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";
import { verifyTiming } from "./timing.mjs";

const canonical = value => {
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error();
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
};
const bytes = value => Buffer.from(JSON.stringify(canonical(value)));
const sha = value => createHash("sha256").update(value).digest("hex");
const digest = value => sha(bytes(value));
const check = condition => { if (!condition) throw new Error(); };

try {
  const proofsRaw = readFileSync(process.argv[2]);
  const keysRaw = readFileSync(process.argv[3]);
  check(proofsRaw.length <= 131072 && keysRaw.length <= 8192);
  const proofs = JSON.parse(proofsRaw), trusted = JSON.parse(keysRaw);
  check(Object.keys(trusted).length >= 1 && Object.keys(trusted).length <= 8);
  function envelope(value) {
    check(value.algorithm === "Ed25519" && value.payload.key_id === value.key_id && digest(value.payload) === value.sha256);
    const raw = Buffer.from(trusted[value.key_id] || "", "base64");
    check(raw.length === 32 && sha(raw) === value.key_id);
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });
    const sig = Buffer.from(value.signature, "base64");
    check(sig.length === 64 && verify(null, Buffer.concat([Buffer.from("v2.customer-approval.v1\0"), bytes(value.payload)]), key, sig));
    return value.payload;
  }
  const r = envelope(proofs.request), a = envelope(proofs.approval_challenge), d = envelope(proofs.decision), e = envelope(proofs.evidence);
  const m = proofs.plan_manifest, p = proofs.plan_report;
  verifyTiming(proofs);
  check(r.kind === "customer-execution" && r.schema_version === "v2.customer-execution.v1" && r.mode === "app-service-saved-plan-update" && r.azure_writes === true);
  check(m.mode === "app-service-update-plan" && r.planning_client_id === m.input.planning_client_id && r.planning_principal_id === m.input.planning_principal_id);
  check(m.execution_gate_version === "customer-execution.v2" && r.execution_workflow_ref === m.execution_workflow_ref && r.environment === m.input.execution_environment);
  check(r.resource_id === `/subscriptions/${m.subscription_id}/resourceGroups/${m.resource_group}/providers/Microsoft.Web/sites/${m.input.app_name}`);
  check(r.candidate_image_sha256 === m.input.image_sha256 && r.previous_image_sha256 === m.baseline.attestation.payload.image_sha256);
  check(r.rollback_action_sha256 === a.binding.release_authorization.rollback_action.sha256);
  check(a.kind === "challenge" && d.kind === "decision" && e.kind === "customer-evidence" && d.decision === "approve");
  for (const value of [r, a, d, e]) {
    check(value.tenant_id === r.tenant_id && value.project_id === r.project_id && value.plan_id === r.plan_id);
    check(Number.isFinite(Date.parse(value.expires_at)) && Date.parse(value.expires_at) > Date.now());
  }
  check(Date.parse(r.expires_at) <= Date.parse(a.expires_at) && Date.parse(a.expires_at) <= Date.parse(e.expires_at) && Date.parse(a.expires_at) <= Date.parse(m.expires_at));
  check(r.tenant_id === m.workspace_id && r.project_id === m.project_id && r.plan_id === m.plan_id);
  check(r.plan_request_sha256 === digest(m) && r.report_sha256 === digest(p) && p.request_sha256 === r.plan_request_sha256);
  check(r.review_sha256 === digest({ request_sha256: r.plan_request_sha256, manifest: m, report: p }));
  check(r.artifact_set_sha256 === digest(p.artifacts));
  check(r.execution_request_sha256 === p.execution_request_sha256 && p.execution_request_sha256 === digest({ schema_version: "v2.execution-request.v1", request_sha256: r.plan_request_sha256, bundle_sha256: m.bundle_sha256, artifacts: p.artifacts }));
  check(r.approval_challenge_sha256 === proofs.approval_challenge.sha256 && r.decision_sha256 === proofs.decision.sha256 && r.evidence_sha256 === proofs.evidence.sha256);
  check(a.binding.request_sha256 === r.plan_request_sha256 && a.binding.review_sha256 === r.review_sha256 && a.binding.report_sha256 === r.report_sha256 && a.binding.execution_request_sha256 === r.execution_request_sha256);
  check(d.challenge_sha256 === proofs.approval_challenge.sha256 && d.review_sha256 === r.review_sha256 && d.execution_request_sha256 === r.execution_request_sha256);
  check(typeof d.actor_user_id === "string" && typeof a.requested_by === "string" && typeof m.created_by === "string" && d.actor_user_id !== a.requested_by && d.actor_user_id !== m.created_by && ["owner", "admin"].includes(d.actor_role));
  check(d.cost_scope_acknowledged === true && d.cost_scope_sha256 === e.cost.scope_sha256 && d.evidence_sha256 === proofs.evidence.sha256);
  check(a.binding.evidence.evidence_sha256 === proofs.evidence.sha256 && e.review_sha256 === r.review_sha256 && e.request_sha256 === r.plan_request_sha256);
  check(e.cost.status === "verified" && e.cost.scope === "app-service-fixed-compute" && e.cost.bill_total_status === "unknown" && e.image_provenance.status === "verified");
  const material = Object.fromEntries(Object.entries(e.cost).filter(([key]) => key !== "scope_sha256"));
  check(digest(material) === e.cost.scope_sha256);
  check(e.image_provenance.source_sha === m.source_sha && e.image_provenance.image_sha256 === m.input.image_sha256);
  check(r.source_sha === m.source_sha && r.repository === m.repository && r.repository_id === m.repository_id && r.repository_owner_id === m.repository_owner_id);
  check(r.write_control_generation === m.write_control_generation && r.trusted_keys_sha256 === digest(trusted));
  if (m.mode === "app-service-update-plan") {
    const release = a.binding.release_authorization;
    check(release.schema_version === "v2.release-authorization.v1" && d.release_authorization_sha256 === digest(release));
    const comp = envelope(release.compatibility), baseline = envelope(m.baseline.attestation);
    check(comp.kind === "database-compatibility" && comp.decision === "approve" && comp.method === "independent-source-review" && comp.automated_database_tests === "not-run");
    check(comp.tenant_id === m.workspace_id && comp.project_id === m.project_id && comp.plan_id === m.plan_id && Date.parse(comp.expires_at) > Date.now() && Date.parse(a.expires_at) <= Date.parse(comp.expires_at));
    check(comp.request_sha256 === digest(m) && comp.review_sha256 === r.review_sha256 && comp.execution_request_sha256 === r.execution_request_sha256 && comp.cost_image_evidence_sha256 === proofs.evidence.sha256);
    check(comp.baseline_sha256 === m.baseline.attestation.sha256 && comp.previous_image_sha256 === baseline.image_sha256 && comp.candidate_image_sha256 === m.input.image_sha256 && comp.source_sha === m.source_sha && comp.policy_sha256 === m.release_policy.sha256);
    check(comp.reviewed_by !== m.created_by && ["owner", "admin"].includes(comp.reviewer_role) && comp.source_reviewed === true && comp.no_database_changes === true && comp.both_images_compatible === true);
    check(baseline.kind === "known-good-release" && baseline.tenant_id === m.workspace_id && baseline.project_id === m.project_id && Date.parse(baseline.expires_at) > Date.now());
    const context = Object.fromEntries(Object.entries(m).filter(([key]) => key !== "rollback_action_sha256"));
    const action = { schema_version: "v2.image-rollback.v1", tenant_id: m.workspace_id, project_id: m.project_id, plan_id: m.plan_id,
      plan_context_sha256: digest(context), resource_id: `/subscriptions/${m.subscription_id}/resourceGroups/${m.resource_group}/providers/Microsoft.Web/sites/${m.input.app_name}`,
      candidate_image_sha256: m.input.image_sha256, restore_image_sha256: baseline.image_sha256, baseline_sha256: m.baseline.attestation.sha256,
      compatibility_sha256: release.compatibility.sha256, policy_sha256: m.release_policy.sha256, registry_name: m.input.registry_name, image_repository: m.input.image_repository };
    check(digest(release.rollback_action) === digest({ ...action, sha256: digest(action) }));
  }
  if (Object.hasOwn(proofs, "authorization")) {
    const grant = envelope(proofs.authorization);
    check(grant.kind === "customer-execution-authorization" && grant.execution_id === r.execution_id && grant.request_sha256 === proofs.request.sha256);
    check(grant.tenant_id === r.tenant_id && grant.project_id === r.project_id && grant.plan_id === r.plan_id);
    check(grant.artifact_set_sha256 === r.artifact_set_sha256 && grant.execution_request_sha256 === r.execution_request_sha256 && grant.rollback_action_sha256 === r.rollback_action_sha256);
    check(grant.resource_id === r.resource_id && grant.planning_client_id === r.planning_client_id && grant.planning_principal_id === r.planning_principal_id);
    check(grant.write_control_generation === r.write_control_generation && Number.isSafeInteger(grant.sequence) && grant.sequence > 0);
    check(["checkpoint", "apply", "rollback", "verify"].includes(grant.operation) && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(grant.operation_id));
    check(Number.isFinite(Date.parse(grant.issued_at)) && Number.isFinite(Date.parse(grant.expires_at)) && Date.parse(grant.issued_at) <= Date.now() + 5000 && Date.parse(grant.expires_at) > Date.now());
    check(Date.parse(grant.expires_at) <= Date.parse(r.expires_at) && Date.parse(grant.expires_at) - Date.parse(grant.issued_at) <= 60000);
  }
  process.stdout.write("verified\n");
} catch {
  process.stderr.write("Signed execution proofs rejected.\n");
  process.exitCode = 1;
}
