import { execFile } from "node:child_process";
import { mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { callbackFactory, canonical, checkedGrant, jsonRequest, requireCondition, sha } from "./automation_transport.mjs";

const arm = "https://management.azure.com";
const apiApp = "2024-03-01";
const apiStack = "2025-07-01";
const hash = /^[a-f0-9]{64}$/;
const appName = /^v2-pr-[a-f0-9]{24}$/;
const armScope = /^\/subscriptions\/([a-f0-9-]{36})\/resourceGroups\/([a-z0-9_.()-]{1,90})$/i;
const equalsId = (one, two) => typeof one === "string" && typeof two === "string" && one.toLowerCase() === two.toLowerCase();
const command = promisify(execFile);

function scopeOf(plan) {
  const match = armScope.exec(plan.target.scope);
  requireCondition(match, "The preview resource group is invalid.");
  return { subscription: match[1], group: match[2] };
}

export function resourceTags(plan) {
  return { "v2-preview-workspace": plan.workspace_id, "v2-preview-reservation": plan.preview_id, "v2-preview-plan": plan.request_id };
}

export function buildTemplate(plan) {
  const cfg = plan.target;
  return {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    contentVersion: "1.0.0.0",
    resources: [{
      type: "Microsoft.App/containerApps", apiVersion: apiApp, name: cfg.name, location: cfg.location,
      tags: resourceTags(plan),
      properties: {
        managedEnvironmentId: cfg.environment_id,
        configuration: { activeRevisionsMode: "Single", ingress: {
          external: true, allowInsecure: false, targetPort: cfg.port, transport: "auto",
        } },
        template: { containers: [{ name: "preview", image: cfg.image, resources: { cpu: 0.25, memory: "0.5Gi" },
          probes: [{ type: "Readiness", httpGet: { path: cfg.health_path, port: cfg.port, scheme: "HTTP" },
            periodSeconds: 5, failureThreshold: 6 }] }],
          scale: { minReplicas: 0, maxReplicas: 1 },
        },
      },
    }],
  };
}

function rawCanonical(value) {
  if (Array.isArray(value)) return value.map(rawCanonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, rawCanonical(value[key])]));
  return value;
}

export function whatIfDigest(result, resourceId) {
  const changes = result?.changes;
  requireCondition(Array.isArray(changes) && changes.length > 0 && !result.error
    && (!result.status || result.status === "Succeeded"), "Azure did not complete the preview what-if.");
  const actual = changes.filter((item) => equalsId(item.resourceId, resourceId));
  requireCondition(actual.length === 1 && actual[0].changeType === "Create"
    && changes.every((item) => item === actual[0] || item.changeType === "Ignore" || item.changeType === "NoChange"),
  "Azure what-if includes changes outside the exact new preview.");
  const normalized = { ...result, changes: [...changes].sort((a, b) => String(a.resourceId).localeCompare(String(b.resourceId))) };
  return sha(JSON.stringify(rawCanonical(normalized)));
}

export function verifyBoundGrant(plan, env, id, digest) {
  scopeOf(plan);
  const cfg = plan.target;
  const owner = env.GITHUB_REPOSITORY.split("/")[0].toLowerCase();
  requireCondition(plan.repository === env.GITHUB_REPOSITORY && plan.workspace_id === env.V2_WORKSPACE_ID
    && plan.request_id === id && plan.request_sha256 === digest
    && plan.actor === `github:${env.GITHUB_REPOSITORY_ID}:${env.GITHUB_RUN_ID}:${env.GITHUB_RUN_ATTEMPT}`
    && /^[a-f0-9]{40}$/.test(plan.head_sha) && Number.isSafeInteger(plan.pull_request) && plan.pull_request >= 1
    && appName.test(cfg.name) && /^[a-z0-9]+$/.test(cfg.location)
    && cfg.name === `v2-pr-${plan.preview_id.replaceAll("-", "").slice(0, 24)}`
    && equalsId(cfg.resource_id, `${cfg.scope}/providers/Microsoft.App/containerApps/${cfg.name}`)
    && equalsId(cfg.stack_id, `${cfg.scope}/providers/Microsoft.Resources/deploymentStacks/${cfg.name}`)
    && cfg.environment_id.toLowerCase().startsWith(`${cfg.scope}/providers/Microsoft.App/managedEnvironments/`.toLowerCase())
    && /^[a-zA-Z0-9][a-zA-Z0-9-]{0,58}[a-zA-Z0-9]$/.test(cfg.environment_id.split("/").at(-1))
    && cfg.image.startsWith(`ghcr.io/${owner}/`) && /^ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9_.-]+@sha256:[a-f0-9]{64}$/.test(cfg.image)
    && Number.isInteger(cfg.port) && cfg.port >= 1 && cfg.port <= 65535 && /^\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]*$/.test(cfg.health_path)
    && sha(JSON.stringify(canonical(cfg))) === plan.target_sha256, "Preview grant scope differs.");
}

export function verifyOwnedStack(plan, stack, app) {
  const tags = resourceTags(plan);
  const resources = stack?.properties?.resources;
  requireCondition(equalsId(stack?.id, plan.target.stack_id)
    && Object.entries(tags).every(([key, value]) => stack.tags?.[key] === value)
    && Array.isArray(resources) && resources.length === 1 && equalsId(resources[0].id, plan.target.resource_id)
    && String(resources[0].status).toLowerCase() === "managed", "The Azure stack does not exclusively manage this preview.");
  if (app) {
    requireCondition(equalsId(app.id, plan.target.resource_id)
      && Object.entries(tags).every(([key, value]) => app.tags?.[key] === value)
      && equalsId(app.properties?.managedEnvironmentId, plan.target.environment_id)
      && app.properties?.template?.containers?.length === 1 && app.properties.template.containers[0].image === plan.target.image,
    "The Azure app does not match the reviewed preview.");
  }
}

export function verifyProvisioning(plan, stack, app) {
  requireCondition(String(app?.properties?.provisioningState).toLowerCase() === "succeeded"
    && String(stack?.properties?.provisioningState).toLowerCase() === "succeeded", "Azure provisioning did not succeed.");
  verifyOwnedStack(plan, stack, app);
}

async function azure(args, timeout = 180000) {
  const { stdout } = await command("az", [...args, "--only-show-errors", "--output", "json"],
    { encoding: "utf8", timeout, maxBuffer: 2 ** 20 });
  return stdout.trim() ? JSON.parse(stdout) : null;
}

function armClient(account, subscription) {
  requireCondition(account.subscription?.toLowerCase() === subscription.toLowerCase(), "Azure returned another subscription.");
  return async (id, version) => {
    const response = await jsonRequest(`${arm}${id}?api-version=${version}`,
      { headers: { Authorization: `Bearer ${account.accessToken}` } }, [200, 404]);
    if (response.status === 200) requireCondition(equalsId(response.data?.id, id), "Azure returned another resource.");
    return response.status === 404 ? null : response.data;
  };
}

async function azureReader(plan) {
  const { subscription } = scopeOf(plan);
  const account = await azure(["account", "get-access-token", "--subscription", subscription, "--resource", arm + "/"]);
  return armClient(account, subscription);
}

async function verifyDedicatedGroup(plan, read) {
  const group = await read(plan.target.scope, "2022-09-01");
  requireCondition(group?.tags?.["v2-preview-workspace"] === plan.workspace_id, "Azure resource group is not dedicated to this V2 workspace's previews.");
}

async function healthCheck(plan, read) {
  const { target } = plan;
  const environment = await read(target.environment_id, apiApp);
  const domain = environment?.properties?.defaultDomain;
  requireCondition(typeof domain === "string" && /^[a-z0-9.-]+\.azurecontainerapps\.io$/.test(domain),
    "The preview environment has no verified Azure ingress domain.");
  const hostname = `${target.name}.${domain}`;
  // Apply, health probes, and synthetic checks can complete on different timelines.
  for (let attempt = 0; attempt < 15; attempt++) {
    const app = await read(target.resource_id, apiApp);
    const revision = app?.properties?.latestRevisionName;
    if (app?.properties?.configuration?.ingress?.fqdn === hostname && /^[a-z0-9-]+$/.test(revision ?? "")) {
      try {
        const response = await fetch(`https://${hostname}${target.health_path}`, { redirect: "error", signal: AbortSignal.timeout(8000) });
        await response.body?.cancel();
        const report = await read(`${target.resource_id}/revisions/${revision}`, apiApp);
        if (response.ok && String(report?.properties?.healthState).toLowerCase() === "healthy"
            && String(report?.properties?.runningState).toLowerCase() === "running"
            && app.properties.latestReadyRevisionName === revision) return hostname;
      } catch {
        // A newly provisioned app may still be starting.
      }
    }
    await delay(6000);
  }
  throw new Error("The preview failed independent workload checks.");
}

async function planning(plan, file, env, phase) {
  const { group, subscription } = scopeOf(plan);
  const read = await azureReader(plan);
  await verifyDedicatedGroup(plan, read);
  requireCondition(!(await read(plan.target.resource_id, apiApp)) && !(await read(plan.target.stack_id, apiStack)), "The preview identity already exists.");
  await verifyOpenPullRequest(plan, env);
  await command("gh", ["attestation", "verify", `oci://${plan.target.image}`, "--repo", plan.repository,
    "--source-digest", plan.head_sha, "--deny-self-hosted-runners"],
    { env: { ...env, GH_TOKEN: env.V2_GITHUB_TOKEN }, timeout: 45000 });
  writeFileSync(file, JSON.stringify(buildTemplate(plan)), { mode: 0o600 });
  const groupArgs = ["--subscription", subscription, "--resource-group", group];
  const digest = whatIfDigest(await azure(["deployment", "group", "what-if", ...groupArgs,
    "--name", plan.target.name, "--mode", "Incremental", "--template-file", file,
    "--validation-level", "ProviderNoRbac", "--no-pretty-print"]), plan.target.resource_id);
  if (phase === "plan") return { what_if_sha256: digest };
  requireCondition(digest === plan.what_if_sha256 && Date.parse(plan.expires_at) > Date.now(), "The Azure what-if changed or the preview grant expired.");
  await verifyOpenPullRequest(plan, env);
  requireCondition(!(await read(plan.target.stack_id, apiStack)) && !(await read(plan.target.resource_id, apiApp)), "The preview identity was taken.");
  requireCondition(Date.parse(plan.expires_at) > Date.now(), "The preview grant expired.");
  await azure(["stack", "group", "create", ...groupArgs, "--name", plan.target.name, "--template-file", file,
    "--deny-settings-mode", "none", "--action-on-unmanage", "detachAll", "--tags",
    ...Object.entries(resourceTags(plan)).map(([key, value]) => `${key}=${value}`)], 420000);
  const app = await read(plan.target.resource_id, apiApp);
  const stack = await read(plan.target.stack_id, apiStack);
  verifyProvisioning(plan, stack, app);
  return { outcome: "healthy", hostname: await healthCheck(plan, read) };
}

async function verifyOpenPullRequest(plan, env) {
  const { data } = await jsonRequest(`https://api.github.com/repos/${plan.repository}/pulls/${plan.pull_request}`, {
    headers: { Authorization: `Bearer ${env.V2_GITHUB_TOKEN}`, Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "V2" },
  }, [200], 2097152);
  requireCondition(data.state === "open" && data.head?.sha === plan.head_sha
    && String(data.head?.repo?.id) === env.GITHUB_REPOSITORY_ID, "The preview PR moved, closed, or belongs to another repository.");
}

async function cleanup(plan) {
  const read = await azureReader(plan);
  const { subscription } = scopeOf(plan);
  const app = await read(plan.target.resource_id, apiApp);
  const stack = await read(plan.target.stack_id, apiStack);
  if (!app && !stack) return;
  await verifyDedicatedGroup(plan, read);
  verifyOwnedStack(plan, stack, app);
  requireCondition(Date.parse(plan.expires_at) > Date.now(), "The preview cleanup grant expired.");
  await azure(["stack", "group", "delete", "--subscription", subscription, "--id", plan.target.stack_id,
    "--action-on-unmanage", "deleteResources", "--yes"], 360000);
  requireCondition(!(await read(plan.target.resource_id, apiApp)) && !(await read(plan.target.stack_id, apiStack)),
    "Azure has not confirmed removal of the preview and its stack.");
}

async function operate(env, id, request_sha256, phase) {
  requireCondition(hash.test(request_sha256), "Invalid preview request digest.");
  const post = callbackFactory({ ...env, V2_REQUEST_ID: id }, "/api/customer-preview-lifecycle");
  const selection = { operation: phase, request_sha256 };
  if (phase === "apply") {
    requireCondition(hash.test(env.V2_WHAT_IF_SHA256), "The reviewed Azure what-if digest is required.");
    selection.what_if_sha256 = env.V2_WHAT_IF_SHA256;
  }
  const { grant } = await post(selection);
  const plan = checkedGrant(grant, env.V2_PUBLIC_KEYS, `preview-${phase}`);
  verifyBoundGrant(plan, env, id, request_sha256);
  const envelope = { operation: `record-${phase}`, request_sha256, grant_sha256: grant.sha256 };
  if (phase === "cleanup") {
    await cleanup(plan);
    await post({ ...envelope, outcome: "removed" });
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), "v2-preview-"));
  const file = join(directory, "preview.json");
  try {
    let evidence;
    try {
      evidence = await planning(plan, file, env, phase);
    } catch (failure) {
      if (phase === "apply") await post({ ...envelope, outcome: "failed" });
      throw failure;
    }
    await post({ ...envelope, ...evidence });
  } finally {
    try {
      unlinkSync(file);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    rmdirSync(directory);
  }
}

async function run(env) {
  requireCondition(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY), "Invalid repository.");
  if (env.V2_OPERATION === "queue") {
    const post = callbackFactory({ ...env, V2_REQUEST_ID: env.V2_PROJECT_ID }, "/api/customer-preview-lifecycle");
    const { cleanup: expired, applications } = await post({ operation: "queue" });
    requireCondition(Array.isArray(expired) && expired.length <= 10 && Array.isArray(applications) && applications.length <= 3,
      "Invalid preview queue.");
    const results = await Promise.allSettled([
      ...expired.map(({ id, sha256 }) => operate(env, id, sha256, "cleanup")),
      ...applications.map(({ id, sha256, what_if_sha256 }) => operate({ ...env, V2_WHAT_IF_SHA256: what_if_sha256 }, id, sha256, "apply")),
    ]);
    requireCondition(results.every((result) => result.status === "fulfilled"), "Some previews still require provider work.");
    return;
  }
  requireCondition(["plan", "apply"].includes(env.V2_OPERATION), "Invalid preview workflow operation.");
  await operate(env, env.V2_REQUEST_ID, env.V2_REQUEST_SHA256, env.V2_OPERATION);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run(process.env).catch(() => { process.stderr.write("V2 could not complete verified preview lifecycle work. Check the V2 records and Azure scope.\n"); process.exitCode = 1; });
}
