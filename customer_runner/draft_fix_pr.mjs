import { pathToFileURL } from "node:url";
import { callbackFactory, checkedGrant, jsonRequest, requireCondition } from "./automation_transport.mjs";

export async function createDraft(grant, github, requestHash, env) {
  const ref = grant.head_branch;
  requireCondition(grant.repository === env.GITHUB_REPOSITORY && grant.repository_id === env.GITHUB_REPOSITORY_ID
    && grant.request_id === env.V2_REQUEST_ID && grant.request_sha256 === requestHash && grant.base_sha === env.GITHUB_SHA
    && grant.actor === `github:${env.GITHUB_REPOSITORY_ID}:${env.GITHUB_RUN_ID}:${env.GITHUB_RUN_ATTEMPT}`
    && /^[a-f0-9]{40}$/.test(grant.head_sha) && /^v2-reviewed-fixes\/[a-f0-9]{32}$/.test(ref), "Draft grant scope differs.");
  const pathRef = (branch) => branch.split("/").map(encodeURIComponent).join("/");
  const base = `/git/ref/heads/${pathRef(grant.base_branch)}`;
  requireCondition((await github("GET", base, [200])).data.object.sha === grant.base_sha, "The approved base advanced.");
  const head = `/git/ref/heads/${pathRef(ref)}`;
  const existing = await github("GET", head, [200, 404]);
  if (existing.status === 404) {
    requireCondition(Date.parse(grant.expires_at) > Date.now(), "The reviewed draft grant expired.");
    await github("POST", "/git/refs", [201, 422], { ref: `refs/heads/${ref}`, sha: grant.head_sha });
  }
  requireCondition((await github("GET", head, [200])).data.object.sha === grant.head_sha, "The fix branch has a different commit.");
  requireCondition((await github("GET", base, [200])).data.object.sha === grant.base_sha, "The approved base advanced before draft creation.");
  const matches = await github("GET", `/pulls?state=all&head=${encodeURIComponent(`${grant.repository.split("/")[0]}:${ref}`)}&per_page=5`, [200]);
  requireCondition(Array.isArray(matches.data) && matches.data.length <= 1, "Conflicting draft requests found.");
  requireCondition(Date.parse(grant.expires_at) > Date.now(), "The reviewed draft grant expired.");
  const candidate = matches.data[0] ?? (await github("POST", "/pulls", [201], {
    head: ref, base: grant.base_branch, title: grant.title, draft: true,
    body: `Reviewed V2 incident fix. Workspace request ${grant.request_id}.`, maintainer_can_modify: false,
  })).data;
  requireCondition(Number.isSafeInteger(candidate.number) && candidate.number > 0, "Missing draft number.");
  const verified = (await github("GET", `/pulls/${candidate.number}`, [200])).data;
  requireCondition(verified.state === "open" && verified.draft === true && verified.head?.ref === ref
    && verified.head?.sha === grant.head_sha && verified.base?.ref === grant.base_branch && verified.base?.sha === grant.base_sha
    && String(verified.head?.repo?.id) === grant.repository_id && String(verified.base?.repo?.id) === grant.repository_id,
  "Draft readback differs from the approved commit or base.");
  return { number: candidate.number, head_sha: grant.head_sha };
}

async function operate(env) {
  requireCondition(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY) && /^[a-f0-9]{64}$/.test(env.V2_REQUEST_SHA256), "Invalid GitHub job scope.");
  const ghToken = env.V2_DRAFT_APP_CLIENT_ID ? env.V2_DRAFT_APP_TOKEN : env.V2_GITHUB_TOKEN;
  requireCondition(typeof ghToken === "string" && ghToken.length >= 20, "The selected GitHub draft credential is unavailable.");
  const post = callbackFactory(env, "/api/customer-fix-pr");
  const request_sha256 = env.V2_REQUEST_SHA256;
  const { grant } = await post({ operation: "start", request_sha256 });
  const reviewed = checkedGrant(grant, env.V2_PUBLIC_KEYS, "draft-fix-pr");
  const github = (method, path, allowed, data = undefined) => jsonRequest(`https://api.github.com/repos/${env.GITHUB_REPOSITORY}${path}`, {
    method, body: data === undefined ? undefined : JSON.stringify(data),
    headers: { Authorization: `Bearer ${ghToken}`, Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10", "Content-Type": "application/json", "User-Agent": "V2" },
  }, allowed);
  const review = await createDraft(reviewed, github, request_sha256, env);
  await post({ operation: "report", request_sha256, grant_sha256: grant.sha256, ...review });
}

export async function run(env) {
  if (env.GITHUB_EVENT_NAME === "schedule") {
    const post = callbackFactory({ ...env, V2_REQUEST_ID: env.V2_PROJECT_ID }, "/api/customer-fix-pr");
    const { requests } = await post({ operation: "queue" });
    requireCondition(Array.isArray(requests) && requests.length <= 5, "Invalid draft queue.");
    const results = await Promise.allSettled(requests.map(({ id, sha256 }) => operate({
      ...env, V2_REQUEST_ID: id, V2_REQUEST_SHA256: sha256,
    })));
    requireCondition(results.every((result) => result.status === "fulfilled"), "Some approved drafts could not be opened.");
  } else {
    await operate(env);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run(process.env).catch(() => { process.stderr.write("V2 could not verify the approved draft operation. Check the repository before retrying.\n"); process.exitCode = 1; });
}
