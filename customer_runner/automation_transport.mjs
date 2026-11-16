import { createHash, createPublicKey, verify } from "node:crypto";

const domain = Buffer.from("v2.customer-approval.v1\0");
const prefix = Buffer.from("302a300506032b6570032100", "hex");
export const sha = (value) => createHash("sha256").update(value).digest("hex");

export function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  if (typeof value === "number") requireCondition(Number.isSafeInteger(value), "Unsupported signed number.");
  return value;
}

function rawBase64(value, size) {
  const raw = Buffer.from(value, "base64");
  requireCondition(raw.length === size && raw.toString("base64") === value, "Invalid signing material.");
  return raw;
}

export function checkedGrant(grant, trustedSource, intent) {
  requireCondition(grant && grant.algorithm === "Ed25519" && grant.payload?.key_id === grant.key_id, "Invalid grant envelope.");
  requireCondition(typeof trustedSource === "string" && trustedSource.length <= 8192, "Invalid trust configuration.");
  const encoded = Buffer.from(JSON.stringify(canonical(grant.payload)));
  const key = rawBase64(JSON.parse(trustedSource)[grant.key_id], 32);
  requireCondition(sha(key) === grant.key_id && sha(encoded) === grant.sha256, "Grant digest differs.");
  requireCondition(verify(null, Buffer.concat([domain, encoded]),
    createPublicKey({ key: Buffer.concat([prefix, key]), type: "spki", format: "der" }), rawBase64(grant.signature, 64)), "Grant signature differs.");
  requireCondition(grant.payload.purpose === intent && Date.parse(grant.payload.expires_at) > Date.now(), "Grant is expired or for another purpose.");
  return grant.payload;
}

export async function jsonRequest(url, options, allowed, limit = 524288) {
  const response = await fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(20000) });
  requireCondition(allowed.includes(response.status), `Provider returned HTTP ${response.status}.`);
  const stream = response.body?.getReader();
  let size = 0;
  const chunks = [];
  if (stream) {
    for (;;) {
      const { done, value } = await stream.read();
      if (done) break;
      size += value.length;
      if (size > limit) {
        await stream.cancel();
        throw new Error("Provider response exceeds the verification limit.");
      }
      chunks.push(Buffer.from(value));
    }
  }
  return { status: response.status, data: chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null };
}

export function callbackFactory(env, prefixPath) {
  const origin = new URL(env.V2_API_ORIGIN);
  requireCondition(origin.protocol === "https:" && !origin.username && !origin.password && !origin.search
    && !origin.hash && origin.pathname === "/" && !origin.port, "Invalid V2 API origin.");
  const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
  requireCondition(uuid.test(env.V2_WORKSPACE_ID) && uuid.test(env.V2_REQUEST_ID), "Invalid request identity.");
  const path = `${prefixPath}/${env.V2_WORKSPACE_ID}/${env.V2_REQUEST_ID}`;
  const url = new URL(path, origin).href;
  return async (payload) => {
    const tokenURL = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
    requireCondition(tokenURL.protocol === "https:" && !tokenURL.username && !tokenURL.password, "Invalid GitHub OIDC service.");
    tokenURL.searchParams.set("audience", url);
    const { data: oidc } = await jsonRequest(tokenURL, { headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } }, [200]);
    const body = JSON.stringify(canonical(payload));
    const key = sha(`${env.GITHUB_RUN_ID}:${env.GITHUB_RUN_ATTEMPT}:${path}:${body}`);
    return (await jsonRequest(url, { method: "POST", body,
      headers: { Authorization: `Bearer ${oidc.value}`, "Content-Type": "application/json", "Idempotency-Key": key } }, [200])).data;
  };
}
