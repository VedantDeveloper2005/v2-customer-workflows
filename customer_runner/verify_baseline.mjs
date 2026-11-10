// Offline request verification. Caller-pinned public keys are not API trust input.
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";
const canonical = value => {
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error();
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
};
const bytes = value => Buffer.from(JSON.stringify(canonical(value)));
const sha = value => createHash("sha256").update(value).digest("hex");
const check = value => { if (!value) throw new Error(); };
try {
  const raw = readFileSync(process.argv[2]), keysRaw = readFileSync(process.argv[3]);
  check(raw.length <= 131072 && keysRaw.length <= 8192);
  const e = JSON.parse(raw), keys = JSON.parse(keysRaw), p = e.payload;
  check(Object.keys(keys).length >= 1 && Object.keys(keys).length <= 8);
  check(e.algorithm === "Ed25519" && p.key_id === e.key_id && sha(bytes(p)) === e.sha256);
  const publicRaw = Buffer.from(keys[e.key_id] || "", "base64"), sig = Buffer.from(e.signature, "base64");
  check(publicRaw.length === 32 && sha(publicRaw) === e.key_id && sig.length === 64);
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicRaw]), format: "der", type: "spki" });
  check(verify(null, Buffer.concat([Buffer.from("v2.customer-approval.v1\0"), bytes(p)]), key, sig));
  check(p.kind === "baseline-request" && p.schema_version === "v2.baseline-request.v1" && p.mode === "read-only-baseline" && p.azure_writes === false);
  check(p.trusted_keys_sha256 === sha(bytes(keys)) && Date.parse(p.expires_at) > Date.now() && Date.parse(p.issued_at) <= Date.now() + 5000);
  check(p.release_policy.version > 0 && sha(bytes(p.release_policy.contract)) === p.release_policy.sha256 && p.release_policy.contract.schema_version === "v2.release-policy.v1");
  process.stdout.write("verified\n");
} catch { process.stderr.write("Signed baseline request rejected.\n"); process.exitCode = 1; }
