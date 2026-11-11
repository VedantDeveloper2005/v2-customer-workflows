// Verify the V2 approval envelopes before Python compares the rehearsal inputs.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const keyIdPattern = /^[a-f0-9]{64}$/;
const domain = Buffer.from("v2.customer-approval.v1\0");
const prefix = Buffer.from("302a300506032b6570032100", "hex");
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const hash = value => createHash("sha256").update(value).digest("hex");

function require(condition) {
  if (!condition) throw new Error();
}

function canonical(value) {
  if (typeof value === "number") require(Number.isSafeInteger(value));
  if (Array.isArray(value)) return value.map(canonical);
  if (object(value)) return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}

function base64(value, length) {
  require(typeof value === "string");
  const raw = Buffer.from(value, "base64");
  require(raw.length === length && raw.toString("base64") === value);
  return raw;
}

try {
  const proofBytes = readFileSync(process.argv[2]);
  const keyBytes = readFileSync(process.argv[3]);
  require(proofBytes.length <= 131072 && keyBytes.length <= 8192);
  const proofs = JSON.parse(proofBytes);
  const keys = JSON.parse(keyBytes);
  require(object(keys) && Object.keys(keys).length >= 1 && Object.keys(keys).length <= 8);
  const trusted = new Map(Object.entries(keys).map(([keyId, encoded]) => {
    const raw = base64(encoded, 32);
    require(keyIdPattern.test(keyId) && hash(raw) === keyId);
    return [keyId, createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" })];
  }));

  require(object(proofs) && [2, 3, 5].includes(Object.keys(proofs).length));
  for (const envelope of Object.values(proofs)) {
    require(object(envelope) && Object.keys(envelope).sort().join(",") === "algorithm,key_id,payload,sha256,signature");
    const { algorithm, key_id: keyId, payload, sha256, signature } = envelope;
    require(algorithm === "Ed25519" && object(payload) && trusted.has(keyId) && payload.key_id === keyId);
    const encoded = Buffer.from(JSON.stringify(canonical(payload)));
    require(hash(encoded) === sha256 && verify(null, Buffer.concat([domain, encoded]), trusted.get(keyId), base64(signature, 64)));
  }
  process.stdout.write("verified\n");
} catch {
  process.stderr.write("Conditional release signatures rejected.\n");
  process.exitCode = 1;
}
