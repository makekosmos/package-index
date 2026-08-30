#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHA256 = /^[0-9a-f]{64}$/i;
const ISO_UTC = /^\d{4}-\d\d-\d\dT.*Z$/;

function version(value) {
  const match = String(value ?? "").match(SEMVER);
  return match ? match.slice(1, 4).map(Number) : null;
}

function compare(a, b) {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function satisfies(value, range) {
  if (!range) return true;
  const current = version(value);
  if (!current) return false;
  for (const part of String(range).trim().split(/\s+/)) {
    const match = part.match(/^(>=|<=|>|<|=)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/);
    if (!match) return false;
    const expected = version(match[2]);
    const result = compare(current, expected);
    const operator = match[1] || "=";
    if ((operator === "=" && result !== 0) || (operator === ">" && result <= 0) ||
        (operator === ">=" && result < 0) || (operator === "<" && result >= 0) ||
        (operator === "<=" && result > 0)) return false;
  }
  return true;
}

export function validateCatalog(catalog, {
  previousSequence = null,
  engineApiVersion = null,
} = {}) {
  if (!catalog || catalog.schema_version !== 1) throw new Error("catalog schema_version must be 1");
  if (!Number.isSafeInteger(catalog.sequence) || catalog.sequence < 1) throw new Error("catalog sequence must be a positive integer");
  if (previousSequence !== null && (!Number.isSafeInteger(previousSequence) || catalog.sequence <= previousSequence)) {
    throw new Error("catalog sequence must be greater than the previous sequence");
  }
  if (!ISO_UTC.test(catalog.issued_at || "") || !ISO_UTC.test(catalog.expires_at || "")) {
    throw new Error("catalog timestamps must be ISO UTC");
  }
  const issued = Date.parse(catalog.issued_at);
  const expires = Date.parse(catalog.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > 366 * 86400000) {
    throw new Error("catalog validity window is invalid");
  }
  if (!Array.isArray(catalog.packages) || catalog.packages.length === 0) throw new Error("catalog packages must be non-empty");
  const ids = new Set();
  for (const [index, entry] of catalog.packages.entries()) {
    const manifest = entry?.manifest;
    const prefix = `packages[${index}]`;
    if (!manifest || manifest.schema_version !== 2) throw new Error(`${prefix}: Manifest v2 is required`);
    if (typeof manifest.id !== "string" || !manifest.id || ids.has(manifest.id)) throw new Error(`${prefix}: duplicate or missing manifest id`);
    ids.add(manifest.id);
    if (!version(manifest.version)) throw new Error(`${prefix}: invalid semver`);
    if (!["app", "source"].includes(manifest.kind)) throw new Error(`${prefix}: invalid package kind`);
    if (manifest.kind === "app" && (typeof manifest.entrypoint !== "string" || !manifest.entrypoint.startsWith("dist/"))) {
      throw new Error(`${prefix}: app entrypoint must be under dist/`);
    }
    const engineRange = manifest.engine_api ?? manifest.engine_api_range;
    if (engineApiVersion && !satisfies(engineApiVersion, engineRange)) throw new Error(`${prefix}: Engine API range is incompatible`);
    if (typeof entry.archive_url !== "string" || !/^https:\/\//.test(entry.archive_url)) throw new Error(`${prefix}: archive_url must be HTTPS`);
    if (!SHA256.test(entry.sha256 || "")) throw new Error(`${prefix}: archive sha256 is invalid`);
    if (!Number.isSafeInteger(entry.size) || entry.size <= 0) throw new Error(`${prefix}: archive size is invalid`);
  }
  return true;
}

export function verifyEnvelope(catalogBytes, envelope, publicKey) {
  // Production Cortex envelopes carry the catalog bytes and a sorted signature set.
  if (envelope?.schema_version === 1 && typeof envelope.bytes === "string" && envelope.signatures) {
    const payload = Buffer.from(envelope.bytes, "base64");
    if (!payload.equals(catalogBytes)) throw new Error("envelope payload mismatch");
    const signatures = Array.isArray(envelope.signatures) ? envelope.signatures : envelope.signatures.signatures;
    if (!Array.isArray(signatures) || signatures.length === 0) throw new Error("envelope signature set is empty");
    for (const item of signatures) {
      const signature = Buffer.from(item?.signature || "", "base64");
      if (item?.algorithm !== "ed25519" || signature.length !== 64 || !crypto.verify(null, catalogBytes, publicKey, signature)) {
        throw new Error("envelope signature verification failed");
      }
    }
    return true;
  }
  if (!envelope || envelope.schema_version !== 1 || !Number.isSafeInteger(envelope.sequence)) {
    throw new Error("envelope metadata is invalid");
  }
  if (envelope.payload_sha256 !== crypto.createHash("sha256").update(catalogBytes).digest("hex")) {
    throw new Error("envelope payload hash mismatch");
  }
  const signature = Buffer.from(envelope.signature || "", "base64");
  if (signature.length !== 64) throw new Error("envelope signature is invalid");
  const key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  if (!crypto.verify(null, catalogBytes, key, signature)) throw new Error("envelope signature verification failed");
  return true;
}

async function main() {
  const fixture = path.resolve(process.argv[2] || "fixtures/catalog-input.json");
  const catalog = JSON.parse(await readFile(fixture, "utf8"));
  validateCatalog(catalog);
  console.log(`Validated catalog sequence ${catalog.sequence} with ${catalog.packages.length} package entries.`);
}

if (path.resolve(process.argv[1] || "") === fileURLToPath(import.meta.url)) main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
