#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHA256 = /^[0-9a-f]{64}$/i;
const ISO_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

// Date.parse silently normalizes nonexistent dates (e.g. February 30 rolls
// into March), so parse components and verify they round-trip exactly.
function parseIsoUtc(value) {
  const match = typeof value === "string" ? ISO_UTC.exec(value) : null;
  if (!match) return null;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const millis = match[7] ? Number(match[7].padEnd(3, "0")) : 0;
  const time = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  const date = new Date(time);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day ||
      date.getUTCHours() !== hour || date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second) {
    return null;
  }
  return time;
}

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
  const issued = parseIsoUtc(catalog.issued_at);
  const expires = parseIsoUtc(catalog.expires_at);
  if (issued === null || expires === null) {
    throw new Error("catalog timestamps must be ISO UTC");
  }
  if (expires <= issued || expires - issued > 366 * 86400000) {
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
    if (!["app", "source", "bridge"].includes(manifest.kind)) throw new Error(`${prefix}: invalid package kind`);
    if (entry.native !== undefined) {
      // Native app entries: kind app + v2 manifest whose entrypoint is the
      // exe inside the release zip, plus a signed `native` descriptor that
      // must agree with the manifest on version and executable.
      const native = entry.native;
      if (!native || typeof native !== "object" || Array.isArray(native)) throw new Error(`${prefix}: invalid native descriptor`);
      if (manifest.kind !== "app") throw new Error(`${prefix}: native entries must be app kind`);
      if (manifest.entrypoint !== native.executable) throw new Error(`${prefix}: native executable must equal manifest entrypoint`);
      if (typeof native.executable !== "string" || !/\.exe$/i.test(native.executable) || native.executable.includes("..") || native.executable.includes("\\")) {
        throw new Error(`${prefix}: native executable must be a safe .exe path`);
      }
      if (typeof native.repository !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(native.repository)) {
        throw new Error(`${prefix}: native repository is invalid`);
      }
      if (native.release_tag !== `v${manifest.version}`) throw new Error(`${prefix}: native release_tag must equal v<version>`);
      if (!["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"].includes(native.target)) {
        throw new Error(`${prefix}: native target is invalid`);
      }
      if (!Array.isArray(manifest.targets) || !manifest.targets.some((target) => target?.runtime === "standalone" && Array.isArray(target?.os) && target.os.includes("windows"))) {
        throw new Error(`${prefix}: native entries require a standalone windows target`);
      }
    } else if (manifest.kind === "app" && (typeof manifest.entrypoint !== "string" || !manifest.entrypoint.startsWith("dist/"))) {
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
  if (typeof envelope?.bytes === "string" && envelope.signatures) {
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
