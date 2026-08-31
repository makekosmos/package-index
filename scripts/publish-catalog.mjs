#!/usr/bin/env node
import { createHash, createPublicKey } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { loadBom, validateBom } from "./validate-bom.mjs";
import { validateCatalog } from "./validate-catalog-input.mjs";

function fail(message) {
  throw new Error(`publication: ${message}`);
}

function object(value) {
  return value && Object.prototype.toString.call(value) === "[object Object]";
}

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function publicKeyFromRawBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) fail("previous catalog public key is invalid");
  const raw = Buffer.from(value, "base64");
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });
}

export async function verifyPreviousPublication({ catalogPath, envelopePath, signaturesPath, publicKey, expectedSequence, engineApiVersion, signingKeyId }) {
  const catalogBytes = await readFile(catalogPath).catch(() => fail("previous catalog is missing"));
  const envelope = JSON.parse(await readFile(envelopePath, "utf8").catch(() => fail("previous catalog envelope is missing")));
  const signatures = JSON.parse(await readFile(signaturesPath, "utf8").catch(() => fail("previous catalog signatures are missing")));
  if (!object(signatures) || signatures.schema_version !== 1 || !Array.isArray(signatures.signatures) ||
      !isDeepStrictEqual(envelope.signatures, signatures)) fail("previous catalog envelope/signatures mismatch");
  const signatureSet = signatures.signatures;
  if (new Set(signatureSet.map((item) => item?.key_id)).size !== signatureSet.length ||
      signatureSet.some((item) => item?.key_id !== signingKeyId)) fail("previous catalog has an unexpected signing key");
  const key = publicKeyFromRawBase64(publicKey);
  // Verify the exact downloaded bytes before parsing or carrying any entries forward.
  const { verifyEnvelope } = await import("./validate-catalog-input.mjs");
  verifyEnvelope(catalogBytes, envelope, key);
  const catalog = JSON.parse(catalogBytes.toString("utf8"));
  if (catalog.sequence !== Number(expectedSequence)) fail("previous catalog sequence mismatch");
  validateCatalog(catalog, { previousSequence: Number(expectedSequence) - 1, engineApiVersion });
  const expectedHash = hash(catalogBytes);
  if (envelope.payload_sha256 && envelope.payload_sha256 !== expectedHash) fail("previous catalog payload hash mismatch");
  return catalog;
}

const MAX_ENTRIES = 512;
const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 128 * 1024 * 1024;
const MAX_COMPRESSION_RATIO = 100;

function safeArchivePath(name, label) {
  if (typeof name !== "string" || !name || name.includes("\\") || name.includes("\0") ||
      name.startsWith("/") || /^[A-Za-z]:/.test(name) || name.includes(":")) {
    fail(`${label} must be a safe relative POSIX path`);
  }
  const parts = name.split("/");
  if (parts.some((part) => !part || part === "." || part === ".." ||
      /^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(part))) {
    fail(`${label} contains an unsafe Windows path component`);
  }
  return name;
}

function zipCentralDirectory(bytes, provider) {
  const start = Math.max(0, bytes.length - 65557);
  let eocd = -1;
  for (let offset = Math.max(0, bytes.length - 22); offset >= start; offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) { eocd = offset; break; }
  }
  if (eocd < 0) fail(`${provider}: ZIP end-of-central-directory is missing`);
  const count = bytes.readUInt16LE(eocd + 10);
  const directorySize = bytes.readUInt32LE(eocd + 12);
  const directoryOffset = bytes.readUInt32LE(eocd + 16);
  if (count > MAX_ENTRIES || directorySize === 0xffffffff || directoryOffset === 0xffffffff ||
      directoryOffset + directorySize > eocd) fail(`${provider}: ZIP entry count/central directory is invalid`);
  const entries = [];
  let offset = directoryOffset;
  let total = 0;
  const names = new Set();
  for (let index = 0; index < count; index += 1) {
    if (offset + 46 > bytes.length || bytes.readUInt32LE(offset) !== 0x02014b50) fail(`${provider}: malformed ZIP central directory`);
    const compressedSize = bytes.readUInt32LE(offset + 20);
    const uncompressedSize = bytes.readUInt32LE(offset + 24);
    const generalPurposeFlags = bytes.readUInt16LE(offset + 8);
    const nameLength = bytes.readUInt16LE(offset + 28);
    const extraLength = bytes.readUInt16LE(offset + 30);
    const commentLength = bytes.readUInt16LE(offset + 32);
    const externalAttributes = bytes.readUInt32LE(offset + 38);
    const localOffset = bytes.readUInt32LE(offset + 42);
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || uncompressedSize > MAX_ENTRY_BYTES ||
        compressedSize > MAX_ENTRY_BYTES || localOffset >= bytes.length) fail(`${provider}: ZIP entry size/offset is invalid`);
    const end = offset + 46 + nameLength + extraLength + commentLength;
    if (end > bytes.length) fail(`${provider}: ZIP central directory entry is truncated`);
    const name = bytes.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    const isDir = name.endsWith("/");
    safeArchivePath(isDir ? name.slice(0, -1) : name, `${provider} archive entry`);
    const collision = (isDir ? name.slice(0, -1) : name).normalize("NFKC").toLocaleLowerCase("en-US");
    if (names.has(collision)) fail(`${provider}: ZIP entry names collide case-insensitively`);
    names.add(collision);
    const mode = (externalAttributes >>> 16) & 0xffff;
    if ((generalPurposeFlags & 0x1) !== 0) fail(`${provider}: encrypted ZIP entries are forbidden`);
    if ((externalAttributes & 0x400) !== 0) fail(`${provider}: ZIP reparse-point entries are forbidden`);
    const dosDirectory = (externalAttributes & 0x10) !== 0;
    if (isDir ? (compressedSize !== 0 || uncompressedSize !== 0 ||
        (mode !== 0 && (mode & 0xf000) !== 0x4000)) : (dosDirectory ||
        (mode !== 0 && (mode & 0xf000) !== 0x8000))) fail(`${provider}: invalid ZIP file type`);
    if (compressedSize === 0 && uncompressedSize > 0 ||
        compressedSize > 0 && uncompressedSize / compressedSize > MAX_COMPRESSION_RATIO) {
      fail(`${provider}: ZIP compression ratio is unsafe`);
    }
    total += uncompressedSize;
    if (total > MAX_TOTAL_BYTES) fail(`${provider}: ZIP uncompressed size is too large`);
    entries.push({ name, compressedSize, uncompressedSize, isDir });
    offset = end;
  }
  if (entries.length === 0) fail(`${provider}: ZIP has no entries`);
  return entries;
}

function verifyPePlatform(data, spec, provider) {
  if (!/\.exe$/i.test(spec.entrypoint)) return;
  if (data.length < 64 || data.subarray(0, 2).toString("ascii") !== "MZ") fail(`${provider}: worker is not a PE executable`);
  const peOffset = data.readUInt32LE(0x3c);
  if (peOffset + 6 > data.length || data.readUInt32LE(peOffset) !== 0x00004550 || data.readUInt16LE(peOffset + 4) !== 0x8664) {
    fail(`${provider}: worker is not an x86_64 Windows PE executable`);
  }
}

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!flag.startsWith("--") || i + 1 >= argv.length || argv[i + 1].startsWith("--")) fail(`missing value for ${flag}`);
    args[flag.slice(2)] = argv[++i];
  }
  for (const name of ["bom", "previous-catalog", "previous-envelope", "previous-signatures", "artifacts-dir", "source-catalog", "cortex", "sequence", "issued-at", "expires-at", "out"]) {
    if (!args[name]) fail(`required argument --${name}`);
  }
  return args;
}

function requiredManifest(manifest, spec, provider) {
  if (!object(manifest) || manifest.schema_version !== 2 || manifest.id !== spec.manifest_id ||
      manifest.version !== spec.version || manifest.kind !== spec.kind || manifest.engine_api !== spec.engine_api ||
      manifest.entrypoint !== spec.entrypoint || manifest.icon !== spec.icon || manifest.publisher !== "kosmos" ||
      typeof manifest.name !== "string" || !manifest.name || !Array.isArray(manifest.permissions) ||
      !Array.isArray(manifest.targets) || manifest.targets.length === 0 || !object(manifest.data) ||
      !Array.isArray(manifest.data.access) || !Array.isArray(manifest.data.defines) || !Array.isArray(manifest.data.mappings)) {
    fail(`${provider}: archive manifest does not match the reviewed BOM contract`);
  }
  const runtime = spec.kind === "app" ? "kosmos-host" : "worker";
  if (!manifest.targets.some((target) => target?.runtime === runtime && Array.isArray(target.os) && target.os.includes("windows"))) {
    fail(`${provider}: archive manifest has no Windows ${runtime} target`);
  }
  return manifest;
}

export function buildCatalogInput(previous, replacements, metadata) {
  if (!object(previous) || !Array.isArray(previous.packages)) fail("previous catalog packages are required");
  const previousIds = new Set();
  for (const entry of previous.packages) {
    const id = entry?.manifest?.id;
    if (typeof id !== "string" || previousIds.has(id)) fail("previous catalog has duplicate or missing package IDs");
    previousIds.add(id);
  }
  const retired = new Set(metadata.retiredPackageIds);
  for (const id of retired) if (!previousIds.has(id)) fail(`retired package ID is not present in the previous catalog: ${id}`);
  const activeIds = new Set(replacements.map((entry) => entry.manifest.id));
  if ([...activeIds].some((id) => retired.has(id))) fail("a package cannot be both active and retired");
  const replaced = new Set([...retired, ...activeIds]);
  const packages = [...previous.packages.filter((entry) => !replaced.has(entry.manifest.id)), ...replacements];
  const catalog = {
    schema_version: 1,
    sequence: metadata.sequence,
    issued_at: metadata.issuedAt,
    expires_at: metadata.expiresAt,
    packages,
  };
  validateCatalog(catalog, { previousSequence: metadata.sequence - 1, engineApiVersion: metadata.engineApiVersion });
  return catalog;
}

export async function inspectArchive(spec, archivePath, zipUtils, sequence) {
  const bytes = await readFile(archivePath).catch(() => fail(`${spec.id}: archive is missing: ${spec.artifact.name}`));
  if (spec.artifact.size !== undefined && bytes.length !== spec.artifact.size) fail(`${spec.id}: archive size mismatch`);
  if (spec.artifact.sha256 !== undefined && hash(bytes) !== spec.artifact.sha256.toLowerCase()) fail(`${spec.id}: archive SHA-256 mismatch`);
  const central = zipCentralDirectory(bytes, spec.id);
  safeArchivePath(spec.entrypoint, `${spec.id}.entrypoint`);
  safeArchivePath(spec.icon, `${spec.id}.icon`);
  let entries;
  try { entries = zipUtils.readZip(archivePath); } catch (error) { fail(`${spec.id}: invalid ZIP archive: ${error.message}`); }
  const files = entries.filter((entry) => !entry.isDir);
  if (entries.length !== central.length) fail(`${spec.id}: ZIP directory views disagree`);
  for (const entry of central) {
    const decoded = files.find((candidate) => candidate.name === entry.name);
    if (entry.isDir) continue;
    if (!decoded || decoded.data.length !== entry.uncompressedSize) fail(`${spec.id}: ZIP uncompressed size mismatch`);
  }
  const manifestEntry = files.find((entry) => entry.name === "manifest.json");
  if (!manifestEntry) fail(`${spec.id}: archive manifest.json is missing`);
  let manifest;
  try { manifest = JSON.parse(manifestEntry.data.toString("utf8")); } catch { fail(`${spec.id}: archive manifest.json is invalid JSON`); }
  requiredManifest(manifest, spec, spec.build?.provider ?? spec.id);
  const licenseEntry = files.find((entry) => /^license(?:[._-].*)?$/i.test(path.posix.basename(entry.name)));
  const expected = ["manifest.json", spec.entrypoint, spec.icon, ...(licenseEntry ? [licenseEntry.name] : [])].sort();
  const actual = files.map((entry) => entry.name).sort();
  if (spec.kind === "app" ? (expected.some((name) => !actual.includes(name)) ||
      actual.some((name) => !expected.includes(name) && !name.startsWith("dist/"))) :
      JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${spec.id}: archive contains unexpected files`);
  if (files.some((entry) => /\.(?:exe|dll|sys|scr|com)$/i.test(entry.name) && entry.name !== spec.entrypoint)) {
    fail(`${spec.id}: unexpected executable or Windows binary in archive`);
  }
  const worker = files.find((entry) => entry.name === spec.entrypoint);
  verifyPePlatform(worker.data, spec, spec.id);
  return {
    manifest,
    archive_url: (spec.artifact.url_template ?? spec.artifact.url).replace("{sequence}", String(sequence)),
    sha256: hash(bytes),
    size: bytes.length,
  };
}

export async function preparePublication({ bomPath, previousCatalogPath, previousEnvelopePath, previousSignaturesPath, artifactsDir, sourceCatalogPath, cortexPath, sequence, issuedAt, expiresAt, outDir }) {
  const bom = await loadBom(bomPath, { expectedSequence: sequence, allowPendingBuilds: true });
  const sourceCatalog = JSON.parse(await readFile(sourceCatalogPath, "utf8"));
  const sourceIds = new Set(bom.packages.filter((entry) => entry.kind === "source").map((entry) => entry.id));
  const sourceCatalogIds = new Set(sourceCatalog?.packages?.map((entry) => entry?.manifest?.id));
  if (!object(sourceCatalog) || sourceCatalog.bom_id !== bom.id || !Array.isArray(sourceCatalog.packages) ||
      sourceCatalog.packages.length !== sourceIds.size || sourceCatalogIds.size !== sourceIds.size ||
      sourceCatalog.packages.some((entry) => !sourceIds.has(entry?.manifest?.id))) {
    fail("source package catalog does not match the reviewed BOM");
  }
  const zipUtils = await import(pathToFileURL(path.join(path.resolve(cortexPath), "desktop", "scripts", "zip-utils.mjs")).href);
  const resolvedEntries = [];
  for (const spec of bom.packages) {
    const inspected = await inspectArchive(spec, path.join(path.resolve(artifactsDir), spec.artifact.name), zipUtils, sequence);
    resolvedEntries.push({ ...spec, _manifest: inspected.manifest, artifact: {
      name: spec.artifact.name,
      url: inspected.archive_url,
      sha256: inspected.sha256,
      size: inspected.size,
    }});
  }
  const resolvedBom = { ...bom, state: "resolved", packages: resolvedEntries };
  validateBom(resolvedBom, { expectedSequence: sequence });
  const previous = await verifyPreviousPublication({
    catalogPath: previousCatalogPath,
    envelopePath: previousEnvelopePath,
    signaturesPath: previousSignaturesPath,
    publicKey: bom.catalog.public_key,
    expectedSequence: Number(sequence) - 1,
    engineApiVersion: bom.compatibility.engine_api,
    signingKeyId: bom.catalog.signing_key_id,
  });
  const replacements = resolvedEntries.map((entry) => ({
    manifest: entry._manifest,
    archive_url: entry.artifact.url,
    sha256: entry.artifact.sha256,
    size: entry.artifact.size,
  }));
  // Keep manifests from the inspected archives in the catalog, never from BOM text.
  for (const entry of resolvedEntries) delete entry._manifest;
  const catalog = buildCatalogInput(previous, replacements, {
    sequence: Number(sequence),
    issuedAt,
    expiresAt,
    retiredPackageIds: bom.retired_package_ids,
    engineApiVersion: bom.compatibility.engine_api,
  });
  await writeFile(path.join(outDir, "release-bom.v1.json"), `${JSON.stringify(resolvedBom, null, 2)}\n`);
  await writeFile(path.join(outDir, "catalog.input.json"), `${JSON.stringify(catalog, null, 2)}\n`);
  return { bom: resolvedBom, catalog };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = parseArgs(process.argv);
  preparePublication({
    bomPath: args.bom,
    previousCatalogPath: args["previous-catalog"],
    previousEnvelopePath: args["previous-envelope"],
    previousSignaturesPath: args["previous-signatures"],
    artifactsDir: args["artifacts-dir"],
    sourceCatalogPath: args["source-catalog"],
    cortexPath: args.cortex,
    sequence: args.sequence,
    issuedAt: args["issued-at"],
    expiresAt: args["expires-at"],
    outDir: path.resolve(args.out),
  }).then(() => console.log(`Prepared catalog input for sequence ${args.sequence}.`)).catch((error) => {
    console.error(`[publication] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}
