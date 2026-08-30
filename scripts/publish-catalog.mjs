#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
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

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!flag.startsWith("--") || i + 1 >= argv.length || argv[i + 1].startsWith("--")) fail(`missing value for ${flag}`);
    args[flag.slice(2)] = argv[++i];
  }
  for (const name of ["bom", "previous-catalog", "artifacts-dir", "source-catalog", "cortex", "sequence", "issued-at", "expires-at", "out"]) {
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
  if (!manifest.targets.some((target) => target?.runtime === "worker" && Array.isArray(target.os) && target.os.includes("windows"))) {
    fail(`${provider}: archive manifest has no Windows worker target`);
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
  let entries;
  try { entries = zipUtils.readZip(archivePath); } catch (error) { fail(`${spec.id}: invalid ZIP archive: ${error.message}`); }
  const files = entries.filter((entry) => !entry.isDir);
  const manifestEntry = files.find((entry) => entry.name === "manifest.json");
  if (!manifestEntry) fail(`${spec.id}: archive manifest.json is missing`);
  let manifest;
  try { manifest = JSON.parse(manifestEntry.data.toString("utf8")); } catch { fail(`${spec.id}: archive manifest.json is invalid JSON`); }
  requiredManifest(manifest, spec, spec.build?.provider ?? spec.id);
  const expected = ["manifest.json", spec.entrypoint, spec.icon].sort();
  const actual = files.map((entry) => entry.name).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${spec.id}: archive contains unexpected files`);
  return {
    manifest,
    archive_url: (spec.artifact.url_template ?? spec.artifact.url).replace("{sequence}", String(sequence)),
    sha256: hash(bytes),
    size: bytes.length,
  };
}

export async function preparePublication({ bomPath, previousCatalogPath, artifactsDir, sourceCatalogPath, cortexPath, sequence, issuedAt, expiresAt, outDir }) {
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
  const previous = JSON.parse(await readFile(previousCatalogPath, "utf8"));
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
