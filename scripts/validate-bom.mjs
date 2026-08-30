import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/i;
const SHA1 = /^[0-9a-f]{40}$/i;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function engineCompatible(requirement, current) {
  if (requirement === current) return true;
  const minimum = /^>=(\d+)\.(\d+)\.(\d+)$/.exec(requirement);
  if (!minimum) return false;
  const actual = current.split(".").map(Number);
  return actual[0] === Number(minimum[1]) &&
    (actual[1] > Number(minimum[2]) ||
      (actual[1] === Number(minimum[2]) && actual[2] >= Number(minimum[3])));
}

export function fail(message) {
  throw new Error(`BOM: ${message}`);
}

function object(value) {
  return value && Object.prototype.toString.call(value) === "[object Object]";
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} is required`);
  return value;
}

function immutableSha(value, label) {
  if (!SHA1.test(requiredString(value, label))) fail(`${label} must be a full immutable commit SHA`);
}

function rejectSecrets(value) {
  if (Array.isArray(value)) return value.forEach(rejectSecrets);
  if (!object(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (/private.?key|secret|token/i.test(key)) fail(`private material is forbidden: ${key}`);
    rejectSecrets(item);
  }
}

function artifact(spec, { allowPendingBuilds }) {
  if (!object(spec.artifact)) fail(`${spec.id}: artifact is required`);
  const name = requiredString(spec.artifact.name, `${spec.id}.artifact.name`);
  if (path.basename(name) !== name || name.includes("\\") || !name.endsWith(".kspkg")) fail(`${spec.id}: artifact name must be a flat .kspkg basename`);
  const url = spec.artifact.url ?? spec.artifact.url_template;
  if (typeof url !== "string" || !url.startsWith("https://")) fail(`${spec.id}: artifact URL must be HTTPS`);
  if (/\/(?:latest|main|master)(?:\/|$)/i.test(url)) fail(`${spec.id}: artifact URL must be immutable`);
  const pending = spec.kind === "source" && spec.build && (spec.artifact.sha256 == null || spec.artifact.size == null);
  if (pending && allowPendingBuilds) return { name, pending: true };
  if (!SHA256.test(requiredString(spec.artifact.sha256, `${spec.id}.artifact.sha256`))) fail(`${spec.id}: invalid artifact SHA-256`);
  if (!Number.isSafeInteger(spec.artifact.size) || spec.artifact.size <= 0) fail(`${spec.id}: artifact size must be a positive safe integer`);
  return { name, pending: false };
}

export function validateBom(bom, { expectedSequence, allowPendingBuilds = false } = {}) {
  if (!object(bom) || bom.schema_version !== 1) fail("schema_version must be 1");
  rejectSecrets(bom);
  if (!["candidate", "resolved"].includes(bom.state)) fail("state must be candidate or resolved");
  if (allowPendingBuilds && bom.state !== "candidate") fail("pending builds are allowed only for candidate BOMs");
  requiredString(bom.id, "id");
  if (!object(bom.release)) fail("release is required");
  if (!SEMVER.test(requiredString(bom.release.version, "release.version"))) fail("invalid release version");
  requiredString(bom.release.channel, "release.channel");
  if (!/^[A-Za-z0-9._-]+$/.test(bom.release.channel)) fail("release.channel contains unsafe characters");
  if (!["win", "mac"].includes(bom.release.platform)) fail("release.platform must be win or mac");
  if (!object(bom.source)) fail("source is required");
  for (const [label, value] of Object.entries({
    "source.cortex.repository": bom.source.cortex?.repository,
    "source.core.repository": bom.source.core?.repository,
    "source.arca_sdk.repository": bom.source.arca_sdk?.repository,
    "source.imago.repository": bom.source.imago?.repository,
    "source.store.repository": bom.source.store?.repository,
  })) {
    requiredString(value, label);
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)) fail(`${label} is invalid`);
  }
  for (const [label, value] of Object.entries({
    "source.cortex.commit": bom.source.cortex?.commit,
    "source.core.commit": bom.source.core?.commit,
    "source.arca_sdk.commit": bom.source.arca_sdk?.commit,
    "source.imago.commit": bom.source.imago?.commit,
    "source.store.commit": bom.source.store?.commit,
  })) immutableSha(value, label);
  if (!object(bom.source.core.ark_artifact)) fail("source.core.ark_artifact is required");
  const arkName = requiredString(bom.source.core.ark_artifact.name, "source.core.ark_artifact.name");
  if (arkName !== (bom.release.platform === "win" ? "ark-core-rpc.exe" : "ark-core-rpc"))
    fail("source.core.ark_artifact.name does not match release platform");
  if (!SHA256.test(requiredString(bom.source.core.ark_artifact.sha256, "source.core.ark_artifact.sha256")))
    fail("source.core.ark_artifact.sha256 is invalid");
  if (!Number.isSafeInteger(bom.source.core.ark_artifact.size) || bom.source.core.ark_artifact.size <= 0)
    fail("source.core.ark_artifact.size must be a positive safe integer");
  if (!object(bom.source.toolchain)) fail("source.toolchain is required");
  for (const name of ["bun", "node", "rust"])
    if (!SEMVER.test(requiredString(bom.source.toolchain[name], `source.toolchain.${name}`))) fail(`invalid ${name} toolchain version`);
  requiredString(bom.source.toolchain.target, "source.toolchain.target");
  for (const name of ["arca_sdk", "imago"]) {
    const pkg = bom.source[name]?.package;
    if (!object(pkg)) fail(`source.${name}.package is required`);
    requiredString(pkg.name, `source.${name}.package.name`);
    if (!SEMVER.test(requiredString(pkg.version, `source.${name}.package.version`))) fail(`invalid ${name} package version`);
    if (pkg.integrity !== `git:${bom.source[name].commit}`) fail(`source.${name}.package.integrity must match its commit`);
  }
  if (!object(bom.compatibility)) fail("compatibility is required");
  if (!SEMVER.test(requiredString(bom.compatibility.shell_api, "compatibility.shell_api"))) fail("invalid shell API version");
  if (!SEMVER.test(requiredString(bom.compatibility.engine_api, "compatibility.engine_api"))) fail("invalid engine API version");
  if (bom.compatibility.package_schema !== 2) fail("package schema must be 2");
  if (!object(bom.catalog)) fail("catalog is required");
  if (!Number.isSafeInteger(bom.catalog.sequence) || bom.catalog.sequence <= 0) fail("catalog.sequence must be a positive safe integer");
  if (bom.catalog.previous_sequence !== bom.catalog.sequence - 1) fail("catalog.previous_sequence must immediately precede sequence");
  if (!Number.isSafeInteger(bom.catalog.store_sequence) || bom.catalog.store_sequence <= 0) fail("catalog.store_sequence must be a positive safe integer");
  if (expectedSequence !== undefined && bom.catalog.sequence !== Number(expectedSequence)) fail("catalog sequence does not match requested sequence");
  requiredString(bom.catalog.channel, "catalog.channel");
  if (!/^[A-Za-z0-9._-]+$/.test(bom.catalog.channel)) fail("catalog.channel contains unsafe characters");
  requiredString(bom.catalog.signing_key_id, "catalog.signing_key_id");
  if (!/^[A-Za-z0-9._-]+$/.test(bom.catalog.signing_key_id)) fail("catalog.signing_key_id contains unsafe characters");
  if (bom.release.channel === "production" && (typeof bom.catalog.public_key !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(bom.catalog.public_key))) {
    fail("catalog.public_key must be a base64 Ed25519 public key for production BOMs");
  }
  if (!Array.isArray(bom.retired_package_ids) || bom.retired_package_ids.some((id) => typeof id !== "string" || !id)) fail("retired_package_ids must be an array of non-empty IDs");
  if (!Array.isArray(bom.packages) || bom.packages.length === 0) fail("packages must be a non-empty array");

  const ids = new Set();
  for (const spec of bom.packages) {
    if (!object(spec)) fail("package entries must be objects");
    const id = requiredString(spec.id, "package.id");
    if (ids.has(id)) fail(`duplicate package ID ${id}`);
    ids.add(id);
    if (!SEMVER.test(requiredString(spec.version, `${id}.version`))) fail(`${id}: invalid version`);
    requiredString(spec.manifest_id, `${id}.manifest_id`);
    if (spec.id !== spec.manifest_id) fail(`${id}: id and manifest_id must match`);
    if (!["app", "source"].includes(spec.kind)) fail(`${id}: invalid kind`);
    if (!engineCompatible(spec.engine_api, bom.compatibility.engine_api)) fail(`${id}: incompatible engine API`);
    requiredString(spec.repository, `${id}.repository`);
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(spec.repository)) fail(`${id}: invalid repository`);
    immutableSha(spec.ref, `${id}.ref`);
    if (spec.kind === "source" && spec.ref !== bom.source.cortex.commit) fail(`${id}: source ref must match source.cortex.commit`);
    requiredString(spec.entrypoint, `${id}.entrypoint`);
    requiredString(spec.icon, `${id}.icon`);
    if (spec.kind === "app") {
      const releaseTag = requiredString(spec.release_tag, `${id}.release_tag`);
      if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(releaseTag)) fail(`${id}: release_tag must be an immutable semver tag`);
      const expectedUrl = bom.state === "candidate"
        ? `https://github.com/${spec.repository}/releases/download/${releaseTag}/${spec.artifact.name}`
        : `https://github.com/makekosmos/package-index/releases/download/catalog-${bom.catalog.sequence}/${spec.artifact.name}`;
      if (spec.artifact.url !== expectedUrl) fail(`${id}: artifact URL does not match repository, tag, and name`);
    }
    if (spec.kind === "source") {
      if (!object(spec.build)) fail(`${id}: source build metadata is required`);
      requiredString(spec.build.provider, `${id}.build.provider`);
      requiredString(spec.build.target, `${id}.build.target`);
      const expectedUrl = `https://github.com/makekosmos/package-index/releases/download/catalog-${bom.catalog.sequence}/${spec.artifact.name}`;
      const expectedTemplate = expectedUrl.replace(String(bom.catalog.sequence), "{sequence}");
      if (bom.state === "candidate" && spec.artifact.url_template !== expectedTemplate)
        fail(`${id}: source artifact URL template is invalid`);
      if (bom.state === "resolved" && spec.artifact.url !== expectedUrl)
        fail(`${id}: resolved source artifact URL is invalid`);
    }
    artifact(spec, { allowPendingBuilds });
  }
  const retired = new Set(bom.retired_package_ids);
  if ([...ids].some((id) => retired.has(id))) fail("retired package IDs must not be active package IDs");
  if (!Array.isArray(bom.artifacts)) fail("artifacts must be an array");
  const artifactNames = new Set();
  for (const output of bom.artifacts) {
    if (!object(output)) fail("artifact entries must be objects");
    const name = requiredString(output.name, "artifact.name");
    if (path.basename(name) !== name || artifactNames.has(name)) fail("artifact names must be unique basenames");
    artifactNames.add(name);
    if (!SHA256.test(requiredString(output.sha256, `${name}.sha256`))) fail(`${name}: invalid SHA-256`);
    if (!Number.isSafeInteger(output.size) || output.size <= 0) fail(`${name}: invalid size`);
  }
  return bom;
}

export async function loadBom(file, options) {
  const bom = JSON.parse(await readFile(file, "utf8"));
  return validateBom(bom, options);
}

export async function verifyArtifacts(bom, directory) {
  for (const spec of bom.packages) {
    if (spec.kind === "source" && (spec.artifact.sha256 == null || spec.artifact.size == null)) continue;
    const file = path.join(directory, spec.artifact.name);
    const info = await stat(file).catch(() => null);
    if (!info?.isFile()) fail(`${spec.id}: artifact is missing: ${spec.artifact.name}`);
    const bytes = await readFile(file);
    if (bytes.length !== spec.artifact.size) fail(`${spec.id}: artifact size mismatch`);
    const hash = createHash("sha256").update(bytes).digest("hex");
    if (hash !== spec.artifact.sha256.toLowerCase()) fail(`${spec.id}: artifact SHA-256 mismatch`);
  }
}

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const flag = argv[i];
    if (flag === "--allow-pending-builds" || flag === "--print-downloads" || flag === "--verify-artifacts") {
      args[flag.slice(2)] = true;
      continue;
    }
    if (!flag.startsWith("--") || i + 1 >= argv.length || argv[i + 1].startsWith("--")) fail(`missing value for ${flag}`);
    args[flag.slice(2)] = argv[++i];
  }
  if (!args.bom) fail("--bom is required");
  return args;
}

async function main(argv = process.argv) {
  const args = parseArgs(argv);
  const bom = await loadBom(args.bom, { expectedSequence: args.sequence, allowPendingBuilds: args["allow-pending-builds"] });
  if (args["verify-artifacts"]) {
    if (!args["artifacts-dir"]) fail("--artifacts-dir is required with --verify-artifacts");
    await verifyArtifacts(bom, path.resolve(args["artifacts-dir"]));
  }
  if (args["print-downloads"]) {
    for (const spec of bom.packages.filter((entry) => entry.kind === "app")) {
      console.log([spec.repository, spec.release_tag, spec.ref, spec.artifact.name].join("\t"));
    }
  } else {
    console.log(`Validated BOM ${bom.id}: ${bom.packages.length} packages`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`[bom] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}
