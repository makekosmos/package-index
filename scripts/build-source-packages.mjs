#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { loadBom } from "./validate-bom.mjs";

let zipUtils;

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const args = { dryRun: false };
  for (let i = 2; i < argv.length; i += 1) {
    const flag = argv[i];
    if (flag === "--dry-run") {
      args.dryRun = true;
      continue;
    }
    if (!flag.startsWith("--") || i + 1 >= argv.length || argv[i + 1].startsWith("--")) {
      fail(`missing value for ${flag}`);
    }
    args[flag.slice(2)] = argv[++i];
  }
  for (const name of ["bom", "cortex", "out", "sequence"]) {
    if (!args[name]) fail(`required argument --${name}`);
  }
  return args;
}

function object(value) {
  return value && Object.prototype.toString.call(value) === "[object Object]";
}

function validateManifest(manifest, spec) {
  const provider = spec.build.provider;
  if (
    manifest.schema_version !== 2 ||
    manifest.id !== spec.manifest_id ||
    manifest.version !== spec.version ||
    manifest.kind !== spec.kind ||
    manifest.publisher !== "kosmos" ||
    manifest.entrypoint !== spec.entrypoint ||
    manifest.icon !== spec.icon
  ) {
    fail(`${provider}: invalid source manifest identity`);
  }
  if (!Array.isArray(manifest.permissions)) fail(`${provider}: permissions are required`);
  const network = manifest.permissions.find((item) => item?.capability === "network");
  const ark = manifest.permissions.find((item) => item?.capability === "ark.write");
  if (!Array.isArray(network?.scopes) || network.scopes.length === 0 || network.scopes.some((scope) => typeof scope !== "string" || !scope.startsWith("https://"))) {
    fail(`${provider}: HTTPS network permission is required`);
  }
  const networkOrigins = new Set(network.scopes.map((scope) => {
    try {
      const url = new URL(scope);
      if (url.protocol !== "https:") throw new Error("not HTTPS");
      return url.origin;
    } catch {
      fail(`${provider}: invalid network scope`);
    }
  }));
  if (!Array.isArray(ark?.scopes) || ark.scopes.length === 0) fail(`${provider}: ark.write permission is required`);
  const integration = manifest.integration;
  if (!object(integration) || !Array.isArray(integration.settings) || integration.settings.length === 0) {
    fail(`${provider}: integration settings are required`);
  }
  const secretKeys = new Set();
  for (const setting of integration.settings) {
    if (!object(setting) || !/^[a-z][a-z0-9_]{0,63}$/.test(setting.key) || typeof setting.label !== "string" || !["text", "secret"].includes(setting.kind) || typeof setting.required !== "boolean") {
      fail(`${provider}: invalid integration setting`);
    }
    if (setting.kind === "secret") {
      secretKeys.add(setting.key);
      if (!object(setting.injection) || !["basic", "cookies", "header"].includes(setting.injection.kind)) {
        fail(`${provider}: invalid secret injection`);
      }
      if (!Array.isArray(setting.injection.origins) || setting.injection.origins.length === 0 || setting.injection.origins.some((origin) => {
        try {
          return !networkOrigins.has(new URL(origin).origin);
        } catch {
          return true;
        }
      })) fail(`${provider}: secret origins must be covered by network permission`);
    }
  }
  if (integration.login !== undefined) {
    if (!object(integration.login) || typeof integration.login.start_url !== "string" || typeof integration.login.completion_url !== "string" || !integration.login.start_url.startsWith("https://") || !integration.login.completion_url.startsWith("https://") || !Array.isArray(integration.login.allowed_cookie_names) || integration.login.allowed_cookie_names.length === 0 || integration.login.allowed_cookie_names.some((name) => typeof name !== "string" || !name) || !secretKeys.has(integration.login.secret_setting)) {
      fail(`${provider}: invalid browser login contract`);
    }
    const loginSetting = integration.settings.find((setting) => setting.key === integration.login.secret_setting);
    if (loginSetting.injection.kind !== "cookies") fail(`${provider}: browser login requires cookie injection`);
  }
  if (!object(integration.schedule) || !Number.isSafeInteger(integration.schedule.interval_seconds) || integration.schedule.interval_seconds <= 0) {
    fail(`${provider}: integration schedule is required`);
  }
  if (!Array.isArray(manifest.targets) || !manifest.targets.some((item) => item?.runtime === "worker" && Array.isArray(item.os) && item.os.includes("windows"))) {
    fail(`${provider}: Windows worker target is required`);
  }
}

async function requiredFile(file, label) {
  const info = await stat(file).catch(() => null);
  if (!info?.isFile() || info.size === 0) fail(`${label} is missing or empty: ${file}`);
}

function runCargo(cargoToml, binary, targetDir, target) {
  const result = spawnSync(process.env.CARGO ?? "cargo", [
    "build",
    "--manifest-path",
    cargoToml,
    "--bin",
    binary,
    "--release",
    "--locked",
    "--target",
    target,
    "--target-dir",
    targetDir,
  ], { stdio: "inherit", windowsHide: true });
  if (result.status !== 0) fail(`cargo build failed for ${binary}`);
}

function archiveEntryNames(entries) {
  return entries.filter((entry) => !entry.isDir).map((entry) => entry.name).sort();
}

async function buildProvider(spec, cortex, out, sequence, dryRun) {
  const provider = spec.build.provider;
  const packageDir = path.join(cortex, "packages", provider);
  const manifestPath = path.join(packageDir, "manifest.json");
  const manifestBytes = await readFile(manifestPath).catch(() => fail(`${provider}: committed manifest is missing`));
  const manifest = JSON.parse(manifestBytes);
  validateManifest(manifest, spec);
  await requiredFile(path.join(packageDir, "Cargo.toml"), `${provider} Cargo.toml`);
  await requiredFile(path.join(packageDir, manifest.icon), `${provider} icon`);
  if (dryRun) return { manifest };

  const stage = path.join(out, "source-stage", provider);
  const targetDir = path.join(stage, "build");
  await rm(stage, { recursive: true, force: true });
  await mkdir(stage, { recursive: true });
  runCargo(path.join(packageDir, "Cargo.toml"), manifest.entrypoint.slice(0, -4), targetDir, spec.build.target);
  const executable = path.join(targetDir, spec.build.target, "release", manifest.entrypoint);
  await requiredFile(executable, `${provider} worker`);
  const iconBytes = await readFile(path.join(packageDir, manifest.icon));
  const archiveBytes = [
    { name: "manifest.json", data: manifestBytes },
    { name: manifest.entrypoint, data: await readFile(executable) },
    { name: "icon.png", data: iconBytes },
  ];
  const archiveName = spec.artifact.name;
  const archive = path.join(out, archiveName);
  zipUtils.writeZip(archive, archiveBytes);
  const entries = zipUtils.readZip(archive);
  const expectedNames = ["icon.png", "manifest.json", manifest.entrypoint].sort();
  if (JSON.stringify(archiveEntryNames(entries)) !== JSON.stringify(expectedNames)) fail(`${provider}: archive must contain only manifest, exact worker, and icon.png`);
  const bytes = await readFile(archive);
  return {
    manifest,
    archive_url: (spec.artifact.url_template ?? spec.artifact.url).replace("{sequence}", String(sequence)),
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  };
}

try {
  const args = parseArgs(process.argv);
  const cortex = path.resolve(args.cortex);
  const out = path.resolve(args.out);
  zipUtils = await import(pathToFileURL(path.join(cortex, "desktop", "scripts", "zip-utils.mjs")).href);
  const bom = await loadBom(args.bom, { expectedSequence: args.sequence, allowPendingBuilds: true });
  const sourceSpecs = bom.packages.filter((spec) => spec.kind === "source");
  const packages = [];
  for (const spec of sourceSpecs) packages.push(await buildProvider(spec, cortex, out, args.sequence, args.dryRun));
  if (!args.dryRun) {
    await writeFile(path.join(out, "source-packages.json"), `${JSON.stringify({ schema_version: 1, bom_id: bom.id, packages }, null, 2)}\n`);
  }
  console.log(`${args.dryRun ? "Validated" : "Built"} ${sourceSpecs.length} source packages: ${sourceSpecs.map((spec) => spec.build.provider).join(", ")}`);
} catch (error) {
  console.error(`[source-packages] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
