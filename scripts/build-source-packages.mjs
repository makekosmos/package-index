#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { loadBom } from "./validate-bom.mjs";
import { readZip, writeZip } from "./zip-utils.mjs";

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
  for (const name of ["bom", "out", "sequence"]) {
    if (!args[name]) fail(`required argument --${name}`);
  }
  // --source-root points at a local checkout for development; --cortex is a
  // deprecated alias kept for the existing publication workflow.
  args.sourceRoot = args["source-root"] ?? args.cortex;
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
      if (!object(setting.injection) || !["basic", "cookies", "header", "json"].includes(setting.injection.kind)) {
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
    const login = integration.login;
    const huawei = object(login) && login.code_exchange === "huawei_health";
    if (!object(login) || typeof login.start_url !== "string" || typeof login.completion_url !== "string" || !login.start_url.startsWith("https://") || (!huawei && !login.completion_url.startsWith("https://")) || !Array.isArray(login.allowed_cookie_names) || (!huawei && login.allowed_cookie_names.length === 0) || login.allowed_cookie_names.some((name) => typeof name !== "string" || !name) || !secretKeys.has(login.secret_setting)) {
      fail(`${provider}: invalid browser login contract`);
    }
    const loginSetting = integration.settings.find((setting) => setting.key === login.secret_setting);
    if (!loginSetting || (huawei ? (login.start_url !== "https://oauth-login.cloud.huawei.com/oauth2/v3/authorize" || login.completion_url !== "hms://redirect_url" || login.allowed_cookie_names.length !== 0 || loginSetting.injection.kind !== "json") : loginSetting.injection.kind !== "cookies")) {
      fail(`${provider}: invalid login injection`);
    }
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

// Strip every GIT_* variable leaked by an enclosing git hook or caller so the
// ephemeral checkout is controlled only by the BOM. Repo-targeting variables
// (GIT_DIR, GIT_INDEX_FILE, ...) can retarget operations onto the caller's
// repository; config-injection variables (GIT_CONFIG_PARAMETERS,
// GIT_CONFIG_COUNT/GIT_CONFIG_KEY_*/GIT_CONFIG_VALUE_*, GIT_CONFIG_GLOBAL,
// GIT_TEMPLATE_DIR, GIT_SSH_COMMAND, ...) can inject init.templateDir hooks or
// url.insteadOf redirects — executing code inside this build job. Ambient
// source authentication still applies through the default config files.
function gitEnv() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!/^GIT_/.test(key)) env[key] = value;
  }
  env.GIT_TERMINAL_PROMPT = "0";
  return env;
}

function git(args, cwd, label) {
  const result = spawnSync(process.env.GIT ?? "git", args, {
    cwd,
    stdio: "inherit",
    windowsHide: true,
    env: gitEnv(),
  });
  if (result.error) fail(`${label}: ${result.error.message}`);
  if (result.status !== 0) fail(`${label}: git ${args[0]} failed`);
}

function gitHead(dir) {
  const result = spawnSync(process.env.GIT ?? "git", ["-C", dir, "rev-parse", "HEAD"], {
    encoding: "utf8",
    windowsHide: true,
    env: gitEnv(),
  });
  return result.status === 0 ? result.stdout.trim() : null;
}

// "" means the working tree is clean; null means there is no usable checkout.
function gitStatus(dir) {
  const result = spawnSync(process.env.GIT ?? "git", ["-C", dir, "status", "--porcelain"], {
    encoding: "utf8",
    windowsHide: true,
    env: gitEnv(),
  });
  return result.status === 0 ? result.stdout.trim() : null;
}

// Fetch the BOM-pinned repository/ref into an ephemeral checkout under --out.
// A cached checkout is reused only when it is still clean at the pinned ref —
// a HEAD match alone would trust a dirty or tampered working tree.
// Source authentication is ambient (credential helpers, `gh auth setup-git`);
// KOSMOS_SOURCE_GIT_BASE may redirect the github.com base for tests/mirrors.
async function sourceCheckout(spec, out) {
  const key = `${encodeURIComponent(spec.repository)}-${spec.ref}`;
  const dir = path.join(out, "source-checkouts", key);
  if (gitHead(dir) === spec.ref && gitStatus(dir) === "") return dir;
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  const base = process.env.KOSMOS_SOURCE_GIT_BASE ?? "https://github.com";
  const url = `${base}/${spec.repository}.git`;
  git(["init", "-q"], dir, spec.id);
  git(["remote", "add", "origin", url], dir, spec.id);
  git(["fetch", "-q", "--depth", "1", "origin", spec.ref], dir, spec.id);
  git(["checkout", "-q", "--detach", "FETCH_HEAD"], dir, spec.id);
  if (gitHead(dir) !== spec.ref) fail(`${spec.id}: checkout did not resolve to pinned ref ${spec.ref}`);
  return dir;
}

function runCargo(cargoToml, binary, targetDir, target, sourceRoot) {
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
  ], {
    env: {
      ...process.env,
      RUSTFLAGS: [
        process.env.RUSTFLAGS,
        target.endsWith("-windows-msvc") ? "-C link-arg=/Brepro" : "",
        target.endsWith("-windows-msvc") ? `--remap-path-prefix=${path.resolve(sourceRoot)}=/cortex` : "",
        target.endsWith("-windows-msvc") ? `--remap-path-prefix=${path.resolve(process.env.CARGO_HOME ?? path.join(os.homedir(), ".cargo"))}=/cargo` : "",
      ].filter(Boolean).join(" "),
    },
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.status !== 0) fail(`cargo build failed for ${binary}`);
}

function archiveEntryNames(entries) {
  return entries.filter((entry) => !entry.isDir).map((entry) => entry.name).sort();
}

async function buildProvider(spec, sourceRoot, out, sequence, dryRun) {
  const provider = spec.build.provider;
  const packageDir = path.join(sourceRoot, "packages", provider);
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
  runCargo(path.join(packageDir, "Cargo.toml"), manifest.entrypoint.slice(0, -4), targetDir, spec.build.target, sourceRoot);
  const executable = path.join(targetDir, spec.build.target, "release", manifest.entrypoint);
  await requiredFile(executable, `${provider} worker`);
  const iconBytes = await readFile(path.join(packageDir, manifest.icon));
  const archiveBytes = [
    { name: "manifest.json", data: manifestBytes },
    { name: manifest.entrypoint, data: await readFile(executable) },
    { name: manifest.icon, data: iconBytes },
  ];
  const archiveName = spec.artifact.name;
  const archive = path.join(out, archiveName);
  writeZip(archive, archiveBytes);
  const entries = readZip(archive);
  const expectedNames = [manifest.icon, "manifest.json", manifest.entrypoint].sort();
  if (JSON.stringify(archiveEntryNames(entries)) !== JSON.stringify(expectedNames)) fail(`${provider}: archive must contain only manifest, exact worker, and the manifest icon`);
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
  const out = path.resolve(args.out);
  const bom = await loadBom(args.bom, { expectedSequence: args.sequence, allowPendingBuilds: true });
  const sourceSpecs = bom.packages.filter((spec) => spec.kind === "source");
  const packages = [];
  for (const spec of sourceSpecs) {
    const sourceRoot = args.sourceRoot ? path.resolve(args.sourceRoot) : await sourceCheckout(spec, out);
    packages.push(await buildProvider(spec, sourceRoot, out, args.sequence, args.dryRun));
    const built = packages[packages.length - 1];
    if (!args.dryRun) console.log(`${spec.build.provider}: ${built.sha256} ${built.size}`);
  }
  if (!args.dryRun) {
    await writeFile(path.join(out, "source-packages.json"), `${JSON.stringify({ schema_version: 1, bom_id: bom.id, packages }, null, 2)}\n`);
  }
  console.log(`${args.dryRun ? "Validated" : "Built"} ${sourceSpecs.length} source packages: ${sourceSpecs.map((spec) => spec.build.provider).join(", ")}`);
} catch (error) {
  console.error(`[source-packages] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
