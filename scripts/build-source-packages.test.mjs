import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

const builderPath = path.resolve(import.meta.dirname, "build-source-packages.mjs");
const GIT = process.env.GIT ?? "git";

// Strip repo-targeting GIT_* variables leaked by enclosing git hooks so the
// fixture repository never operates on the caller's repo. The builder receives
// the environment verbatim on purpose: it must scrub GIT_* itself.
function gitEnv(extra = {}) {
  const env = { ...process.env, GIT_TERMINAL_PROMPT: "0", ...extra };
  for (const key of Object.keys(env)) {
    if (/^GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|QUARANTINE_PATH|NAMESPACE|PREFIX)$/.test(key)) delete env[key];
  }
  return env;
}

function runBuilder(args, env = {}) {
  return spawnSync(process.execPath, [builderPath, ...args], {
    encoding: "utf8",
    windowsHide: true,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", ...env },
  });
}

function git(args, cwd) {
  const result = spawnSync(GIT, args, { cwd, encoding: "utf8", windowsHide: true, env: gitEnv() });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function manifestFixture() {
  return {
    schema_version: 2,
    id: "com.kosmos.fixture",
    version: "1.0.0",
    kind: "source",
    engine_api: ">=1.0.0",
    name: "Fixture",
    publisher: "kosmos",
    entrypoint: "fixture-worker.exe",
    icon: "icon.png",
    data: { access: [], defines: [], mappings: [] },
    permissions: [
      { capability: "network", scopes: ["https://fixture.example/"] },
      { capability: "ark.write", scopes: ["fixture"] },
    ],
    integration: {
      settings: [{
        key: "api_key",
        label: "API key",
        kind: "secret",
        required: true,
        injection: { kind: "header", origins: ["https://fixture.example"] },
      }],
      schedule: { interval_seconds: 3600 },
    },
    targets: [{ runtime: "worker", os: ["windows"] }],
  };
}

function bomFixture(commit) {
  return {
    schema_version: 1,
    state: "candidate",
    id: "fixture-bom",
    release: { version: "1.0.0", channel: "test", platform: "win" },
    source: {
      cortex: { repository: "makekosmos/fixture-src", commit },
      core: { repository: "makekosmos/core", commit: "2".repeat(40), ark_artifact: { name: "ark-core-rpc.exe", sha256: "2".repeat(64), size: 1 } },
      arca_sdk: { repository: "makekosmos/arca-sdk", commit: "3".repeat(40), package: { name: "@makekosmos/ark", version: "1.0.0", integrity: `git:${"3".repeat(40)}` } },
      imago: { repository: "makekosmos/imago", commit: "4".repeat(40), package: { name: "@makekosmos/visuals", version: "1.0.0", integrity: `git:${"4".repeat(40)}` } },
      store: { repository: "makekosmos/store", commit: "6".repeat(40) },
      toolchain: { pnpm: "1.0.0", node: "1.0.0", rust: "1.0.0", target: "x86_64-pc-windows-msvc" },
    },
    compatibility: { shell_api: "1.0.0", engine_api: "1.0.0", package_schema: 2 },
    catalog: { sequence: 2, previous_sequence: 1, store_sequence: 1, channel: "test", signing_key_id: "test" },
    retired_package_ids: [],
    packages: [{
      id: "com.kosmos.fixture",
      manifest_id: "com.kosmos.fixture",
      kind: "source",
      engine_api: ">=1.0.0",
      version: "1.0.0",
      repository: "makekosmos/fixture-src",
      ref: commit,
      entrypoint: "fixture-worker.exe",
      icon: "icon.png",
      build: { provider: "fixture", target: "x86_64-pc-windows-msvc" },
      artifact: {
        name: "fixture.kspkg",
        url_template: "https://github.com/makekosmos/package-index/releases/download/catalog-{sequence}/fixture.kspkg",
      },
    }],
    artifacts: [],
  };
}

async function writePackage(root) {
  const packageDir = path.join(root, "packages", "fixture");
  await mkdir(packageDir, { recursive: true });
  await writeFile(path.join(packageDir, "manifest.json"), `${JSON.stringify(manifestFixture(), null, 2)}\n`);
  await writeFile(path.join(packageDir, "Cargo.toml"), "[package]\nname = \"fixture-worker\"\nversion = \"1.0.0\"\n");
  await writeFile(path.join(packageDir, "icon.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
}

test("source packages validate from an explicit local source checkout", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-src-build-"));
  try {
    const sourceRoot = path.join(dir, "checkout");
    await writePackage(sourceRoot);
    const bomPath = path.join(dir, "bom.json");
    await writeFile(bomPath, JSON.stringify(bomFixture("f".repeat(40))));
    const result = runBuilder(["--bom", bomPath, "--source-root", sourceRoot, "--out", path.join(dir, "out"), "--sequence", "2", "--dry-run"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Validated 1 source packages: fixture/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("duplicate or malformed permission grants fail closed", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-src-build-"));
  try {
    for (const [label, mutate, expected] of [
      // A second `network` entry would carry scopes the per-capability checks
      // never inspect (non-HTTPS origins, non-URL strings).
      ["duplicate network capability", (m) => {
        m.permissions.push({ capability: "network", scopes: ["http://insecure.invalid", "not-a-url"] });
      }, /duplicate permission capability/],
      ["non-string ark.write scopes", (m) => {
        m.permissions.find((p) => p.capability === "ark.write").scopes = [123, null];
      }, /ark.write permission is required/],
      ["permission entry without a capability", (m) => {
        m.permissions.push({ scopes: [] });
      }, /invalid or duplicate permission capability/],
      ["duplicate integration setting key", (m) => {
        m.integration.settings.push({ ...m.integration.settings[0] });
      }, /duplicate integration setting key/],
      // Identity fields publish verifies against the BOM — engine_api, name,
      // and the data contract — must hold at build time, not mid-publish.
      ["engine_api drifted from the BOM", (m) => {
        m.engine_api = ">=99.0.0";
      }, /invalid source manifest identity/],
      ["missing manifest name", (m) => {
        delete m.name;
      }, /invalid source manifest identity/],
      ["missing manifest data contract", (m) => {
        delete m.data;
      }, /invalid source manifest identity/],
    ]) {
      const sourceRoot = path.join(dir, `checkout-${label.replaceAll(" ", "-")}`);
      await writePackage(sourceRoot);
      const manifest = manifestFixture();
      mutate(manifest);
      await writeFile(path.join(sourceRoot, "packages", "fixture", "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
      const bomPath = path.join(dir, "bom.json");
      await writeFile(bomPath, JSON.stringify(bomFixture("f".repeat(40))));
      const result = runBuilder(["--bom", bomPath, "--source-root", sourceRoot, "--out", path.join(dir, "out"), "--sequence", "2", "--dry-run"]);
      assert.notEqual(result.status, 0, `${label} unexpectedly accepted`);
      assert.match(result.stderr, expected, label);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a missing committed manifest fails closed", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-src-build-"));
  try {
    const sourceRoot = path.join(dir, "checkout");
    await mkdir(path.join(sourceRoot, "packages", "fixture"), { recursive: true });
    const bomPath = path.join(dir, "bom.json");
    await writeFile(bomPath, JSON.stringify(bomFixture("f".repeat(40))));
    const result = runBuilder(["--bom", bomPath, "--source-root", sourceRoot, "--out", path.join(dir, "out"), "--sequence", "2", "--dry-run"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /committed manifest is missing/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the builder fetches the BOM-pinned repository/ref without a checkout arg", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-src-build-"));
  try {
    const remote = path.join(dir, "remotes", "makekosmos", "fixture-src.git");
    await mkdir(remote, { recursive: true });
    git(["init", "-q"], remote);
    git(["config", "user.email", "fixture@example.test"], remote);
    git(["config", "user.name", "fixture"], remote);
    git(["config", "uploadpack.allowAnySHA1InWant", "true"], remote);
    git(["remote", "add", "origin", "https://invalid.example/unused.git"], remote);
    await writePackage(remote);
    git(["add", "-A"], remote);
    git(["commit", "-qm", "fixture"], remote);
    const commit = git(["rev-parse", "HEAD"], remote);
    const bomPath = path.join(dir, "bom.json");
    await writeFile(bomPath, JSON.stringify(bomFixture(commit)));
    const base = path.join(dir, "remotes").replaceAll("\\", "/");
    // A leaked GIT_DIR (as set by enclosing git hooks) must not retarget the
    // ephemeral checkout onto the caller's repository.
    const result = runBuilder(
      ["--bom", bomPath, "--out", path.join(dir, "out"), "--sequence", "2", "--dry-run"],
      { KOSMOS_SOURCE_GIT_BASE: base, GIT_DIR: remote },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Validated 1 source packages: fixture/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("leaked GIT_CONFIG_* injection cannot install hooks into the checkout", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-src-build-"));
  try {
    const remote = path.join(dir, "remotes", "makekosmos", "fixture-src.git");
    await mkdir(remote, { recursive: true });
    git(["init", "-q"], remote);
    git(["config", "user.email", "fixture@example.test"], remote);
    git(["config", "user.name", "fixture"], remote);
    git(["config", "uploadpack.allowAnySHA1InWant", "true"], remote);
    await writePackage(remote);
    git(["add", "-A"], remote);
    git(["commit", "-qm", "fixture"], remote);
    const commit = git(["rev-parse", "HEAD"], remote);
    const bomPath = path.join(dir, "bom.json");
    await writeFile(bomPath, JSON.stringify(bomFixture(commit)));
    // init.templateDir copied into the ephemeral checkout would run this
    // post-checkout hook inside the build job.
    const hooks = path.join(dir, "template", "hooks");
    await mkdir(hooks, { recursive: true });
    const marker = path.join(dir, "pwned.txt");
    const hook = path.join(hooks, "post-checkout");
    await writeFile(hook, `#!/bin/sh\ntouch "${marker}"\n`);
    await chmod(hook, 0o755);
    const base = path.join(dir, "remotes").replaceAll("\\", "/");
    const result = runBuilder(
      ["--bom", bomPath, "--out", path.join(dir, "out"), "--sequence", "2", "--dry-run"],
      {
        KOSMOS_SOURCE_GIT_BASE: base,
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "init.templateDir",
        GIT_CONFIG_VALUE_0: path.join(dir, "template"),
        GIT_TEMPLATE_DIR: path.join(dir, "template"),
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Validated 1 source packages: fixture/);
    await assert.rejects(readFile(marker), /ENOENT/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a dirty cached checkout is refetched instead of trusted", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-src-build-"));
  try {
    const remote = path.join(dir, "remotes", "makekosmos", "fixture-src.git");
    await mkdir(remote, { recursive: true });
    git(["init", "-q"], remote);
    git(["config", "user.email", "fixture@example.test"], remote);
    git(["config", "user.name", "fixture"], remote);
    git(["config", "uploadpack.allowAnySHA1InWant", "true"], remote);
    await writePackage(remote);
    git(["add", "-A"], remote);
    git(["commit", "-qm", "fixture"], remote);
    const commit = git(["rev-parse", "HEAD"], remote);
    const bomPath = path.join(dir, "bom.json");
    await writeFile(bomPath, JSON.stringify(bomFixture(commit)));
    const base = path.join(dir, "remotes").replaceAll("\\", "/");
    const out = path.join(dir, "out");
    const args = ["--bom", bomPath, "--out", out, "--sequence", "2", "--dry-run"];
    const env = { KOSMOS_SOURCE_GIT_BASE: base };
    assert.equal(runBuilder(args, env).status, 0);
    const checkout = path.join(out, "source-checkouts", `${encodeURIComponent("makekosmos/fixture-src")}-${commit}`);
    // Tamper with the cached working tree: HEAD still matches the pinned ref,
    // so a HEAD-only reuse check would trust the poisoned manifest.
    const manifestPath = path.join(checkout, "packages", "fixture", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.permissions[0].scopes = ["https://evil.example/"];
    manifest.integration.settings[0].injection.origins = ["https://evil.example"];
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const result = runBuilder(args, env);
    assert.equal(result.status, 0, result.stderr);
    const restored = JSON.parse(await readFile(manifestPath, "utf8"));
    assert.deepEqual(restored.permissions[0].scopes, ["https://fixture.example/"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the deprecated --cortex alias still selects a local checkout", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-src-build-"));
  try {
    const sourceRoot = path.join(dir, "cortex");
    await writePackage(sourceRoot);
    const bomPath = path.join(dir, "bom.json");
    await writeFile(bomPath, JSON.stringify(bomFixture("f".repeat(40))));
    const result = runBuilder(["--bom", bomPath, "--cortex", sourceRoot, "--out", path.join(dir, "out"), "--sequence", "2", "--dry-run"]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Validated 1 source packages: fixture/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
