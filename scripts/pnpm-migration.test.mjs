import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const tracked = (file) => execFileSync("git", ["ls-files", file], { cwd: root, encoding: "utf8" }).trim();

test("Package Index pins pnpm and keeps its intentional no-lock policy", async () => {
  const manifest = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  const bom = JSON.parse(await readFile(path.join(root, "release/bom.v1.json"), "utf8"));
  assert.equal(manifest.packageManager, "pnpm@12.4.1");
  assert.deepEqual(bom.source.toolchain, {
    node: bom.source.toolchain.node,
    pnpm: "12.4.1",
    rust: bom.source.toolchain.rust,
    target: bom.source.toolchain.target,
  });
  assert.equal(tracked("bun.lock"), "");
  assert.equal(tracked("pnpm-lock.yaml"), "");
  const pnpm = process.platform === "win32" ? process.env.ComSpec ?? "cmd.exe" : "pnpm";
  const pnpmArgs = process.platform === "win32" ? ["/d", "/s", "/c", "pnpm --pm-on-fail=ignore --config.verify-deps-before-run=false run check:toolchain"] : ["--pm-on-fail=ignore", "--config.verify-deps-before-run=false", "run", "check:toolchain"];
  execFileSync(pnpm, pnpmArgs, { cwd: root, stdio: "ignore" });
  assert.equal(existsSync(path.join(root, "pnpm-lock.yaml")), false);
  const active = await Promise.all(["package.json", "README.md", ".githooks/pre-push", ".github/workflows/quality.yml"]
    .map((file) => readFile(path.join(root, file), "utf8")));
  assert.ok(active.every((source) => !/\bbun(?:x)?\b/.test(source)));
});
