import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

const checker = path.resolve(import.meta.dirname, "check-workflow-contract.mjs");
const SHA = "11d5960a326750d5838078e36cf38b85af677262";

function runChecker(cwd) {
  return spawnSync(process.execPath, [checker], { cwd, encoding: "utf8", windowsHide: true });
}

const STEP_PREFIX = `name: t
on: workflow_dispatch
permissions: { contents: read }
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
`;

// YAML accepts several `uses` key spellings — quoted keys, a space before the
// colon, node anchors, and flow mappings — and every spelling still executes
// the referenced action, so none of them may bypass the commit-SHA pin rule.
for (const [label, step] of [
  ["mutable ref", `      - uses: actions/checkout@main\n`],
  ["quoted key with mutable ref", `      - "uses": actions/checkout@main\n`],
  ["spaced key with mutable ref", `      - uses : actions/checkout@main\n`],
  ["anchored key with mutable ref", `      - &a uses: actions/checkout@main\n`],
  ["flow mapping with mutable ref", `      - {uses: actions/checkout@main}\n`],
  ["job-level reusable workflow", `    uses: octo/repo/.github/workflows/ci.yml@main\n`],
  // A `uses` value with no `@` at all executes an unpinned reference — bare
  // action names and docker image tags must not slip past the pin check.
  ["bare action without ref", `      - uses: octo/action\n`],
  ["docker image without digest", `      - uses: docker://alpine:3.19\n`],
  ["empty ref", `      - uses: octo/action@\n`],
]) {
  test(`rejects ${label}`, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "wf-contract-"));
    try {
      await mkdir(path.join(dir, ".github", "workflows"), { recursive: true });
      await writeFile(path.join(dir, ".github", "workflows", "t.yml"), STEP_PREFIX + step);
      const result = runChecker(dir);
      assert.notEqual(result.status, 0, `${label}: ${result.stderr}`);
      assert.match(result.stderr, /pinned to a full commit SHA/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

for (const [label, step] of [
  ["SHA-pinned step", `      - uses: actions/checkout@${SHA} # v4\n`],
  ["quoted key, SHA-pinned", `      - "uses": actions/checkout@${SHA}\n`],
  ["flow mapping, SHA-pinned", `      - {uses: actions/checkout@${SHA}, name: x}\n`],
  ["local action without ref", `      - uses: ./.github/actions/local\n`],
]) {
  test(`accepts ${label}`, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "wf-contract-"));
    try {
      await mkdir(path.join(dir, ".github", "workflows"), { recursive: true });
      await writeFile(path.join(dir, ".github", "workflows", "t.yml"), STEP_PREFIX + step);
      const result = runChecker(dir);
      assert.equal(result.status, 0, `${label}: ${result.stderr}`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

test("a workflow without top-level permissions is rejected", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "wf-contract-"));
  try {
    await mkdir(path.join(dir, ".github", "workflows"), { recursive: true });
    await writeFile(path.join(dir, ".github", "workflows", "t.yml"), "name: t\non: push\njobs: {}\n");
    const result = runChecker(dir);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /top-level permissions/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the repository's own workflows pass", () => {
  const result = runChecker(path.resolve(import.meta.dirname, ".."));
  assert.equal(result.status, 0, result.stderr);
});
