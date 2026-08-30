import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";

const workflow = await readFile(path.resolve(import.meta.dirname, "../.github/workflows/publish-package-v1.yml"), "utf8");
const retiredWorkflow = path.resolve(import.meta.dirname, "../.github/workflows/publish-shell.yml");

test("package publication workflow consumes an immutable BOM", () => {
  assert.match(workflow, /bom_ref:/);
  assert.match(workflow, /bom_path:/);
  assert.match(workflow, /ref: \$\{\{ inputs\.bom_ref \}\}/);
  assert.match(workflow, /ref: \$\{\{ steps\.bom\.outputs\.cortex_ref \}\}/);
  assert.doesNotMatch(workflow, /inputs\.source_ref/);
  assert.match(workflow, /validate-bom\.mjs --bom/);
  assert.match(workflow, /--verify-artifacts --artifacts-dir out/);
  assert.match(workflow, /gh release download "catalog-\$previous_sequence"/);
  assert.match(workflow, /release-bom\.v1\.json/);
  assert.match(workflow, /cortex\/Cargo\.lock/);
  assert.match(workflow, /GH_TOKEN="\$KOSMOS_SOURCE_REPO_TOKEN" gh api/);
  assert.match(workflow, /--target "\$BOM_REF"/);
  assert.match(workflow, /Preflight exact releases, refs, and previous envelope \(no secrets\)/);
  assert.match(workflow, /refs\/tags\/\$release_tag/);
  assert.match(workflow, /verify-previous-catalog\.mjs/);
  assert.match(workflow, /--previous-envelope out\/previous\/catalog\.envelope\.json/);
  assert.match(workflow, /--previous-signatures out\/previous\/catalog\.signatures\.json/);
  assert.ok(workflow.indexOf("Preflight exact releases") < workflow.indexOf("secrets.KOSMOS_SOURCE_REPO_TOKEN"));
  assert.ok(workflow.indexOf("secrets.KOSMOS_PACKAGE_RELEASE_PRIVATE_KEY") > workflow.indexOf("Preflight exact releases"));
});

test("no independent catalog publisher bypasses the BOM", async () => {
  await assert.rejects(readFile(retiredWorkflow, "utf8"), /ENOENT/);
});

test("package release tags and versions are not hard-coded in workflow source", () => {
  assert.doesNotMatch(workflow, /gh release download v\d/);
  assert.doesNotMatch(workflow, /com\.kosmos\.(arcadia|dictation|agenda|memoria|focus)-0\.\d+\.\d+\.kspkg/);
  assert.doesNotMatch(workflow, /version!==\"0\.1\.0\"/);
});
