import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { validateReleaseBom } from "./validate-release-bom.mjs";

const bomPath = path.resolve(import.meta.dirname, "../release/bom.v1.json");

test("checked-in release BOM satisfies the first-party repository gate", async () => {
  const bom = JSON.parse(await readFile(bomPath, "utf8"));
  assert.doesNotThrow(() => validateReleaseBom(bom));
});

test("source repository pins are gated to the makekosmos org", async () => {
  // Every `source.*` pin feeds `gh api` lookups or the ephemeral checkouts the
  // workers are built from — the same org requirement as package repositories.
  // Unreferenced pins (store, arca_sdk, imago, core) carry no package entry, so
  // only this gate sees them.
  for (const key of ["cortex", "core", "arca_sdk", "imago", "store", "integrations"]) {
    const bom = JSON.parse(await readFile(bomPath, "utf8"));
    bom.source[key].repository = "attacker/repo";
    assert.throws(() => validateReleaseBom(bom), new RegExp(`source\\.${key}\\.repository`), key);
  }
});
