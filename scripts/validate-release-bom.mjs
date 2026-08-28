#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const bom = JSON.parse(await readFile(new URL("../release-bom.json", import.meta.url), "utf8"));
if (bom.schema_version !== 1 || bom.policy !== "reviewed-release-bom" || !Array.isArray(bom.packages) || bom.packages.length === 0) {
  throw new Error("release BOM schema or policy is invalid");
}
const ids = new Set();
for (const item of bom.packages) {
  if (!item || typeof item.id !== "string" || ids.has(item.id)) throw new Error("release BOM contains duplicate or invalid IDs");
  ids.add(item.id);
  if (!/^makekosmos\/[a-z0-9-]+$/.test(item.repository)) throw new Error(`${item.id}: repository must be an explicit makekosmos repo`);
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(item.tag)) throw new Error(`${item.id}: release tag must be immutable semver`);
  if (typeof item.archive_name !== "string" || item.archive_name.includes("/") || item.archive_name.includes("\\") || !item.archive_name.endsWith(".kspkg")) {
    throw new Error(`${item.id}: archive name must be a flat .kspkg file`);
  }
}
console.log(`Validated reviewed release BOM with ${bom.packages.length} packages.`);
