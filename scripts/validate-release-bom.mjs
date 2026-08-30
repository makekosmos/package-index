#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadBom } from "./validate-bom.mjs";

const bomPath = path.resolve(fileURLToPath(new URL("../release/bom.v1.json", import.meta.url)));
const bom = await loadBom(bomPath, { expectedSequence: 12, allowPendingBuilds: true });
const ids = new Set();
for (const item of bom.packages) {
  if (!item || typeof item.id !== "string" || ids.has(item.id)) throw new Error("release BOM contains duplicate or invalid IDs");
  ids.add(item.id);
  if (item.kind !== "app") continue;
  if (!/^makekosmos\/[a-z0-9-]+$/.test(item.repository)) throw new Error(`${item.id}: repository must be an explicit makekosmos repo`);
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(item.release_tag)) throw new Error(`${item.id}: release tag must be immutable semver`);
  const archiveName = item.artifact.name;
  if (typeof archiveName !== "string" || archiveName.includes("/") || archiveName.includes("\\") || !archiveName.endsWith(".kspkg")) {
    throw new Error(`${item.id}: archive name must be a flat .kspkg file`);
  }
}
console.log(`Validated reviewed release BOM with ${bom.packages.length} packages.`);
