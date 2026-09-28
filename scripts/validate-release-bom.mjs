#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadBom } from "./validate-bom.mjs";

// The checked-in release BOM is additionally gated to first-party repositories:
// every package must name an explicit makekosmos repo — and so must every
// `source.*` pin. The pins feed `gh api` commit/store lookups in the publish
// workflow and drive which repository the source workers are built from, so an
// out-of-org pin is the same review gap as an out-of-org package.
export function validateReleaseBom(bom) {
  for (const [key, pin] of Object.entries(bom.source ?? {})) {
    if (pin?.repository !== undefined && !/^makekosmos\/[a-z0-9-]+$/.test(pin.repository)) {
      throw new Error(`source.${key}.repository must be an explicit makekosmos repo`);
    }
  }
  const ids = new Set();
  for (const item of bom.packages) {
    if (!item || typeof item.id !== "string" || ids.has(item.id)) throw new Error("release BOM contains duplicate or invalid IDs");
    ids.add(item.id);
    if (item.kind === "source") {
      if (!/^makekosmos\/[a-z0-9-]+$/.test(item.repository)) throw new Error(`${item.id}: source repository must be an explicit makekosmos repo`);
      continue;
    }
    if (!/^makekosmos\/[a-z0-9-]+$/.test(item.repository)) throw new Error(`${item.id}: repository must be an explicit makekosmos repo`);
    if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(item.release_tag)) throw new Error(`${item.id}: release tag must be immutable semver`);
    const archiveName = item.artifact.name;
    const extension = item.kind === "native-app" ? ".zip" : ".kspkg";
    if (typeof archiveName !== "string" || archiveName.includes("/") || archiveName.includes("\\") || !archiveName.endsWith(extension)) {
      throw new Error(`${item.id}: archive name must be a flat ${extension} file`);
    }
  }
  return bom;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const bomPath = path.resolve(fileURLToPath(new URL("../release/bom.v1.json", import.meta.url)));
  const bom = await loadBom(bomPath, { allowPendingBuilds: true });
  validateReleaseBom(bom);
  console.log(`Validated reviewed release BOM with ${bom.packages.length} packages.`);
}
