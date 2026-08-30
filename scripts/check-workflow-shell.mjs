#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(".github/workflows");
for (const name of (await readdir(root)).filter((entry) => /\.ya?ml$/.test(entry))) {
  const source = await readFile(path.join(root, name), "utf8");
  const runs = [...source.matchAll(/\brun:\s*\|\s*\n((?:^[ ]{10,}.*\n?)+)/gm)];
  for (const run of runs) {
    const body = run[1].replace(/^ {10}/gm, "");
    if (!/^set -Eeuo pipefail\s*$/m.test(body)) throw new Error(`${name}: every multiline shell step must enable strict mode`);
    if (/\brm\s+-rf\b/.test(body)) throw new Error(`${name}: recursive force deletion is forbidden in publication workflows`);
  }
}
console.log("Validated workflow shell strict-mode and deletion checks.");
