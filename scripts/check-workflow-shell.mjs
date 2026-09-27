#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(".github/workflows");
for (const name of (await readdir(root)).filter((entry) => /\.ya?ml$/.test(entry))) {
  const source = await readFile(path.join(root, name), "utf8");
  const lines = source.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    // A `run:` key introduces a multiline shell script whenever its value is a
    // block scalar — `|` or `>`, optionally with chomping/indent indicators
    // and a trailing comment. Anchor the body to the key's own column so
    // deeper- or shallower-indented steps cannot evade detection.
    if (!/^\s*(?:-\s+)?run:\s*[|>][0-9+-]{0,2}\s*(?:#[^\n]*)?$/.test(lines[index])) continue;
    const keyColumn = lines[index].indexOf("run:");
    const body = [];
    for (let line = index + 1; line < lines.length; line += 1) {
      if (lines[line].trim() === "") { body.push(""); continue; }
      if (lines[line].match(/^ */)[0].length <= keyColumn) break;
      body.push(lines[line]);
      index = line;
    }
    const text = body.join("\n");
    if (!/^[ ]*set -Eeuo pipefail[ ]*$/m.test(text)) throw new Error(`${name}: every multiline shell step must enable strict mode`);
    if (/\brm\s+-rf\b/.test(text)) throw new Error(`${name}: recursive force deletion is forbidden in publication workflows`);
  }
}
console.log("Validated workflow shell strict-mode and deletion checks.");
