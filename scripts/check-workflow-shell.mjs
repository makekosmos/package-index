#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

// A `run` key introduces a shell step. YAML accepts the key in several
// spellings — quoted (`"run":`, `'run':`), separated from the colon
// (`run :`), anchored or tagged (`- &a run:`, `- !tag run:`), and nested in a
// flow mapping (`- {run: ...}`) — and every spelling still executes, so all
// of them must be screened.
const RUN_KEY = /(?:^(\s*(?:-\s+)?(?:[&!*][^\s#]+\s+)*)|[{,]\s*)["']?run["']?\s*:\s*/;
// A multiline script arrives via a block scalar — `|` or `>`, optionally with
// chomping/indent indicators and a trailing comment.
const BLOCK_SCALAR = /^[|>][0-9+-]{0,2}\s*(?:#[^\n]*)?$/;
const STRICT_MODE = /^[ ]*set -Eeuo pipefail[ ]*$/m;
const FORCE_DELETE = /\brm\s+-rf\b/;

const root = path.resolve(".github/workflows");
for (const name of (await readdir(root)).filter((entry) => /\.ya?ml$/.test(entry))) {
  const source = await readFile(path.join(root, name), "utf8");
  const lines = source.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const match = RUN_KEY.exec(lines[index]);
    if (!match) continue;
    // Line-start spellings anchor the body to the column of the step's first
    // content token (the `run` key itself, or a leading `&a`/`!tag`): YAML
    // accepts block-scalar bodies and folded plain-scalar continuations at
    // any deeper indentation. Flow-mapping spellings cannot hold block
    // scalars and have no continuation lines to collect.
    const lineStart = match[1] !== undefined;
    const keyColumn = lineStart ? /^\s*(?:-\s+)?/.exec(match[1])[0].length : Number.MAX_SAFE_INTEGER;
    const value = lines[index].slice(match.index + match[0].length);
    const body = [value];
    for (let line = index + 1; line < lines.length; line += 1) {
      if (lines[line].trim() === "") { body.push(""); continue; }
      if (lines[line].match(/^ */)[0].length <= keyColumn) break;
      body.push(lines[line]);
      index = line;
    }
    const text = body.join("\n");
    if (lineStart && BLOCK_SCALAR.test(value) && !STRICT_MODE.test(text)) {
      throw new Error(`${name}: every multiline shell step must enable strict mode`);
    }
    if (FORCE_DELETE.test(text)) {
      throw new Error(`${name}: recursive force deletion is forbidden in publication workflows`);
    }
  }
}
console.log("Validated workflow shell strict-mode and deletion checks.");
