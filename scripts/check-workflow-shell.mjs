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

// Recursive force deletion is the forbidden operation — not one flag spelling.
// Option clusters fold the flags in any order (`rm -fr`, `rm -Rf`), split them
// (`rm -r -f`), quote them (`rm "-rf"`), place them after operands
// (`rm out/ -rf`), or use long options (`rm --recursive --force`).
// `literal` marks a `|` block scalar, where each line is its own command;
// `>` and plain scalars fold continuation lines into the same command.
// Shell word semantics apply inside a token, not only at its edges: quote
// removal and backslash escapes fold `-"rf"`, `-r"f"`, and `-\rf` into `-rf`,
// and GNU getopt_long accepts any unambiguous long-option prefix — `rm --rec
// --fo` and even `rm --r --f` execute --recursive --force. Tokens are resolved
// the same way before flag parsing; expansion-bearing spellings (`-$VAR`,
// `-$()` substitutions) cannot be screened statically and are rejected as
// unverifiable rather than trusted.
function unquoteToken(raw) {
  return raw.replace(/\\(.)/g, "$1").replace(/["']/g, "");
}

function isForceRecursiveDelete(text, literal) {
  const joined = text.replace(/\\\r?\n/g, " ");
  const commands = literal ? joined.split("\n") : [joined.replace(/[ ]*\n[ ]*/g, " ").replace(/\t/g, " ")];
  for (const line of commands) {
    for (const match of line.matchAll(/\brm\b/g)) {
      const segment = line.slice(match.index).split(/[|&;<>]/, 1)[0];
      let recursive = false;
      let force = false;
      for (const raw of segment.trim().split(/\s+/).slice(1)) {
        const token = unquoteToken(raw);
        if (token === "--") break;
        if (/^-.*[$`\\]/.test(token)) return true;
        if (token.startsWith("--")) {
          const word = token.slice(2);
          if (word && "recursive".startsWith(word)) recursive = true;
          if (word && "force".startsWith(word)) force = true;
          continue;
        }
        const short = /^-([a-zA-Z]+)$/.exec(token);
        if (short) {
          if (/[rR]/.test(short[1])) recursive = true;
          if (/f/.test(short[1])) force = true;
        }
      }
      if (recursive && force) return true;
    }
  }
  return false;
}

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
    if (isForceRecursiveDelete(text, BLOCK_SCALAR.test(value) && value.startsWith("|"))) {
      throw new Error(`${name}: recursive force deletion is forbidden in publication workflows`);
    }
  }
}
console.log("Validated workflow shell strict-mode and deletion checks.");
