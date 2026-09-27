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
// unverifiable rather than trusted. The command word resolves the same way —
// `r"m"`, `r'm'`, `r\m`, `r$'m'`, and `r$'\x6d'` all exec rm — so each line is
// also scanned with quotes and escapes folded.
const ANSI_C_SIMPLE = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v" };

// `$'...'` ANSI-C quoting resolves `\xHH`, `\uHHHH`, `\UHHHHHHHH`, `\ooo`
// octal, `\cX` control, and single-letter escapes statically — decoding them
// before quote folding keeps `r$'\x6d'` and `-$'\x72\x66'` visible to the
// scan.
function decodeAnsiC(body) {
  return body.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|.)/g, (_escape, sequence) => {
    if (/^[xuU]/.test(sequence)) {
      const code = parseInt(sequence.slice(1), 16);
      return code <= 0x10ffff ? String.fromCodePoint(code) : "";
    }
    if (/^[0-7]/.test(sequence)) return String.fromCharCode(parseInt(sequence, 8) & 0xff);
    if (sequence[0] === "c") return String.fromCharCode(sequence.charCodeAt(1) & 0x1f);
    return ANSI_C_SIMPLE[sequence] ?? sequence;
  });
}

function unquoteToken(raw) {
  return raw
    .replace(/\$'(?:[^'\\]|\\.)*'?/g, (quoted) => decodeAnsiC(quoted.slice(2, quoted.endsWith("'") ? -1 : undefined)))
    .replace(/\$(?=["'])/g, "")
    .replace(/\\(.)/g, "$1")
    .replace(/["']/g, "");
}

// `|`/`;`/`&` end a simple command — redirections do not. `rm >/dev/null -rf`,
// `rm 2>/dev/null -rf`, `rm </dev/null -rf`, `rm >&2 -rf`, `rm &>log -rf`, and
// `rm <<EOF -rf` all still deliver the flags to rm, so truncating the scan at
// the first redirect operator hides them. Strip each redirection — optional
// fd/`{var}`/`&` prefix, the operator, and its target word — before cutting at
// the real separators.
const SHELL_REDIRECTION = /(?:\d+|\{[a-zA-Z_][a-zA-Z0-9_]*\}|&)?(?:<<<|<<|<&|<>|>\||&>>|&>|>>|>&|<|>)[ \t]*[^\s|&;]*/g;

function isForceRecursiveDelete(text, literal) {
  let commands;
  if (literal) {
    // YAML strips the block scalar's common indent before the shell sees the
    // text, and a `\<newline>` continuation then merges the next line's
    // stripped content: `rm -r\<newline>f` reaches rm as `rm -rf`. Folding to
    // whitespace — or keeping the indent — splits the flag cluster.
    const raw = text.split("\n");
    const indent = (raw.slice(1).find((line) => line.trim() !== "") ?? "").match(/^ */)[0].length;
    commands = raw
      .map((line, index) => (index === 0 ? line : line.slice(Math.min(indent, line.match(/^ */)[0].length))))
      .join("\n")
      .replace(/\\\r?\n/g, "")
      .split("\n");
  } else {
    commands = [text.replace(/\\\r?\n/g, " ").replace(/[ ]*\n[ ]*/g, " ").replace(/\t/g, " ")];
  }
  for (const line of commands) {
    for (const command of new Set([line, unquoteToken(line)])) {
      for (const match of command.matchAll(/\brm\b/g)) {
        const segment = command.slice(match.index).replace(SHELL_REDIRECTION, " ").split(/[|&;]/, 1)[0];
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
    // `run:` may hand its value to a deeper line — `run:` followed by an
    // indented `|` is still a block scalar to the shell, not an empty step:
    // YAML hands the shell the scalar's literal lines, `\<newline>`
    // continuations included. Folding those lines as a plain scalar both
    // hides the strict-mode requirement and splits the continuation merge.
    let scalar = value;
    let scalarText = text;
    if (lineStart && (value.trim() === "" || value.trimStart().startsWith("#"))) {
      const markerIndex = body.findIndex((bodyLine, bodyIndex) => bodyIndex > 0 && bodyLine.trim() !== "");
      const marker = markerIndex > 0 ? body[markerIndex].trim() : "";
      if (BLOCK_SCALAR.test(marker)) {
        const markerIndent = body[markerIndex].match(/^ */)[0].length;
        const content = [marker];
        for (let j = markerIndex + 1; j < body.length; j += 1) {
          if (body[j].trim() !== "" && body[j].match(/^ */)[0].length <= markerIndent) break;
          content.push(body[j]);
        }
        scalar = marker;
        scalarText = content.join("\n");
      }
    }
    if (lineStart && BLOCK_SCALAR.test(scalar) && !STRICT_MODE.test(scalarText)) {
      throw new Error(`${name}: every multiline shell step must enable strict mode`);
    }
    if (isForceRecursiveDelete(scalarText, scalar.startsWith("|") && BLOCK_SCALAR.test(scalar)) ||
        (scalarText !== text && isForceRecursiveDelete(text, false))) {
      throw new Error(`${name}: recursive force deletion is forbidden in publication workflows`);
    }
  }
}
console.log("Validated workflow shell strict-mode and deletion checks.");
