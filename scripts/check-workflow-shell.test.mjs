import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

const checker = path.resolve(import.meta.dirname, "check-workflow-shell.mjs");

function runChecker(cwd) {
  return spawnSync(process.execPath, [checker], { cwd, encoding: "utf8", windowsHide: true });
}

const STEP_PREFIX = `name: t
on: workflow_dispatch
permissions: { contents: read }
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
`;

// The gate must catch multiline run blocks in every YAML block-scalar style
// and at any indentation — not only `run: |` bodies indented ten spaces.
for (const [label, step] of [
  ["literal | without strict mode", "      - run: |\n          rm -rf \"$GITHUB_WORKSPACE\"\n          echo done\n"],
  ["chomping |- without strict mode", "      - run: |-\n          rm -rf \"$GITHUB_WORKSPACE\"\n          echo done\n"],
  ["folded > without strict mode", "      - run: >\n          rm -rf \"$GITHUB_WORKSPACE\"\n          echo done\n"],
  ["shallow-indented | without strict mode", "    - run: |\n        rm -rf \"$GITHUB_WORKSPACE\"\n        echo done\n"],
  ["strict-mode | with forbidden deletion", "      - run: |\n          set -Eeuo pipefail\n          rm -rf \"$RUNNER_TEMP\"\n"],
  ["| with trailing comment", "      - run: | # cleans outputs\n          set -Eeuo pipefail\n          rm -rf \"$RUNNER_TEMP\"\n"],
  // Alternative YAML key spellings still execute a shell step — quoted keys,
  // a space before the colon, node anchors, and flow mappings cannot evade
  // the gate.
  ["quoted key block without strict mode", "      - \"run\": |\n          rm -rf \"$GITHUB_WORKSPACE\"\n          echo done\n"],
  ["spaced key block without strict mode", "      - run : |\n          rm -rf \"$GITHUB_WORKSPACE\"\n          echo done\n"],
  ["anchored key block without strict mode", "      - &a run: |\n          rm -rf \"$GITHUB_WORKSPACE\"\n          echo done\n"],
  ["anchored key block with forbidden deletion", "      - &a run: |\n          set -Eeuo pipefail\n          rm -rf \"$RUNNER_TEMP\"\n"],
  ["single-line run with forbidden deletion", "      - run: rm -rf \"$RUNNER_TEMP\"\n"],
  ["flow-mapping run with forbidden deletion", "      - {run: rm -rf \"$RUNNER_TEMP\"}\n"],
  ["folded plain scalar hiding forbidden deletion", "      - run: rm\n            -rf \"$RUNNER_TEMP\"\n"],
  // The forbidden operation is recursive force deletion itself — reordered,
  // split, quoted, operand-trailing, line-continued, and long-option flag
  // spellings all perform it and must be caught just like `rm -rf`.
  ["reordered flags", "      - run: |\n          set -Eeuo pipefail\n          rm -fr \"$RUNNER_TEMP\"\n"],
  ["uppercase recursive flag", "      - run: |\n          set -Eeuo pipefail\n          rm -Rf \"$RUNNER_TEMP\"\n"],
  ["split flags", "      - run: |\n          set -Eeuo pipefail\n          rm -r -f \"$RUNNER_TEMP\"\n"],
  ["long options", "      - run: |\n          set -Eeuo pipefail\n          rm --recursive --force \"$RUNNER_TEMP\"\n"],
  ["quoted cluster", "      - run: |\n          set -Eeuo pipefail\n          rm \"-rf\" \"$RUNNER_TEMP\"\n"],
  ["operand before flags", "      - run: |\n          set -Eeuo pipefail\n          rm \"$RUNNER_TEMP\" -rf\n"],
  ["line continuation", "      - run: |\n          set -Eeuo pipefail\n          rm \\\n            -rf \"$RUNNER_TEMP\"\n"],
  // A `\<newline>` at the block indent is deleted by the shell, merging the
  // next line's stripped content: `rm -r\<newline>f` reaches rm as `rm -rf`.
  // Folding it to whitespace — or leaving the YAML indent in — splits the
  // flag cluster and hides the operation.
  ["line continuation inside the flag cluster", "      - run: |\n          set -Eeuo pipefail\n          rm -r\\\n          f \"$RUNNER_TEMP\"\n"],
  ["line continuation before the cluster", "      - run: |\n          set -Eeuo pipefail\n          rm -\\\n          rf \"$RUNNER_TEMP\"\n"],
  // The command word resolves quotes and escapes the same way flag tokens do
  // — `r"m"`, `r'm'`, and `r\m` all exec rm, so a literal `\brm\b` match on
  // the raw text is not enough.
  ["double-quoted command word", "      - run: |\n          set -Eeuo pipefail\n          r\"m\" -rf \"$RUNNER_TEMP\"\n"],
  ["single-quoted command word", "      - run: |\n          set -Eeuo pipefail\n          r'm' -rf \"$RUNNER_TEMP\"\n"],
  ["escaped command word", "      - run: |\n          set -Eeuo pipefail\n          r\\m -rf \"$RUNNER_TEMP\"\n"],
  ["ANSI-quoted command word", "      - run: |\n          set -Eeuo pipefail\n          r$'m' -rf \"$RUNNER_TEMP\"\n"],
  ["quoted command word", "      - run: |\n          set -Eeuo pipefail\n          \"rm\" -rf \"$RUNNER_TEMP\"\n"],
  // Shell resolves quotes and escapes inside a token — `-"rf"`, `-r"f"`, and
  // `-\rf` all reach rm as -rf — and GNU getopt_long accepts unambiguous
  // long-option prefixes, so --rec/--fo and even --r/--f are --recursive
  // --force. Flag tokens built from expansions cannot be screened and are
  // treated as unverifiable.
  ["abbreviated long options", "      - run: |\n          set -Eeuo pipefail\n          rm --rec --fo \"$RUNNER_TEMP\"\n"],
  ["minimal long-option abbreviations", "      - run: |\n          set -Eeuo pipefail\n          rm --r --f \"$RUNNER_TEMP\"\n"],
  ["interior double quotes", "      - run: |\n          set -Eeuo pipefail\n          rm -\"rf\" \"$RUNNER_TEMP\"\n"],
  ["quote splitting the cluster", "      - run: |\n          set -Eeuo pipefail\n          rm -r\"f\" \"$RUNNER_TEMP\"\n"],
  ["backslash escape in cluster", "      - run: |\n          set -Eeuo pipefail\n          rm -r\\f \"$RUNNER_TEMP\"\n"],
  ["escape before the flag letter", "      - run: |\n          set -Eeuo pipefail\n          rm -\\rf \"$RUNNER_TEMP\"\n"],
  ["unverifiable flag expansion", "      - run: |\n          set -Eeuo pipefail\n          rm -\"$FLAGS\" \"$RUNNER_TEMP\"\n"],
  // Redirections do not terminate the command — `rm >/dev/null -rf`,
  // `rm 2>/dev/null -rf`, `rm <<EOF -rf`, and `rm >&2 -rf` all still pass -rf
  // to rm, so the flag scan must see past each redirection rather than
  // truncating at the operator.
  ["output redirect before flags", "      - run: |\n          set -Eeuo pipefail\n          rm >/dev/null -rf \"$RUNNER_TEMP\"\n"],
  ["fd redirect before flags", "      - run: |\n          set -Eeuo pipefail\n          rm 2>/dev/null -rf \"$RUNNER_TEMP\"\n"],
  ["input redirect before flags", "      - run: |\n          set -Eeuo pipefail\n          rm </dev/null -rf \"$RUNNER_TEMP\"\n"],
  ["fd duplication before flags", "      - run: |\n          set -Eeuo pipefail\n          rm 2>&1 -rf \"$RUNNER_TEMP\"\n"],
  ["merged redirect before flags", "      - run: |\n          set -Eeuo pipefail\n          rm &>/dev/null -rf \"$RUNNER_TEMP\"\n"],
  ["heredoc redirect before flags", "      - run: |\n          set -Eeuo pipefail\n          rm <<EOF -rf \"$RUNNER_TEMP\"\n          EOF\n"],
  ["redirect between split flags", "      - run: |\n          set -Eeuo pipefail\n          rm -r 2>/dev/null -f \"$RUNNER_TEMP\"\n"],
  // `$'...'` ANSI-C quoting resolves escapes — `r$'\x6d'`, `r$'\155'`, and
  // `r$'\u006d'` all exec rm, and `-$'\x72\x66'` smuggles the flag cluster.
  ["ANSI hex-escaped command word", "      - run: |\n          set -Eeuo pipefail\n          r$'\\x6d' -rf \"$RUNNER_TEMP\"\n"],
  ["ANSI octal-escaped command word", "      - run: |\n          set -Eeuo pipefail\n          r$'\\155' -rf \"$RUNNER_TEMP\"\n"],
  ["ANSI unicode-escaped command word", "      - run: |\n          set -Eeuo pipefail\n          r$'\\u006d' -rf \"$RUNNER_TEMP\"\n"],
  ["ANSI escape in flag cluster", "      - run: |\n          set -Eeuo pipefail\n          rm -$'\\x72\\x66' \"$RUNNER_TEMP\"\n"],
  // `run:` may leave its value to a deeper line — `run:` followed by an
  // indented `|` is still a block scalar to the shell, so the strict-mode
  // requirement and the literal `\<newline>` continuation semantics both
  // still apply.
  ["next-line block scalar without strict mode", "      - run:\n          |\n            rm -f \"$RUNNER_TEMP/file\"\n            echo done\n"],
  ["next-line block scalar with forbidden deletion", "      - run:\n          |\n            set -Eeuo pipefail\n            rm -rf \"$RUNNER_TEMP\"\n"],
  ["next-line block scalar continuation cluster", "      - run:\n          |\n            set -Eeuo pipefail\n            rm -r\\\n            f \"$RUNNER_TEMP\"\n"],
]) {
  test(`rejects ${label}`, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "wf-shell-"));
    try {
      await mkdir(path.join(dir, ".github", "workflows"), { recursive: true });
      await writeFile(path.join(dir, ".github", "workflows", "t.yml"), STEP_PREFIX + step);
      const result = runChecker(dir);
      assert.notEqual(result.status, 0, `${label}: ${result.stderr}`);
      assert.match(result.stderr, /strict mode|recursive force deletion/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

for (const [label, step] of [
  ["strict-mode | at depth", "      - run: |\n          set -Eeuo pipefail\n          echo ok\n"],
  ["strict-mode |- at depth", "      - run: |-\n          set -Eeuo pipefail\n          echo ok\n"],
  ["single-line run", "      - run: echo ok\n"],
  ["anchored strict-mode block", "      - &a run: |\n          set -Eeuo pipefail\n          echo ok\n"],
  ["two compliant blocks", "      - run: |\n          set -Eeuo pipefail\n          echo one\n      - run: |\n          set -Eeuo pipefail\n          echo two\n"],
  // Deletion without the recursive+force combination stays allowed.
  ["plain rm of a file", "      - run: |\n          set -Eeuo pipefail\n          rm -f \"$RUNNER_TEMP/file\"\n"],
  ["recursive delete without force", "      - run: |\n          set -Eeuo pipefail\n          rm -r \"$RUNNER_TEMP/dir\"\n"],
  ["long force without recursive", "      - run: |\n          set -Eeuo pipefail\n          rm --force \"$RUNNER_TEMP/file\"\n"],
  ["long recursive without force", "      - run: |\n          set -Eeuo pipefail\n          rm --recursive \"$RUNNER_TEMP/dir\"\n"],
  ["end-of-options before -rf", "      - run: |\n          set -Eeuo pipefail\n          rm -- \"$RUNNER_TEMP/-rf\"\n"],
  ["rm without recursive flag sharing a line", "      - run: |\n          set -Eeuo pipefail\n          rm out.txt && echo done\n"],
  // Indentation beyond the block indent survives as real whitespace in the
  // shell input, so `rm -r\<newline>  f` is `rm -r` with a `f` operand —
  // recursive without force, not recursive force deletion.
  ["continuation line indented past the block", "      - run: |\n          set -Eeuo pipefail\n          rm -r\\\n            f \"$RUNNER_TEMP/file\"\n"],
  // A block scalar may also start on the line after `run:` — the same strict
  // mode and allowed-deletion rules apply to that spelling.
  ["next-line block scalar with strict mode", "      - run:\n          |\n            set -Eeuo pipefail\n            echo ok\n"],
  ["allowed deletion through a redirect", "      - run: |\n          set -Eeuo pipefail\n          rm -f out.txt >/dev/null\n"],
]) {
  test(`accepts ${label}`, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "wf-shell-"));
    try {
      await mkdir(path.join(dir, ".github", "workflows"), { recursive: true });
      await writeFile(path.join(dir, ".github", "workflows", "t.yml"), STEP_PREFIX + step);
      const result = runChecker(dir);
      assert.equal(result.status, 0, `${label}: ${result.stderr}`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

test("the repository's own workflows pass", () => {
  const result = runChecker(path.resolve(import.meta.dirname, ".."));
  assert.equal(result.status, 0, result.stderr);
});
