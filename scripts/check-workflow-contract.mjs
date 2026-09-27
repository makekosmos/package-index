#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

// A `uses` key invokes an action. YAML accepts the key in several spellings —
// quoted (`"uses":`), separated from the colon (`uses :`), anchored or tagged
// (`- &a uses:`), and inside a flow mapping (`- {uses: ...}`) — and every
// spelling still executes the referenced action. Capture the whole value so
// that `uses:` lines WITHOUT an `@<ref>` — a bare action name or a
// `docker://image:tag` — cannot slip past the pin check. The ref may also
// arrive on a deeper line — `uses:` followed by an indented `owner/action@sha`
// is a folded continuation to YAML and still executes — so the value capture
// is allowed to be empty and resolved against the following lines below.
const USES_KEY = /(?:^(\s*(?:-\s+)?(?:[&!*][^\s#]+\s+)*)|[{,]\s*)["']?uses["']?\s*:\s*([^\s#},]*)/;

const root = path.resolve(".github/workflows");
const files = (await readdir(root)).filter((file) => /\.ya?ml$/.test(file));
if (files.length === 0) throw new Error("no workflow files found");
for (const file of files) {
  const source = await readFile(path.join(root, file), "utf8");
  if (!/^permissions\s*:/m.test(source)) throw new Error(`${file}: top-level permissions are required`);
  const lines = source.split("\n");
  for (const [index, line] of lines.entries()) {
    const match = USES_KEY.exec(line);
    if (!match) continue;
    const lineStart = match[1] !== undefined;
    const keyColumn = lineStart ? /^\s*(?:-\s+)?/.exec(match[1])[0].length : Number.MAX_SAFE_INTEGER;
    let value = match[2];
    if (!value) {
      // A same-line `}`/`,` closes an empty flow value — no ref to pin.
      const rest = line.slice(match.index + match[0].length);
      if (lineStart || !/^\s*[}\],]/.test(rest)) {
        for (let j = index + 1; j < lines.length; j += 1) {
          const text = lines[j];
          if (text.trim() === "" || text.trimStart().startsWith("#")) continue;
          // Block values continue only at deeper indentation than the key.
          if (lineStart && text.match(/^ */)[0].length <= keyColumn) break;
          const closing = lineStart ? -1 : text.search(/[}\],]/);
          const token = /[^\s{}\[\],#]+/.exec(text);
          if (token && (closing < 0 || token.index < closing)) { value = token[0]; break; }
          break;
        }
      }
    }
    if (!value) continue; // `uses:` with no resolvable ref cannot run an action
    // Local actions (`uses: ./path`) run content from the checked-out ref and
    // carry no `@` pin; everything else must pin a full commit SHA.
    if (value.startsWith("./")) continue;
    const ref = value.includes("@") ? value.slice(value.lastIndexOf("@") + 1) : null;
    if (!ref || !/^[0-9a-f]{40}$/i.test(ref)) throw new Error(`${file}:${index + 1}: actions must be pinned to a full commit SHA`);
  }
}
console.log(`Validated ${files.length} workflow files for permissions and immutable actions.`);
