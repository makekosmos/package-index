#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

// A `uses` key invokes an action. YAML accepts the key in several spellings —
// quoted (`"uses":`), separated from the colon (`uses :`), anchored or tagged
// (`- &a uses:`), and inside a flow mapping (`- {uses: ...}`) — and every
// spelling still executes the referenced action. Capture the whole value so
// that `uses:` lines WITHOUT an `@<ref>` — a bare action name or a
// `docker://image:tag` — cannot slip past the pin check.
const USES_KEY = /(?:^\s*(?:-\s+)?(?:[&!*][^\s#]+\s+)*|[{,]\s*)["']?uses["']?\s*:\s*([^\s#},]+)/;

const root = path.resolve(".github/workflows");
const files = (await readdir(root)).filter((file) => /\.ya?ml$/.test(file));
if (files.length === 0) throw new Error("no workflow files found");
for (const file of files) {
  const source = await readFile(path.join(root, file), "utf8");
  if (!/^permissions\s*:/m.test(source)) throw new Error(`${file}: top-level permissions are required`);
  for (const [index, line] of source.split("\n").entries()) {
    const match = USES_KEY.exec(line);
    if (!match) continue;
    // Local actions (`uses: ./path`) run content from the checked-out ref and
    // carry no `@` pin; everything else must pin a full commit SHA.
    if (match[1].startsWith("./")) continue;
    const ref = match[1].includes("@") ? match[1].slice(match[1].lastIndexOf("@") + 1) : null;
    if (!ref || !/^[0-9a-f]{40}$/i.test(ref)) throw new Error(`${file}:${index + 1}: actions must be pinned to a full commit SHA`);
  }
}
console.log(`Validated ${files.length} workflow files for permissions and immutable actions.`);
