#!/usr/bin/env node
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(".github/workflows");
const files = (await readdir(root)).filter((file) => /\.ya?ml$/.test(file));
if (files.length === 0) throw new Error("no workflow files found");
for (const file of files) {
  const source = await readFile(path.join(root, file), "utf8");
  if (!/^permissions\s*:/m.test(source)) throw new Error(`${file}: top-level permissions are required`);
  for (const [index, line] of source.split("\n").entries()) {
    const match = line.match(/^\s*-?\s*uses:\s*[^@]+@([^\s#]+)/);
    if (match && !/^[0-9a-f]{40}$/i.test(match[1])) throw new Error(`${file}:${index + 1}: actions must be pinned to a full commit SHA`);
  }
}
console.log(`Validated ${files.length} workflow files for permissions and immutable actions.`);
