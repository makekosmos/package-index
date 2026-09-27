import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { readZip, writeZip } from "./zip-utils.mjs";

const LFH_SIG = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const CDFH_SIG = Buffer.from([0x50, 0x4b, 0x01, 0x02]);

test("readZip round-trips a valid archive", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "zip-utils-"));
  try {
    const file = path.join(dir, "ok.zip");
    writeZip(file, [
      { name: "manifest.json", data: Buffer.from("{}") },
      { name: "a.txt", data: Buffer.from("abcd") },
    ]);
    const entries = readZip(file);
    assert.deepEqual(entries.map((entry) => entry.name), ["manifest.json", "a.txt"]);
    assert.equal(entries[1].data.toString("utf8"), "abcd");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("readZip rejects a local-header name that differs from the central entry", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "zip-utils-"));
  try {
    const file = path.join(dir, "name-mismatch.zip");
    writeZip(file, [{ name: "manifest.json", data: Buffer.from("{}") }]);
    const bytes = Buffer.from(await readFile(file));
    assert.equal(bytes.indexOf(LFH_SIG), 0);
    bytes.subarray(30, 30 + "manifest.json".length).set(Buffer.from("nanifest.jso"));
    await writeFile(file, bytes);
    assert.throws(() => readZip(file), /local header does not match central directory/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("readZip rejects a local-header method that differs from the central entry", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "zip-utils-"));
  try {
    const file = path.join(dir, "method-mismatch.zip");
    writeZip(file, [{ name: "a.txt", data: Buffer.from("abcd") }]);
    const bytes = Buffer.from(await readFile(file));
    assert.equal(bytes.indexOf(LFH_SIG), 0);
    bytes.writeUInt16LE(8, 8); // local method stored -> deflate, payload untouched
    await writeFile(file, bytes);
    assert.throws(() => readZip(file), /local header does not match central directory/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("readZip rejects a central uncompressed size that disagrees with the data", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "zip-utils-"));
  try {
    const file = path.join(dir, "size-lie.zip");
    writeZip(file, [{ name: "a.txt", data: Buffer.from("abcd") }]);
    const bytes = Buffer.from(await readFile(file));
    const cd = bytes.indexOf(CDFH_SIG);
    assert.notEqual(cd, -1);
    bytes.writeUInt32LE(100, cd + 24); // central uncompressedSize 4 -> 100
    await writeFile(file, bytes);
    assert.throws(() => readZip(file), /size mismatch/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
