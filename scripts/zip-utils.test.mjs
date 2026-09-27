import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import zlib from "node:zlib";
import { readZip, writeZip } from "./zip-utils.mjs";

const LFH_SIG = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const CDFH_SIG = Buffer.from([0x50, 0x4b, 0x01, 0x02]);

// Minimal method-8 (deflate) archive — the local writer only emits stored
// entries, so inflate-path fixtures are assembled by hand.
function writeDeflateZip(file, name, payload, declaredUncomp) {
  const compressed = zlib.deflateRawSync(payload);
  const nameBuf = Buffer.from(name, "utf8");
  const lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0);
  lfh.writeUInt16LE(8, 8);
  lfh.writeUInt32LE(compressed.length, 18);
  lfh.writeUInt32LE(declaredUncomp, 22);
  lfh.writeUInt16LE(nameBuf.length, 26);
  const cdStart = lfh.length + nameBuf.length + compressed.length;
  const cdfh = Buffer.alloc(46);
  cdfh.writeUInt32LE(0x02014b50, 0);
  cdfh.writeUInt16LE(8, 10);
  cdfh.writeUInt32LE(compressed.length, 20);
  cdfh.writeUInt32LE(declaredUncomp, 24);
  cdfh.writeUInt16LE(nameBuf.length, 28);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cdfh.length + nameBuf.length, 12);
  eocd.writeUInt32LE(cdStart, 16);
  return writeFile(file, Buffer.concat([lfh, nameBuf, compressed, cdfh, nameBuf, eocd]));
}

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

test("readZip rejects out-of-bounds offsets with clean errors", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "zip-utils-"));
  try {
    const file = path.join(dir, "oob.zip");
    writeZip(file, [{ name: "a.txt", data: Buffer.from("abcd") }]);
    const bytes = Buffer.from(await readFile(file));
    // Point the EOCD's central-directory offset far past EOF — must fail with
    // a zip error, not a raw Buffer bounds exception.
    const oob = Buffer.from(bytes);
    oob.writeUInt32LE(0x00ff_ff00, oob.length - 6);
    await writeFile(file, oob);
    assert.throws(() => readZip(file), /bad central dir header/);
    // Point the central entry's local-header offset past EOF.
    const oobLocal = Buffer.from(bytes);
    const cd = oobLocal.indexOf(CDFH_SIG);
    oobLocal.writeUInt32LE(0x00ff_ff00, cd + 42);
    await writeFile(file, oobLocal);
    assert.throws(() => readZip(file), /bad local header/);
    // A buffer smaller than an EOCD record cannot contain one.
    await writeFile(file, Buffer.from("PK"));
    assert.throws(() => readZip(file), /not a valid zip/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("readZip bounds inflate output by the declared uncompressed size", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "zip-utils-"));
  try {
    // A correctly-declared deflate entry round-trips.
    const ok = path.join(dir, "ok-deflate.zip");
    const payload = Buffer.from("deflate me ".repeat(64));
    await writeDeflateZip(ok, "a.txt", payload, payload.length);
    const entries = readZip(ok);
    assert.equal(entries[0].data.toString("utf8"), payload.toString("utf8"));

    // The central directory under-declares uncompressedSize; the stream
    // inflates far beyond it. The decode must abort at the declared bound
    // instead of allocating the real expansion before the length check.
    const bomb = path.join(dir, "bomb.zip");
    await writeDeflateZip(bomb, "a.txt", Buffer.alloc(8 * 1024 * 1024, 0x41), 64);
    assert.throws(() => readZip(bomb));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
