import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { buildCatalogInput, inspectArchive, verifyPreviousPublication } from "./publish-catalog.mjs";
import { readZip, writeZip } from "./test-zip-utils.mjs";

const fixture = JSON.parse(await readFile(new URL("../fixtures/catalog-input.json", import.meta.url), "utf8"));

function replacement(id = "com.kosmos.fixture") {
  return {
    manifest: structuredClone(fixture.packages[0].manifest),
    archive_url: "https://github.com/makekosmos/package-index/releases/download/catalog-8/fixture.kspkg",
    sha256: "b".repeat(64),
    size: 2048,
  };
}

test("replacement removes the old ID and preserves unrelated packages", () => {
  const previous = {
    ...structuredClone(fixture),
    sequence: 7,
    packages: [
      structuredClone(fixture.packages[0]),
      { ...structuredClone(fixture.packages[0]), manifest: { ...fixture.packages[0].manifest, id: "com.kosmos.untouched" } },
    ],
  };
  const next = buildCatalogInput(previous, [replacement()], {
    sequence: 8,
    issuedAt: "2026-08-29T00:00:00Z",
    expiresAt: "2026-09-29T00:00:00Z",
    retiredPackageIds: [],
    engineApiVersion: "1.5.0",
  });
  assert.deepEqual(next.packages.map((entry) => entry.manifest.id), ["com.kosmos.untouched", "com.kosmos.fixture"]);
  assert.equal(next.sequence, 8);
});

test("retirement of an unknown ID fails closed", () => {
  assert.throws(() => buildCatalogInput(fixture, [replacement()], {
    sequence: 8,
    issuedAt: "2026-08-29T00:00:00Z",
    expiresAt: "2026-09-29T00:00:00Z",
    retiredPackageIds: ["com.kosmos.typo"],
    engineApiVersion: "1.5.0",
  }), /not present in the previous catalog/);
});

test("active and retired IDs cannot overlap", () => {
  assert.throws(() => buildCatalogInput(fixture, [replacement()], {
    sequence: 8,
    issuedAt: "2026-08-29T00:00:00Z",
    expiresAt: "2026-09-29T00:00:00Z",
    retiredPackageIds: ["com.kosmos.fixture"],
    engineApiVersion: "1.5.0",
  }), /both active and retired/);
});

test("previous catalog requires exact envelope bytes, signatures, and key", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-previous-"));
  try {
    const catalogPath = path.join(dir, "catalog.json");
    const envelopePath = path.join(dir, "catalog.envelope.json");
    const signaturesPath = path.join(dir, "catalog.signatures.json");
    const bytes = Buffer.from(JSON.stringify(fixture, null, 2) + "\n");
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
    const signatures = { schema_version: 1, signatures: [{ key_id: "fixture-key", algorithm: "ed25519", signature: crypto.sign(null, bytes, privateKey).toString("base64") }] };
    const signature = signatures.signatures[0];
    const envelope = { bytes: bytes.toString("base64"), signatures: { schema_version: 1, signatures: [{ algorithm: signature.algorithm, key_id: signature.key_id, signature: signature.signature }] } };
    await writeFile(catalogPath, bytes);
    await writeFile(envelopePath, JSON.stringify(envelope));
    await writeFile(signaturesPath, JSON.stringify(signatures));
    await verifyPreviousPublication({ catalogPath, envelopePath, signaturesPath, publicKey: rawPublicKey, expectedSequence: 7, engineApiVersion: "1.5.0", signingKeyId: "fixture-key" });
    await assert.rejects(() => verifyPreviousPublication({ catalogPath, envelopePath: path.join(dir, "missing.json"), signaturesPath, publicKey: rawPublicKey, expectedSequence: 7, engineApiVersion: "1.5.0", signingKeyId: "fixture-key" }), /envelope is missing/);
    const { publicKey: wrongKey } = crypto.generateKeyPairSync("ed25519");
    const wrongRaw = wrongKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
    await assert.rejects(() => verifyPreviousPublication({ catalogPath, envelopePath, signaturesPath, publicKey: wrongRaw, expectedSequence: 7, engineApiVersion: "1.5.0", signingKeyId: "fixture-key" }), /signature verification failed/);
    await writeFile(catalogPath, Buffer.from("tampered"));
    await assert.rejects(() => verifyPreviousPublication({ catalogPath, envelopePath, signaturesPath, publicKey: rawPublicKey, expectedSequence: 7, engineApiVersion: "1.5.0", signingKeyId: "fixture-key" }), /payload mismatch/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function archiveSpec(overrides = {}) {
  return {
    id: "com.kosmos.fixture",
    manifest_id: "com.kosmos.fixture",
    kind: "source",
    engine_api: ">=1.0.0",
    version: "1.0.0",
    entrypoint: "fixture-worker.exe",
    icon: "icon.png",
    build: { provider: "fixture", target: "x86_64-pc-windows-msvc" },
    artifact: { name: "fixture.kspkg", url: "https://github.com/makekosmos/package-index/releases/download/catalog-8/fixture.kspkg" },
    ...overrides,
  };
}

function completeManifest(spec) {
  return {
    schema_version: 2, id: spec.manifest_id, name: "Fixture", version: spec.version, kind: spec.kind,
    engine_api: spec.engine_api, entrypoint: spec.entrypoint, icon: spec.icon, publisher: "kosmos",
    permissions: [], targets: spec.targets ?? [{ runtime: spec.kind === "app" ? "kosmos-host" : "worker", os: ["windows"] }], data: { access: [], defines: [], mappings: [] },
  };
}

function peFixture() {
  const bytes = Buffer.alloc(128);
  bytes.write("MZ", 0, "ascii");
  bytes.writeUInt32LE(64, 0x3c);
  bytes.writeUInt32LE(0x00004550, 64);
  bytes.writeUInt16LE(0x8664, 68);
  return bytes;
}

async function writeArchive(file, spec = archiveSpec(), extras = []) {
  writeZip(file, [
    { name: "manifest.json", data: JSON.stringify(completeManifest(spec)) },
    { name: spec.entrypoint, data: peFixture() },
    { name: spec.icon, data: Buffer.from("icon") },
    { name: "LICENSE.txt", data: Buffer.from("license") },
    ...extras,
  ]);
}

async function mutateCentral(file, entryName, mutate) {
  const bytes = Buffer.from(await readFile(file));
  for (let offset = 0; offset + 46 <= bytes.length; offset += 1) {
    if (bytes.readUInt32LE(offset) !== 0x02014b50) continue;
    const nameLength = bytes.readUInt16LE(offset + 28);
    const name = bytes.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    if (name === entryName) mutate(bytes, offset);
  }
  await writeFile(file, bytes);
}

test("archive policy rejects traversal, collisions, and extra files", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-archive-"));
  try {
    const spec = archiveSpec();
    const valid = path.join(dir, "valid.kspkg");
    await writeArchive(valid, spec);
    await assert.doesNotReject(() => inspectArchive(spec, valid, { readZip }, 8));
    const app = path.join(dir, "app.kspkg");
    const appSpec = archiveSpec({ kind: "app", entrypoint: "dist/index.html", build: undefined, artifact: { name: "app.kspkg", url: "https://example.test/app.kspkg" } });
    const appManifest = completeManifest(appSpec);
    appManifest.targets.push({ runtime: "worker", os: ["windows"], entrypoint: "worker/fixture-worker.exe" });
    writeZip(app, [
      { name: "dist/", data: Buffer.alloc(0), externalAttributes: 0x10 },
      { name: "dist/assets/", data: Buffer.alloc(0), externalAttributes: 0x41ff0000 },
      { name: "dist/index.html", data: Buffer.from("app") },
      { name: "dist/assets/app.js", data: Buffer.from("js") },
      { name: "icon.png", data: Buffer.from("icon") },
      { name: "manifest.json", data: JSON.stringify(appManifest) },
      { name: "compatibility.json", data: JSON.stringify({ schema_version: 1 }) },
      { name: "provenance.json", data: JSON.stringify({ schema_version: 1, source_commit: "a".repeat(40) }) },
      { name: "schemas/", data: Buffer.alloc(0), externalAttributes: 0x10 },
      { name: "schemas/example.json", data: Buffer.from("{}") },
      { name: "worker/fixture-worker.exe", data: peFixture() },
    ]);
    const inspectedApp = await inspectArchive(appSpec, app, { readZip }, 8);
    assert.equal(inspectedApp.archive_url, "https://github.com/makekosmos/package-index/releases/download/catalog-8/app.kspkg");
    const unsafeWorker = path.join(dir, "unsafe-worker.kspkg");
    const unsafeWorkerSpec = archiveSpec({ kind: "app", entrypoint: "dist/index.html", build: undefined, artifact: { name: "unsafe-worker.kspkg" }, targets: [{ runtime: "kosmos-host", os: ["windows"] }, { runtime: "worker", os: ["windows"], entrypoint: "../escape.exe" }] });
    await writeArchive(unsafeWorker, unsafeWorkerSpec);
    await assert.rejects(() => inspectArchive(unsafeWorkerSpec, unsafeWorker, { readZip }, 8), /unsafe/);
    const nonPeWorker = path.join(dir, "non-pe-worker.kspkg");
    const nonPeWorkerSpec = archiveSpec({ kind: "app", entrypoint: "dist/index.html", build: undefined, artifact: { name: "non-pe-worker.kspkg" }, targets: [{ runtime: "kosmos-host", os: ["windows"] }, { runtime: "worker", os: ["windows"], entrypoint: "worker/fixture-worker.exe" }] });
    writeZip(nonPeWorker, [
      { name: "dist/", data: Buffer.alloc(0), externalAttributes: 0x10 },
      { name: "dist/index.html", data: Buffer.from("app") },
      { name: "icon.png", data: Buffer.from("icon") },
      { name: "manifest.json", data: JSON.stringify(completeManifest(nonPeWorkerSpec)) },
      { name: "worker/fixture-worker.exe", data: Buffer.from("not a PE") },
    ]);
    await assert.rejects(() => inspectArchive(nonPeWorkerSpec, nonPeWorker, { readZip }, 8), /PE executable/);
    const extra = path.join(dir, "extra.kspkg");
    await writeArchive(extra, spec, [{ name: "payload.exe", data: peFixture() }]);
    await assert.rejects(() => inspectArchive(spec, extra, { readZip }, 8), /unexpected/);
    const traversal = path.join(dir, "traversal.kspkg");
    await writeArchive(traversal, spec, [{ name: "../escape.txt", data: Buffer.from("x") }]);
    await assert.rejects(() => inspectArchive(spec, traversal, { readZip }, 8), /unsafe|unexpected/);
    const collision = path.join(dir, "collision.kspkg");
    await writeArchive(collision, spec, [{ name: "ICON.PNG", data: Buffer.from("collision") }]);
    await assert.rejects(() => inspectArchive(spec, collision, { readZip }, 8), /collide|unexpected/);
    const unsafeEntrypoint = path.join(dir, "unsafe-entrypoint.kspkg");
    const unsafeSpec = archiveSpec({ entrypoint: "CON.exe", artifact: { name: "unsafe-entrypoint.kspkg" } });
    await writeArchive(unsafeEntrypoint, unsafeSpec);
    await assert.rejects(() => inspectArchive(unsafeSpec, unsafeEntrypoint, { readZip }, 8), /unsafe/);
    const wrongPe = path.join(dir, "wrong-pe.kspkg");
    const wrongPeSpec = archiveSpec({ artifact: { name: "wrong-pe.kspkg" } });
    const badPe = Buffer.from(peFixture());
    badPe.writeUInt16LE(0x014c, 68);
    writeZip(wrongPe, [
      { name: "manifest.json", data: JSON.stringify(completeManifest(wrongPeSpec)) },
      { name: wrongPeSpec.entrypoint, data: badPe },
      { name: wrongPeSpec.icon, data: Buffer.from("icon") },
      { name: "LICENSE.txt", data: Buffer.from("license") },
    ]);
    await assert.rejects(() => inspectArchive(wrongPeSpec, wrongPe, { readZip }, 8), /PE executable/);
    const symlink = path.join(dir, "symlink.kspkg");
    await writeArchive(symlink, spec);
    await mutateCentral(symlink, spec.entrypoint, (bytes, offset) => bytes.writeUInt32LE(0xa0000000, offset + 38));
    await assert.rejects(() => inspectArchive(spec, symlink, { readZip }, 8), /file type/);
    const encrypted = path.join(dir, "encrypted.kspkg");
    await writeArchive(encrypted, spec);
    await mutateCentral(encrypted, spec.entrypoint, (bytes, offset) => bytes.writeUInt16LE(1, offset + 8));
    await assert.rejects(() => inspectArchive(spec, encrypted, { readZip }, 8), /encrypted/);
    const reparse = path.join(dir, "reparse.kspkg");
    await writeArchive(reparse, spec);
    await mutateCentral(reparse, spec.entrypoint, (bytes, offset) => bytes.writeUInt32LE(0x400, offset + 38));
    await assert.rejects(() => inspectArchive(spec, reparse, { readZip }, 8), /reparse/);
    const bomb = path.join(dir, "ratio.kspkg");
    await writeArchive(bomb, spec);
    await mutateCentral(bomb, spec.entrypoint, (bytes, offset) => bytes.writeUInt32LE(1, offset + 20));
    await assert.rejects(() => inspectArchive(spec, bomb, { readZip }, 8), /compression ratio/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a worker target declaring the package entrypoint is not double-counted", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-archive-"));
  try {
    // Source manifests may declare their worker target's entrypoint — the
    // same file as spec.entrypoint. The expected-file list must dedupe it or
    // a conforming archive fails the exact-match check.
    const spec = archiveSpec({
      artifact: { name: "declared-worker.kspkg" },
      targets: [{ runtime: "worker", os: ["windows"], entrypoint: "fixture-worker.exe" }],
    });
    const file = path.join(dir, "declared-worker.kspkg");
    await writeArchive(file, spec);
    const inspected = await inspectArchive(spec, file, { readZip }, 8);
    assert.equal(inspected.manifest.id, spec.manifest_id);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a sub-EOCD-length archive fails cleanly instead of crashing", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-archive-"));
  try {
    const spec = archiveSpec({ artifact: { name: "tiny.kspkg" } });
    const tiny = path.join(dir, "tiny.kspkg");
    await writeFile(tiny, Buffer.from("PK"));
    await assert.rejects(() => inspectArchive(spec, tiny, { readZip }, 8), /end-of-central-directory/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an EOCD signature inside the archive comment cannot shadow entries", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-archive-"));
  try {
    const spec = archiveSpec({ artifact: { name: "shadowed.kspkg" } });
    const file = path.join(dir, "shadowed.kspkg");
    writeZip(file, [
      { name: "manifest.json", data: JSON.stringify(completeManifest(spec)) },
      { name: spec.entrypoint, data: peFixture() },
      { name: spec.icon, data: Buffer.from("icon") },
      { name: "evil.exe", data: peFixture() },
      { name: "../traversal.txt", data: Buffer.from("escape") },
    ]);
    const bytes = Buffer.from(await readFile(file));
    const eocd = bytes.length - 22;
    // A second EOCD-shaped record inside the real record's comment claims a
    // three-entry directory: a scan that stops at the last signature sees a
    // clean archive while resyncing readers extract evil.exe and the
    // traversal path. The entry set must not depend on the consumer's scan.
    const fake = Buffer.alloc(22);
    fake.writeUInt32LE(0x06054b50, 0);
    fake.writeUInt16LE(3, 10);
    fake.writeUInt32LE(3 * 46 + "manifest.json".length + spec.entrypoint.length + spec.icon.length, 12);
    fake.writeUInt32LE(bytes.readUInt32LE(eocd + 16), 16);
    fake.writeUInt16LE(0, 20);
    const comment = Buffer.concat([fake, Buffer.alloc(8, 0x20)]);
    bytes.writeUInt16LE(comment.length, eocd + 20);
    await writeFile(file, Buffer.concat([bytes, comment]));
    await assert.rejects(() => inspectArchive(spec, file, { readZip }, 8), /end-of-central-directory/);

    // A trailing record that also reaches EOF leaves two self-consistent
    // EOCDs — ambiguous, not authoritative for either declaration.
    const ambiguous = path.join(dir, "ambiguous.kspkg");
    await writeArchive(ambiguous, spec);
    const amb = Buffer.from(await readFile(ambiguous));
    const ambEocd = amb.length - 22;
    const tail = Buffer.alloc(22);
    tail.writeUInt32LE(0x06054b50, 0);
    tail.writeUInt16LE(4, 10);
    tail.writeUInt32LE(amb.readUInt32LE(ambEocd + 12), 12);
    tail.writeUInt32LE(amb.readUInt32LE(ambEocd + 16), 16);
    tail.writeUInt16LE(8, 20);
    const ambComment = Buffer.concat([tail, Buffer.alloc(8)]);
    amb.writeUInt16LE(ambComment.length, ambEocd + 20);
    await writeFile(ambiguous, Buffer.concat([amb, ambComment]));
    await assert.rejects(() => inspectArchive(archiveSpec({ artifact: { name: "ambiguous.kspkg" } }), ambiguous, { readZip }, 8), /ambiguous/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("Windows-aliased archive names cannot evade executable screening", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-alias-"));
  try {
    // A component ending in "." or " " is stripped by Win32 path normalization:
    // "evil.exe." and "evil.exe " both materialize as evil.exe, but a naive
    // /\.exe$/ check skips them — the PE gate and the unexpected-executable
    // denylist must not let them through.
    for (const [label, entrypoint] of [
      ["trailing space", "worker/evil.exe "],
      ["trailing dot", "worker/evil.exe."],
      ["reserved device", "worker/CONIN$"],
    ]) {
      const spec = archiveSpec({
        kind: "app",
        entrypoint: "dist/index.html",
        build: undefined,
        artifact: { name: `${label.replace(" ", "-")}.kspkg` },
        targets: [
          { runtime: "kosmos-host", os: ["windows"] },
          { runtime: "worker", os: ["windows"], entrypoint },
        ],
      });
      const file = path.join(dir, `${label.replace(" ", "-")}.kspkg`);
      writeZip(file, [
        { name: "dist/", data: Buffer.alloc(0), externalAttributes: 0x10 },
        { name: "dist/index.html", data: Buffer.from("app") },
        { name: "icon.png", data: Buffer.from("icon") },
        { name: "manifest.json", data: JSON.stringify(completeManifest(spec)) },
        { name: entrypoint, data: Buffer.from("not a PE executable") },
      ]);
      await assert.rejects(() => inspectArchive(spec, file, { readZip }, 8), /unsafe|unexpected/i, label);
    }
    // A declared worker entrypoint of another executable type is still a PE
    // image and must be verified, not exempted by the /\.exe$/ gate.
    const dllSpec = archiveSpec({
      kind: "app",
      entrypoint: "dist/index.html",
      build: undefined,
      artifact: { name: "dll-worker.kspkg" },
      targets: [
        { runtime: "kosmos-host", os: ["windows"] },
        { runtime: "worker", os: ["windows"], entrypoint: "worker/helper.dll" },
      ],
    });
    const dllFile = path.join(dir, "dll-worker.kspkg");
    writeZip(dllFile, [
      { name: "dist/", data: Buffer.alloc(0), externalAttributes: 0x10 },
      { name: "dist/index.html", data: Buffer.from("app") },
      { name: "icon.png", data: Buffer.from("icon") },
      { name: "manifest.json", data: JSON.stringify(completeManifest(dllSpec)) },
      { name: "worker/helper.dll", data: Buffer.from("not a PE either") },
    ]);
    await assert.rejects(() => inspectArchive(dllSpec, dllFile, { readZip }, 8), /PE executable/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
