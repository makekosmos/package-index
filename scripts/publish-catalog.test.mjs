import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { buildCatalogInput, inspectArchive, verifyPreviousPublication } from "./publish-catalog.mjs";
import { readZip, writeZip } from "../../cortex/desktop/scripts/zip-utils.mjs";

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
    const envelope = { schema_version: 1, bytes: bytes.toString("base64"), signatures };
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
    permissions: [], targets: [{ runtime: "worker", os: ["windows"] }], data: { access: [], defines: [], mappings: [] },
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

test("archive policy rejects traversal, collisions, missing license, and extra files", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "kosmos-archive-"));
  try {
    const spec = archiveSpec();
    const valid = path.join(dir, "valid.kspkg");
    await writeArchive(valid, spec);
    await assert.doesNotReject(() => inspectArchive(spec, valid, { readZip }, 8));
    const extra = path.join(dir, "extra.kspkg");
    await writeArchive(extra, spec, [{ name: "payload.exe", data: peFixture() }]);
    await assert.rejects(() => inspectArchive(spec, extra, { readZip }, 8), /unexpected/);
    const noLicense = path.join(dir, "no-license.kspkg");
    const noLicenseSpec = { ...spec, artifact: { name: "no-license.kspkg" } };
    writeZip(noLicense, [
      { name: "manifest.json", data: JSON.stringify(completeManifest(noLicenseSpec)) },
      { name: noLicenseSpec.entrypoint, data: peFixture() },
      { name: noLicenseSpec.icon, data: Buffer.from("icon") },
    ]);
    await assert.rejects(() => inspectArchive(noLicenseSpec, noLicense, { readZip }, 8), /license/);
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
    await assert.rejects(() => inspectArchive(spec, symlink, { readZip }, 8), /symlinks|special/);
    const bomb = path.join(dir, "ratio.kspkg");
    await writeArchive(bomb, spec);
    await mutateCentral(bomb, spec.entrypoint, (bytes, offset) => bytes.writeUInt32LE(1, offset + 20));
    await assert.rejects(() => inspectArchive(spec, bomb, { readZip }, 8), /compression ratio/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
