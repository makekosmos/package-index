import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { loadBom, validateBom, verifyArtifacts } from "./validate-bom.mjs";

const root = path.resolve(import.meta.dirname, "..");
const bomPath = path.join(root, "release", "bom.v1.json");
const builder = await readFile(path.join(root, "scripts", "build-source-packages.mjs"), "utf8");

test("checked-in BOM is v1 and contains all catalog package inputs", async () => {
  const bom = await loadBom(bomPath, { expectedSequence: 14, allowPendingBuilds: true });
  assert.equal(bom.packages.length, 11);
  assert.equal(bom.packages.filter((entry) => entry.kind === "app").length, 5);
  assert.equal(bom.packages.filter((entry) => entry.kind === "source").length, 6);
  assert.ok(bom.packages.every((entry) => /^[0-9a-f]{40}$/i.test(entry.ref)));
  assert.match(bom.source.core.ark_artifact.sha256, /^[0-9a-f]{64}$/);
});

test("reviewed BOM pins the authorized Store commit and envelope sequence", async () => {
  const bom = await loadBom(bomPath, { expectedSequence: 14, allowPendingBuilds: true });
  assert.equal(bom.source.store.commit, "2426064ff656b0cf8c636c472aa4817ae1530603");
  assert.equal(bom.catalog.store_sequence, 14);
});

test("source package builds use committed Cargo locks", () => {
  assert.match(builder, /"--locked"/);
});

test("pending source artifacts are rejected unless explicitly allowed", async () => {
  const bom = JSON.parse(await readFile(bomPath, "utf8"));
  assert.throws(() => validateBom(bom), /artifact\.sha256 is required/);
  assert.doesNotThrow(() => validateBom(bom, { allowPendingBuilds: true }));
});

test("duplicate IDs and mutable refs fail closed", async () => {
  const bom = JSON.parse(await readFile(bomPath, "utf8"));
  bom.packages[1].id = bom.packages[0].id;
  assert.throws(() => validateBom(bom, { allowPendingBuilds: true }), /duplicate package ID/);

  const mutable = JSON.parse(await readFile(bomPath, "utf8"));
  mutable.packages[0].ref = "main";
  assert.throws(() => validateBom(mutable, { allowPendingBuilds: true }), /full immutable commit SHA/);

  const incompatible = JSON.parse(await readFile(bomPath, "utf8"));
  incompatible.packages[0].engine_api = ">=2.0.0";
  assert.throws(() => validateBom(incompatible, { allowPendingBuilds: true }), /incompatible engine API/);

  const secret = JSON.parse(await readFile(bomPath, "utf8"));
  secret.signing = { private_key: "never" };
  assert.throws(() => validateBom(secret, { allowPendingBuilds: true }), /private material/);

  const declarative = JSON.parse(await readFile(bomPath, "utf8"));
  declarative.metadata = { secret_setting: "session" };
  assert.doesNotThrow(() => validateBom(declarative, { allowPendingBuilds: true }));
});

test("artifact verification checks both size and SHA-256", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "kosmos-bom-"));
  try {
    const bytes = Buffer.from("fixture archive");
    const bom = {
      schema_version: 1,
      state: "resolved",
      id: "fixture",
      release: { version: "1.0.0", channel: "test", platform: "win" },
      source: {
        cortex: { repository: "makekosmos/cortex", commit: "1111111111111111111111111111111111111111" },
        core: { repository: "makekosmos/core", commit: "2222222222222222222222222222222222222222", ark_artifact: { name: "ark-core-rpc.exe", sha256: "2".repeat(64), size: 1 } },
        arca_sdk: { repository: "makekosmos/arca-sdk", commit: "3333333333333333333333333333333333333333", package: { name: "@makekosmos/ark", version: "1.0.0", integrity: "git:3333333333333333333333333333333333333333" } },
        imago: { repository: "makekosmos/imago", commit: "4444444444444444444444444444444444444444", package: { name: "@makekosmos/visuals", version: "1.0.0", integrity: "git:4444444444444444444444444444444444444444" } },
        store: { repository: "makekosmos/store", commit: "6666666666666666666666666666666666666666" },
        toolchain: { bun: "1.0.0", node: "1.0.0", rust: "1.0.0", target: "x86_64-pc-windows-msvc" },
      },
      compatibility: { shell_api: "1.0.0", engine_api: "1.0.0", package_schema: 2 },
      catalog: { sequence: 2, previous_sequence: 1, store_sequence: 1, channel: "test", signing_key_id: "test" },
      retired_package_ids: [],
      packages: [{
        id: "com.kosmos.fixture",
        manifest_id: "com.kosmos.fixture",
        kind: "app",
        engine_api: ">=1.0.0",
        version: "1.0.0",
        repository: "makekosmos/fixture",
        ref: "5555555555555555555555555555555555555555",
        release_tag: "v1.0.0",
        entrypoint: "dist/index.html",
        icon: "icon.png",
        artifact: {
          name: "fixture.kspkg",
          url: "https://github.com/makekosmos/package-index/releases/download/catalog-2/fixture.kspkg",
          sha256: createHash("sha256").update(bytes).digest("hex"),
          size: bytes.length,
        },
      }],
      artifacts: [],
    };
    await writeFile(path.join(directory, "fixture.kspkg"), bytes);
    validateBom(bom);
    await verifyArtifacts(bom, directory);
    await writeFile(path.join(directory, "fixture.kspkg"), Buffer.from("tampered"));
    await assert.rejects(() => verifyArtifacts(bom, directory), /artifact size mismatch|artifact SHA-256 mismatch/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
