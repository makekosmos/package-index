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
  const bom = await loadBom(bomPath, { expectedSequence: 22, allowPendingBuilds: true });
  assert.equal(bom.packages.length, 12);
  assert.equal(bom.packages.filter((entry) => entry.kind === "app").length, 5);
  assert.equal(bom.packages.filter((entry) => entry.kind === "source").length, 7);
  assert.ok(bom.packages.every((entry) => /^[0-9a-f]{40}$/i.test(entry.ref)));
  assert.match(bom.source.core.ark_artifact.sha256, /^[0-9a-f]{64}$/);
});

test("reviewed BOM pins the authorized Store commit and envelope sequence", async () => {
  const bom = await loadBom(bomPath, { expectedSequence: 22, allowPendingBuilds: true });
  assert.equal(bom.source.store.commit, "2e6afcbc6c27514e9841a260005d92cb81e038c6");
  assert.equal(bom.catalog.store_sequence, 16);
});

test("source package builds use committed Cargo locks", () => {
  assert.match(builder, /"--locked"/);
});

test("builder uses the vendored zip-utils, not a Cortex checkout", () => {
  assert.match(builder, /"\.\/zip-utils\.mjs"/);
  assert.doesNotMatch(builder, /desktop[\\/]scripts[\\/]zip-utils/);
});

test("source packages must match a pinned source repository", async () => {
  const drifted = JSON.parse(await readFile(bomPath, "utf8"));
  drifted.packages.find((entry) => entry.kind === "source").ref = "0".repeat(40);
  assert.throws(() => validateBom(drifted, { allowPendingBuilds: true }), /pinned source repository/);

  const moved = JSON.parse(await readFile(bomPath, "utf8"));
  moved.source.integrations = { repository: "makekosmos/integrations", commit: "e".repeat(40) };
  for (const entry of moved.packages.filter((item) => item.kind === "source")) {
    entry.repository = "makekosmos/integrations";
    entry.ref = "e".repeat(40);
  }
  assert.doesNotThrow(() => validateBom(moved, { allowPendingBuilds: true }));

  const mutable = JSON.parse(await readFile(bomPath, "utf8"));
  mutable.source.integrations = { repository: "makekosmos/integrations", commit: "main" };
  assert.throws(() => validateBom(mutable, { allowPendingBuilds: true }), /immutable commit SHA/);

  const traversal = JSON.parse(await readFile(bomPath, "utf8"));
  traversal.packages.find((entry) => entry.kind === "source").build.provider = "../escape";
  assert.throws(() => validateBom(traversal, { allowPendingBuilds: true }), /build\.provider/);
});

test("artifact names cannot evade the publish glob or download pattern", async () => {
  // Artifact names land in `out/` and move by pattern/enumeration:
  // `gh release download --pattern` treats `*`/`?`/`[` as wildcards and a
  // leading `.` is not a portable basename — such names would publish a
  // release inconsistent with the catalog, or pull uninspected sibling
  // assets into it.
  for (const bad of [".hidden.kspkg", "..x.kspkg", "all*.kspkg", "x?.kspkg", "list[0].kspkg", "my file.kspkg", "-x.kspkg"]) {
    const bom = JSON.parse(await readFile(bomPath, "utf8"));
    bom.packages[0].artifact.name = bad;
    bom.packages[0].artifact.url = `https://github.com/makekosmos/arcadia/releases/download/v0.1.11/${bad}`;
    assert.throws(() => validateBom(bom, { allowPendingBuilds: true }), /artifact name/, bad);
  }
  const bom = JSON.parse(await readFile(bomPath, "utf8"));
  bom.artifacts.push({ name: ".release-notes.md", sha256: "a".repeat(64), size: 1 });
  assert.throws(() => validateBom(bom, { allowPendingBuilds: true }), /unique portable basenames/);
});

test("pending source artifacts are rejected unless explicitly allowed", async () => {
  const bom = JSON.parse(await readFile(bomPath, "utf8"));
  delete bom.packages.find((entry) => entry.kind === "source").artifact.sha256;
  delete bom.packages.find((entry) => entry.kind === "source").artifact.size;
  assert.throws(() => validateBom(bom), /artifact\.sha256 is required/);
  assert.doesNotThrow(() => validateBom(bom, { allowPendingBuilds: true }));
});

test("pending source artifacts still reject malformed declared fields", async () => {
  // The pending exemption covers absent metadata — a sha256 or size that is
  // declared must still satisfy the artifact contract.
  for (const [sha256, size] of [["not-a-sha256", undefined], ["z".repeat(64), undefined], [undefined, "not-a-number"], [undefined, -4], [undefined, 1.5]]) {
    const bom = JSON.parse(await readFile(bomPath, "utf8"));
    const artifact = bom.packages.find((entry) => entry.kind === "source").artifact;
    delete artifact.sha256;
    delete artifact.size;
    if (sha256 !== undefined) artifact.sha256 = sha256;
    if (size !== undefined) artifact.size = size;
    assert.throws(() => validateBom(bom, { allowPendingBuilds: true }), /SHA-256|size/);
  }
  // A declared-but-valid sha256 with size still pending remains allowed.
  const bom = JSON.parse(await readFile(bomPath, "utf8"));
  const artifact = bom.packages.find((entry) => entry.kind === "source").artifact;
  artifact.sha256 = "a".repeat(64);
  delete artifact.size;
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

test("entrypoint and icon must satisfy the archive path contract", async () => {
  // The source builder resolves icon/entrypoint under packages/<provider>/
  // with path.join and publishes them as archive members — traversal or
  // unsafe components must fail at review, not mid-publish.
  for (const bad of ["../escape.txt", "../../outside", "a/../icon.png", "/abs/icon.png", "C:/icon.png", "a\\icon.png", "sub//icon.png", "icon.png.", "icon.png ", "con.png"]) {
    const bom = JSON.parse(await readFile(bomPath, "utf8"));
    bom.packages.find((entry) => entry.kind === "source").icon = bad;
    assert.throws(() => validateBom(bom, { allowPendingBuilds: true }), /icon.*safe relative POSIX path|icon.*unsafe path component/, bad);
  }
  // An app entrypoint outside dist/ can never satisfy the catalog manifest
  // contract; a source entrypoint that is not a flat *.exe name can never be
  // produced by the `cargo --bin` build the workflow runs.
  const app = JSON.parse(await readFile(bomPath, "utf8"));
  app.packages.find((entry) => entry.kind === "app").entrypoint = "evil.exe";
  assert.throws(() => validateBom(app, { allowPendingBuilds: true }), /entrypoint must be under dist\//);
  for (const bad of ["worker", "sub/dir.exe", "worker.dll", "../w.exe"]) {
    const bom = JSON.parse(await readFile(bomPath, "utf8"));
    bom.packages.find((entry) => entry.kind === "source").entrypoint = bad;
    assert.throws(() => validateBom(bom, { allowPendingBuilds: true }), /entrypoint/, bad);
  }
});

test("package artifact names must be unique and disjoint from declared artifacts", async () => {
  const bom = JSON.parse(await readFile(bomPath, "utf8"));
  bom.packages[1].artifact.name = bom.packages[0].artifact.name;
  bom.packages[1].artifact.url = `https://github.com/makekosmos/dictation/releases/download/v0.2.5/${bom.packages[0].artifact.name}`;
  assert.throws(() => validateBom(bom, { allowPendingBuilds: true }), /duplicate artifact name/);

  const colliding = JSON.parse(await readFile(bomPath, "utf8"));
  colliding.artifacts.push({ name: colliding.packages[0].artifact.name, sha256: "a".repeat(64), size: 1 });
  assert.throws(() => validateBom(colliding, { allowPendingBuilds: true }), /collides with a package artifact/);
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
        toolchain: { pnpm: "12.4.1", node: "1.0.0", rust: "1.0.0", target: "x86_64-pc-windows-msvc" },
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

    // Declared release artifacts (bom.artifacts) must be verified too.
    await writeFile(path.join(directory, "fixture.kspkg"), bytes);
    const extra = Buffer.from("release sidecar");
    bom.artifacts.push({ name: "sidecar.bin", sha256: createHash("sha256").update(extra).digest("hex"), size: extra.length });
    await assert.rejects(() => verifyArtifacts(bom, directory), /artifact is missing: sidecar\.bin/);
    await writeFile(path.join(directory, "sidecar.bin"), extra);
    await verifyArtifacts(bom, directory);
    await writeFile(path.join(directory, "sidecar.bin"), Buffer.from("corrupt sidecar!!"));
    await assert.rejects(() => verifyArtifacts(bom, directory), /sidecar\.bin: artifact (size|SHA-256) mismatch/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
