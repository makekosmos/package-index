import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { buildCatalogInput } from "./publish-catalog.mjs";

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
