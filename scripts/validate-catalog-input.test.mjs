import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import { validateCatalog, verifyEnvelope } from "./validate-catalog-input.mjs";

const catalog = JSON.parse(await readFile(new URL("../fixtures/catalog-input.json", import.meta.url), "utf8"));
const bytes = Buffer.from(JSON.stringify(catalog, null, 2) + "\n");

function copy() {
  return structuredClone(catalog);
}

test("accepts valid fixture and bounded engine API range", () => {
  assert.equal(validateCatalog(catalog, { previousSequence: 6, engineApiVersion: "1.5.0" }), true);
  const bridgeCatalog = copy();
  bridgeCatalog.packages[0].manifest.kind = "bridge";
  assert.equal(validateCatalog(bridgeCatalog), true);
});

for (const [name, mutate, expected] of [
  ["duplicate IDs", (c) => { c.packages.push(structuredClone(c.packages[0])); }, /duplicate/],
  ["invalid manifest", (c) => { c.packages[0].manifest.schema_version = 1; }, /Manifest v2/],
  ["bad hash", (c) => { c.packages[0].sha256 = "bad"; }, /sha256/],
  ["incompatible Engine API", (c) => {}, /Engine API/],
  ["non-monotonic sequence", (c) => {}, /greater/],
  ["invalid timestamps", (c) => { c.issued_at = "not-a-date"; }, /timestamps/],
]) {
  test(name, () => {
    const c = copy();
    if (name === "incompatible Engine API") assert.throws(() => validateCatalog(c, { engineApiVersion: "2.0.0" }), expected);
    else if (name === "non-monotonic sequence") assert.throws(() => validateCatalog(c, { previousSequence: c.sequence }), expected);
    else {
      mutate(c);
      assert.throws(() => validateCatalog(c), expected);
    }
  });
}

test("rejects a tampered envelope signature", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const envelope = {
    schema_version: 1,
    sequence: catalog.sequence,
    payload_sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    signature: crypto.sign(null, bytes, privateKey).toString("base64"),
  };
  verifyEnvelope(bytes, envelope, publicKey);
  const altered = Buffer.from(bytes);
  altered[altered.length - 2] ^= 1;
  assert.throws(() => verifyEnvelope(altered, envelope, publicKey), /hash mismatch|verification/);
});

test("verifies Cortex bytes-and-signatures envelope", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const envelope = {
    schema_version: 1,
    bytes: bytes.toString("base64"),
    signatures: [{
      key_id: "fixture",
      algorithm: "ed25519",
      signature: crypto.sign(null, bytes, privateKey).toString("base64"),
    }],
  };
  assert.equal(verifyEnvelope(bytes, envelope, publicKey), true);
  envelope.bytes = Buffer.from("tampered").toString("base64");
  assert.throws(() => verifyEnvelope(bytes, envelope, publicKey), /payload mismatch/);
});
