import test from "node:test";
import assert from "node:assert/strict";
import { findSecrets } from "./check-secrets.mjs";

test("rejects private keys and literal production credentials", () => {
  const source = "-----BEGIN " + "PRIVATE KEY-----\n" + ["password", "correct-horse-battery-staple"].join(": ") + "\n";
  assert.equal(findSecrets(source, "fixture.txt").length, 2);
});

test("allows documented secret references and placeholders", () => {
  const source = "token: ${{ secrets.RELEASE_TOKEN }}\npassword: replace-me\n";
  assert.deepEqual(findSecrets(source, "fixture.yml"), []);
});
