#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import crypto from "node:crypto";
import { validateCatalog, verifyEnvelope } from "./validate-catalog-input.mjs";

const catalogBytes = await readFile(new URL("../fixtures/catalog-input.json", import.meta.url));
const catalog = JSON.parse(catalogBytes);
validateCatalog(catalog, { previousSequence: catalog.sequence - 1, engineApiVersion: "1.5.0" });

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const signature = crypto.sign(null, catalogBytes, privateKey);
const envelope = {
  schema_version: 1,
  sequence: catalog.sequence,
  payload_sha256: crypto.createHash("sha256").update(catalogBytes).digest("hex"),
  signature: signature.toString("base64"),
};
verifyEnvelope(catalogBytes, envelope, publicKey);
console.log("Dry-run passed with fixture catalog and ephemeral Ed25519 key; no release or production secret was used.");
