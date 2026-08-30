#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { verifyPreviousPublication } from "./publish-catalog.mjs";

function args(argv) {
  const values = {};
  for (let i = 2; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!flag.startsWith("--") || i + 1 >= argv.length || argv[i + 1].startsWith("--")) throw new Error(`missing value for ${flag}`);
    values[flag.slice(2)] = argv[++i];
  }
  for (const key of ["bom", "catalog", "envelope", "signatures", "sequence"]) if (!values[key]) throw new Error(`required argument --${key}`);
  return values;
}

try {
  const values = args(process.argv);
  const bom = JSON.parse(await readFile(values.bom, "utf8"));
  await verifyPreviousPublication({
    catalogPath: values.catalog,
    envelopePath: values.envelope,
    signaturesPath: values.signatures,
    publicKey: bom.catalog.public_key,
    expectedSequence: Number(values.sequence),
    engineApiVersion: bom.compatibility.engine_api,
    signingKeyId: bom.catalog.signing_key_id,
  });
  console.log(`Verified previous catalog sequence ${values.sequence} envelope.`);
} catch (error) {
  console.error(`[previous-catalog] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
