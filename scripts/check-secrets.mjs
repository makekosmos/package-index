#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const PLACEHOLDER = /^(?:$|example|sample|test|dummy|fake|changeme|replace(?:[-_ ]?me)?|your[-_ ]?(?:token|password|secret)|\$\{[^}]+\}|<[^>]+>)$/i;
const SECRET_PATTERNS = [
  ["private key", /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
  ["GitLab token", /\bglpat-[A-Za-z0-9_\-]{20,}\b/],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/],
  ["live API key", /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/],
];
const ASSIGNMENT = /\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9+/_-]+))/gi;

export function findSecrets(source, file) {
  const findings = [];
  for (const [kind, pattern] of SECRET_PATTERNS) {
    if (pattern.test(source)) findings.push(`${file}: ${kind}`);
  }
  for (const match of source.matchAll(ASSIGNMENT)) {
    const value = match[2] ?? match[3] ?? match[4];
    if (value.length >= 12 && !PLACEHOLDER.test(value)) {
      findings.push(`${file}: literal ${match[1]} value`);
    }
  }
  return findings;
}

export function trackedFiles() {
  const result = spawnSync("git", ["ls-files", "-z"], { encoding: "utf8" });
  if (result.error || result.status !== 0) throw new Error(`git ls-files failed${result.error ? `: ${result.error.message}` : ""}`);
  return result.stdout.split("\0").filter(Boolean);
}

export async function scanTrackedFiles() {
  const findings = [];
  for (const file of trackedFiles()) {
    const source = await readFile(file);
    if (source.includes(0)) continue;
    findings.push(...findSecrets(source.toString("utf8"), file));
  }
  return findings;
}

if (import.meta.main) {
  const findings = await scanTrackedFiles();
  if (findings.length) throw new Error(`secret scan failed:\n${findings.join("\n")}`);
  console.log(`Secret scan passed (${trackedFiles().length} tracked files).`);
}
