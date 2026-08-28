# Kosmos Package Index

Public binary-only distribution channel for **Kosmos Package Index**.

- Initial component line: 0.1.0.
- Source of truth: the private Kosmos monorepo.
- Status: metadata only; no standalone artifact is available until its build,
  signing, integrity, and updater checks pass.
- Releases are immutable and must include hashes and provenance. Private signing
  keys, tokens, source workspaces, build caches, and local artifacts never belong
  in this repository.

Engine API compatibility is versioned separately and remains 1.0.0. Package v1
schema remains 1.

## Operator publication

Run the `Publish Package v1` workflow with an immutable Kosmos commit SHA and
the next catalog sequence plus bounded ISO UTC timestamps:

```text
source_ref=<40-character Kosmos commit SHA>
sequence=<next strictly increasing integer>
issued_at=2026-08-02T16:00:00Z
expires_at=2026-09-01T16:00:00Z
```

The production environment must provide only these secret names:
`KOSMOS_SOURCE_REPO_TOKEN`, `KOSMOS_RELEASE_REPO_TOKEN`, and
`KOSMOS_PACKAGE_RELEASE_PRIVATE_KEY`. The workflow verifies source identity,
the prior sequence, package manifests, Engine API compatibility, archive
contents, hashes, and existing-release guards before creating a temporary key
file. It publishes immutable releases and deletes the key file on every exit
path.

The workflow builds the standalone crates in
`packages/{bigfrontend,greatfrontend,leetcode,codewars,hevy,toggl}` on
`windows-latest`. It packages each committed `manifest.json`, exact worker
executable, and `icon.png`, then rejects any artifact that is not the expected
Windows `source` package with a valid permissions and integration contract.

## Pull-request checks

The secret-free quality gate validates that every workflow declares explicit
permissions and pins actions to immutable commit SHAs. It runs fixture-based
schema, duplicate-ID, manifest, Engine API, hash, timestamp, sequence, and
signature/envelope tampering tests, plus a dry-run with an ephemeral Ed25519 key.
No GitHub token, release, or production signing secret is used:

```powershell
node scripts/check-workflow-contract.mjs
node --test scripts/validate-catalog-input.test.mjs
node scripts/dry-run.mjs
```

The fixture validator is intentionally separate from production publication:
the PR contract proves deterministic validation and signing-input handling,
while the production workflow remains the only path allowed to use release
credentials.

## Rollback and provenance

Releases are append-only: never overwrite a `catalog-N` tag or reuse a
sequence. To roll back, point consumers at the last known-good immutable
catalog release and investigate the failed release; do not delete or replace
the tag. Verify provenance by checking the release asset SHA-256, the embedded
Manifest v2 identity/version, the source commit recorded by the operator, and
the detached Ed25519 signature against the published key allowlist.
