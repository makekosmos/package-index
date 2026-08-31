# Kosmos Package Index

Public binary-only distribution channel for **Kosmos Package Index**.

- Initial component line: 0.1.0.
- Source of truth: the private Kosmos monorepo.
- Status: metadata only; no standalone artifact is available until its build,
  signing, integrity, and updater checks pass.
- Releases are immutable and must include hashes and provenance. Private signing
  keys, tokens, source workspaces, build caches, and local artifacts never belong
  in this repository.

Engine API compatibility is versioned separately and remains 1.0.0. Package
manifest schema remains 2.

## Operator publication

Run the `Publish Package v1` workflow with the immutable Package Index commit
containing the reviewed BOM, its path, and its catalog sequence:

```text
bom_ref=<40-character Package Index commit SHA>
bom_path=release/bom.v1.json
sequence=<BOM catalog sequence>
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

First-party application versions are maintained in the reviewed
`release/bom.v1.json`; publication reads that file rather than workflow source
edits and validates each repository/tag/archive tuple before any signing key is
materialized.

The workflow builds the standalone crates in
`packages/{bigfrontend,greatfrontend,leetcode,codewars,hevy,toggl}` on
`windows-latest`. It packages each committed `manifest.json`, exact worker
executable, and `icon.png`, then rejects any artifact that is not the expected
Windows `source` package with a valid permissions and integration contract.
Catalog construction and archive inspection live in the versioned
`scripts/publish-catalog.mjs` module; the workflow only orchestrates downloads,
preflight checks, signing, and immutable release creation.
The no-secret preflight checks the target release is unused and verifies the
previous catalog's exact downloaded bytes, detached signatures, and pinned
public key. The credentialed build step resolves each private BOM commit and
release tag exactly before the signing key is exposed. Archives are fail-closed on unsafe ZIP paths/metadata,
compression bombs, executable extras, missing license metadata, and wrong PE
platforms.

## Pull-request checks

The secret-free quality gate validates that every workflow declares explicit
permissions and pins actions to immutable commit SHAs. It runs fixture-based
schema, duplicate-ID, manifest, Engine API, hash, timestamp, sequence, and
signature/envelope tampering tests, plus a dry-run with an ephemeral Ed25519 key.
No GitHub token, release, or production signing secret is used:

```powershell
bun install
bun run check
```

The repository has no package dependencies, so Bun intentionally produces no
lockfile. The pinned Bun 1.3.14 install configures repository-owned pre-commit
and pre-push hooks without downloading packages.
The fixture validator is intentionally separate from production publication:
the PR contract proves deterministic validation and signing-input handling,
while the production workflow remains the only path allowed to use release
credentials.

Pre-commit runs the workflow contract and fixture tests when publication inputs
change. Pre-push runs the aggregate check; CI remains authoritative and adds
the secret scan and actionlint.

## Release BOM and dry-run

[`release/bom.v1.json`](release/bom.v1.json) is the reviewed v1 release BOM for
the Package catalog. It pins the Cortex/Core/Arca SDK/Imago commits, toolchains,
API compatibility, catalog sequence, signing key ID, and every app/source
package input. Application release refs are full commit SHAs with checked-in
archive SHA-256 and sizes. Source package archive hashes are filled after the
workers are built. The checked-in document has `state: candidate`; publication
changes only that field and the pending source artifact metadata to produce a
fully hashed `state: resolved` BOM attached to the immutable catalog release.

Validate the checked-in BOM without signing secrets:

```text
node scripts/validate-bom.mjs --bom release/bom.v1.json --sequence 12 --allow-pending-builds
node scripts/build-source-packages.mjs --bom release/bom.v1.json --cortex <cortex-checkout> --out out --sequence 12 --dry-run
```

Production publication takes only `bom_ref`; the Cortex commit is resolved from
that immutable BOM. The workflow verifies every release tag resolves to the BOM
SHA, downloads and hash-checks all external archives, builds and checks all
source archives, then signs and publishes `release-bom.v1.json` beside the
catalog artifacts.

## Rollback

Rollback selects an existing immutable `catalog-N` release and its attached
`release-bom.v1.json`; it never reconstructs versions from `main`, `latest`, or
manual release tags. Download the catalog and BOM from the same release, verify
the signed envelope and BOM hashes, and point the updater at that immutable
catalog. A new publication must use a new sequence and a reviewed BOM.

For provenance verification, use the pinned Cortex catalog verifier with the
catalog and envelope downloaded from the same release, and verify the BOM
artifact hashes with `validate-bom.mjs --verify-artifacts`. The verifier rejects
payload mismatch, unknown envelope shape, invalid Ed25519 signatures, duplicate
package IDs, mutable URLs, and incompatible Engine API ranges.
