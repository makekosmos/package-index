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
`KOSMOS_PACKAGE_RELEASE_PRIVATE_KEY`. The workflow never puts the private key
in arguments or logs, publishes the package archives before the
`catalog-<sequence>` release, refuses existing tags, and deletes its temporary
key file on every exit path.

The workflow builds the standalone crates in
`packages/{bigfrontend,greatfrontend,leetcode,codewars,hevy,toggl}` on
`windows-latest`. It packages each committed `manifest.json`, exact worker
executable, and `icon.png`, then rejects any artifact that is not the expected
Windows `source` package with a valid permissions and integration contract.
