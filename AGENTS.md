# Package Index agent guide

- Distribution metadata only: no credentials, private sources, caches, runtime
  binaries, or mutable sibling trees.
- Preserve immutable catalogs, exact hashes/provenance, monotonic catalog
  sequence, and signature checks. Use `rtk bun run check`.
- Shared BOM/catalog files have one writer; never bypass hooks or weaken gates.
- Report exact base/final SHA and PASS/FAIL/NOT_RUN. Use ephemeral keys only
  for local signing dry-runs; do not publish without explicit assignment.
