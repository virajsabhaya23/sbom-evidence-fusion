# Changelog

All notable changes will be documented here. This project follows Semantic Versioning and the Keep a Changelog structure.

## 0.2.0 - Unreleased

- Replace the graph-wide completeness gate for negative reachability with a
  query-local closure certificate. `unreachable` is now returned only when every
  node reachable from the query source has an authoritative outgoing dependency
  set; otherwise the verdict is `unknown` and the blocking opaque nodes are
  listed. Dense unrelated subgraphs can no longer justify a false negative.
- Reject reachability queries whose endpoints are absent from the fused graph
  instead of returning a positive self-reachability answer.

- Preserve npm resolution roles from `package-lock.json`. `optionalDependencies`,
  `peerDependencies` (with `peerDependenciesMeta`), and `devDependencies` are now
  ingested alongside `dependencies`, and each edge records its declared section,
  resolved path, and the lock entry's `dev`/`optional`/`devOptional`/`peer` flags.
- Runtime reachability now includes installed optional dependencies, excludes
  development-only edges, and never treats a peer dependency as an owned runtime
  child; peer relationships remain visible under the `all` context.
- An optional dependency that npm omitted is treated as a legitimate resolution
  outcome rather than a missing edge to repair.

- Preserve CycloneDX/SPDX artifact-hash provenance, quarantine edges around
  conflicting strong hashes, and round-trip confirmed hashes into repairs.

- Replace unsafe whole-PURL lowercasing with ECMA-427/type-aware parsing and
  canonical serialization through the official Python implementation.
- Retain original identity aliases and reject ambiguous opaque component-key
  collisions.
- Add adversarial case, qualifier, percent-encoding, ecosystem, and version
  parity tests.
- Prefer Maven dependency-tree JSON and harden the text fallback so classifier,
  type, scope, optionality, and depth survive as relationship evidence.
- Add compile/runtime/test-aware reachability for Maven graphs.
