# Evidence Fusion Specification v0.1

## Principle
A missing dependency edge is not treated as evidence of absence. The engine records positive edge evidence from independent sources and separately estimates whether the available graph is complete enough for a closed-world reachability conclusion.

## Edge confidence
Each source type has an evidence weight. Independent evidence is combined as `1 - product(1 - weight)`. Current defaults prioritize package-manager/build/runtime evidence over generator-only SBOM evidence.

States:
- `confirmed`: confidence >= 0.95
- `probable`: confidence >= 0.60
- `unknown`: below 0.60

Every emitted repaired relationship remains traceable to the source IDs and locators that supported it.

## Component identity

PURLs are canonicalized according to ECMA-427 and registered package-type
definitions through `packageurl-python`. Scheme/type and qualifier-key
normalization does not imply that namespace, name, or version are globally
case-insensitive. No whole-PURL case fold is permitted. Original source
identifiers are retained as aliases. Opaque, non-PURL keys may be reused only
for the same name/version pair; a conflicting reuse is an identity error, not
permission to fuse the components.

Strong artifact hashes (SHA-256/384/512) are material-identity evidence, not
ordinary aliases. Matching hashes merge with per-source provenance. Different
values for the same strong algorithm create an identity conflict and
quarantine incident edges from repaired adjacency. Missing hashes do not imply
a conflict; weak-only disagreement remains explicitly qualified evidence.

## Reachability safety
`reachable` is always a positive-path claim. `unreachable` is emitted only when graph completeness is >= 0.85. Otherwise absence of a path is reported as `unknown` with a reason.

## Non-goals
This project is not an SBOM generator, generic merger, vulnerability scanner, or GUAC replacement. It is an upstream evidence repair/reconciliation engine.
