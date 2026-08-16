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

## Reachability safety
`reachable` is always a positive-path claim. `unreachable` is emitted only when graph completeness is >= 0.85. Otherwise absence of a path is reported as `unknown` with a reason.

## Non-goals
This project is not an SBOM generator, generic merger, vulnerability scanner, or GUAC replacement. It is an upstream evidence repair/reconciliation engine.
