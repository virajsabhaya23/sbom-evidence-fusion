# SBOM Evidence Fusion & Dependency Graph Repair Engine

**Tracker idea:** OC-009  
**Goal:** repair incomplete SBOM dependency graphs using independent evidence while preserving provenance and refusing unsafe "unreachable" conclusions when graph evidence is incomplete.

## Why this exists
CycloneDX explicitly notes that components omitted from a dependency graph may have **unknown dependencies**, not zero dependencies. Existing SBOM tools already aggregate or assemble documents; this project targets a narrower problem: reconcile dependency-edge evidence from independent sources, score relationship confidence, detect degenerate graphs, and keep reachability uncertainty visible.

## Implemented end-to-end flow
1. Ingest CycloneDX JSON, SPDX JSON, npm `package-lock.json`, pnpm/yarn JSON dependency trees, `pip inspect` JSON, `poetry.lock`, Maven `dependency:tree` text, and generic runtime/build evidence JSON.
2. Normalize component identity with the ECMA-427 reference implementation,
   registered type rules, and retained original aliases.
3. Detect empty/degenerate dependency graphs per source.
4. Fuse positive edge evidence with source-specific weights.
5. Classify edges as `confirmed`, `probable`, or `unknown`.
6. Emit repaired CycloneDX and SPDX documents, a graph-diff summary, and an evidence/provenance sidecar.
7. Answer reachability queries with `reachable`, `unreachable`, or `unknown`; absence of a path is **not** treated as proof when completeness is insufficient.
8. Run a deterministic 100-case synthetic benchmark that measures fusion recovery against known ground truth.

## Install
```bash
python -m pip install sbom-evidence-fusion
```

## Component identity safety

SBOMFuse never lowercases an entire Package URL. Supplied PURLs are parsed and
serialized by `packageurl-python`, so type-specific case, percent-encoding,
qualifier, and subpath rules are applied consistently. Components without a
PURL are constructed through the same implementation; unknown ecosystems use
the case-sensitive `generic` type. Original PURLs, source references, and name
spellings remain in `identity_aliases` for auditability. Invalid PURLs and
ambiguous opaque-ID collisions fail closed instead of silently merging nodes.

## Demo
```bash
sbom-fuse fuse examples/source-a.cdx.json examples/source-b.spdx.json examples/package-lock.json --out-dir demo-out
cat demo-out/evidence-ledger.json
```

Expected: the `alpha -> beta` relationship missing from the CycloneDX source is recovered from SPDX + package-lock evidence, and every repaired edge contains source provenance.

## Reachability
```bash
sbom-fuse reach examples/source-a.cdx.json examples/source-b.spdx.json examples/package-lock.json \
  --from pkg:npm/demo-app@1.0.0 --to pkg:npm/beta@2.0.0 --json
```

## Tests
```bash
python -m unittest discover -s tests -v
```

CI additionally runs 58 official validate/canonicalization vectors from a
pinned `package-url/purl-spec` revision across the core specification and the
seven ecosystems accepted by the current parsers. The pin makes results
reproducible; dependency/spec upgrades must deliberately update it.

## Benchmark
```bash
python benchmark/generate_benchmark.py
```
The included benchmark is deterministic and synthetic. It validates the fusion algorithm mechanically; it is **not** represented as the planned real-world 100-project benchmark across Syft/Trivy/Microsoft SBOM Tool/GUAC-style workflows.

## Architecture
- `parsers.py`: format-specific evidence ingestion
- `identity.py`: cross-source component normalization
- `fusion.py`: graph diagnostics, evidence fusion, confidence, safe reachability
- `exporters.py`: repaired CycloneDX + evidence ledger
- `cli.py`: local zero-service CLI

See `docs/SPEC.md` and `docs/THREAT_MODEL.md`.

## Originality boundary
This repository does **not** claim originality for SBOM aggregation, graph storage, hidden dependency discovery, or package-manager parsing. The proposed contribution is the combination of:
- explicit per-edge evidence provenance;
- confidence-based cross-source relationship repair;
- graph-degeneracy detection; and
- uncertainty-aware reachability that refuses a closed-world negative verdict when the evidence base is incomplete.

Those claims still require external validation and independent adoption before they can support any "major significance" argument.

## Current limitations
- Reference implementation supports CycloneDX JSON, SPDX JSON, npm package-lock v2/v3, pnpm/yarn JSON dependency-tree exports, pip inspect JSON, Poetry lock files, and Maven dependency-tree text.
- Raw pnpm/yarn lockfile YAML is intentionally not parsed without a YAML dependency; use their JSON resolution/list output as evidence.
- Confidence weights are transparent defaults, not statistically calibrated probabilities.
- Type-specific identity behavior follows package-url-python 0.17.x and the
  PURL definitions it implements; future type-definition changes require a
  dependency update and conformance rerun.
- Real-world 100-project multi-generator validation remains required before publication of comparative claims.

## License
Apache-2.0
