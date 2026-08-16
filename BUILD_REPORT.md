# BUILD REPORT — OC-009

## Selected idea
**OC-009 — SBOM Evidence Fusion + Dependency Graph Repair Engine**

## Stack
Python 3.13.5 (standard-library runtime), setuptools packaging, `unittest` test suite.

## Implemented
- CycloneDX JSON and SPDX JSON ingestion.
- npm package-lock v2/v3 evidence.
- pnpm/yarn JSON dependency-tree resolution evidence.
- pip `inspect` JSON evidence.
- Poetry lockfile evidence.
- Maven `dependency:tree` text evidence.
- PURL-first component normalization.
- Empty/degenerate graph detection.
- Source-weighted dependency-edge fusion with provenance ledger.
- confirmed/probable/unknown relationship states.
- repaired CycloneDX export.
- uncertainty-aware reachability that refuses unsafe negative conclusions.
- deterministic 100-case synthetic benchmark and versioned evidence artifacts.

## Verification results
- Editable package build/install: PASS (`pip install -e . --no-build-isolation --no-deps`).
- Automated tests: PASS (13/13).
- Python compilation: PASS (`python -m compileall`).
- End-to-end fuse demo: PASS (4 sources, 3 normalized components, 2 fused edges; repaired CycloneDX/SPDX + diff + evidence ledger emitted).
- Reachability demo: PASS (`demo-app -> alpha -> beta`, completeness 1.0).
- Synthetic benchmark: PASS (100 deterministic cases; mean precision 1.000000; mean recall 0.983443; best-single mean recall 0.913266).

## Verification commands
```bash
python -m pip install -e . --no-build-isolation --no-deps
python -m unittest discover -s tests -v
python -m compileall -q src tests benchmark
sbom-fuse fuse examples/source-a.cdx.json examples/source-b.spdx.json examples/package-lock.json --out-dir demo-out
sbom-fuse reach examples/source-a.cdx.json examples/source-b.spdx.json examples/package-lock.json --from pkg:npm/demo-app@1.0.0 --to pkg:npm/beta@2.0.0 --json
python benchmark/generate_benchmark.py
```

## Important research limitation
The tracker calls for a **real 100-project multi-ecosystem benchmark using 3–4 major SBOM generators**. The included 100-case benchmark is synthetic and only validates algorithm mechanics/reproducibility. It does not satisfy the future real-world comparative validation requirement and no claim of real-world superiority is made.
