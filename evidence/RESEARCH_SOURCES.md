# Research sources used for the build

Retrieved/verified 2026-08-14.

- CycloneDX — Software Dependencies: https://cyclonedx.org/use-cases/software-dependencies/
- CycloneDX — Specification Overview: https://cyclonedx.org/specification/overview/
- Interlynk `sbomasm`: https://github.com/interlynk-io/sbomasm
- Microsoft `sbom-tool` CLI reference: https://github.com/microsoft/sbom-tool/blob/main/docs/sbom-tool-cli-reference.md
- GUAC documentation: https://docs.guac.sh/guac/
- Tracker research papers for OC-009: arXiv 2607.22140, 2607.04614, 2601.23020, 2606.22827.

## Prior-art boundary
Existing tools already perform SBOM generation, aggregation, assembly, enrichment, and graph storage. This build therefore avoids claiming those capabilities as original. Its research target is evidence-level dependency-edge reconciliation with explicit provenance/confidence and uncertainty-aware reachability decisions.
