from __future__ import annotations
import json
from datetime import datetime, timezone
from .fusion import FusionResult, overall_completeness


def evidence_report(result: FusionResult) -> dict:
    return {
        "format": "sbom-evidence-fusion/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "completeness": overall_completeness(result),
        "sources": result.sources,
        "components": result.components,
        "edges": [d.to_dict() for _, d in sorted(result.edges.items())],
        "policy": {
            "confirmed_threshold": 0.95,
            "probable_threshold": 0.60,
            "unsafe_unreachable_below_completeness": 0.85,
            "confidence_combiner": "1 - product(1 - evidence_weight)",
        },
    }


def repaired_cyclonedx(result: FusionResult) -> dict:
    components = []
    for key, meta in sorted(result.components.items()):
        comp = {"type": "library", "bom-ref": key, "name": meta.get("name") or key, "version": meta.get("version") or ""}
        if key.startswith("pkg:"):
            comp["purl"] = key
        if meta.get("material_identity")!="conflicted":
            hashes={item["algorithm"]:item["value"] for item in meta.get("artifact_hashes",[])}
            if hashes: comp["hashes"]=[{"alg":algorithm,"content":value} for algorithm,value in sorted(hashes.items())]
        components.append(comp)
    deps = []
    by_parent: dict[str, list[str]] = {}
    for (parent, child), decision in result.edges.items():
        if decision.state in {"confirmed", "probable"}:
            by_parent.setdefault(parent, []).append(child)
    for key in sorted(result.components):
        deps.append({"ref": key, "dependsOn": sorted(by_parent.get(key, []))})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"properties": [
            {"name": "sbom-fuse:completeness", "value": str(overall_completeness(result))},
            {"name": "sbom-fuse:edge-evidence-sidecar", "value": "evidence-ledger.json"},
        ]},
        "components": components,
        "dependencies": deps,
    }



def repaired_spdx(result: FusionResult) -> dict:
    packages = []
    id_map = {}
    for idx, (key, meta) in enumerate(sorted(result.components.items()), 1):
        sid = f"SPDXRef-Package-{idx}"
        id_map[key] = sid
        pkg = {"SPDXID": sid, "name": meta.get("name") or key, "versionInfo": meta.get("version") or "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": False}
        if key.startswith("pkg:"):
            pkg["externalRefs"] = [{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":key}]
        if meta.get("material_identity")!="conflicted":
            names={"SHA-256":"SHA256","SHA-384":"SHA384","SHA-512":"SHA512"}
            hashes={item["algorithm"]:item["value"] for item in meta.get("artifact_hashes",[])}
            if hashes: pkg["checksums"]=[{"algorithm":names[algorithm],"checksumValue":value} for algorithm,value in sorted(hashes.items())]
        packages.append(pkg)
    relationships = []
    for (parent, child), decision in sorted(result.edges.items()):
        if decision.state in {"confirmed", "probable"}:
            relationships.append({"spdxElementId":id_map[parent],"relationshipType":"DEPENDS_ON","relatedSpdxElement":id_map[child],"comment":f"sbom-fuse confidence={decision.confidence:.6f}; evidence sidecar=evidence-ledger.json"})
    return {"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"sbom-fuse-repaired","documentNamespace":"https://sbom-fuse.invalid/repaired","creationInfo":{"created":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"creators":["Tool: sbom-evidence-fusion-0.1.0"]},"packages":packages,"relationships":relationships}


def source_diff(result: FusionResult) -> dict:
    fused = set(result.edges)
    sources = []
    for src in result.sources:
        sources.append({"source_id":src["source_id"],"source_type":src["source_type"],"components":src["components"],"edges":src["edges"],"degenerate":src["degenerate"]})
    return {"format":"sbom-fuse-diff/v1","fused_edge_count":len(fused),"sources":sources,"note":"Per-edge additions and provenance are listed in evidence-ledger.json; this summary preserves source graph quality for CI diffing."}

def dump_json(path, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
