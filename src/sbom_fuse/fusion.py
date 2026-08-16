from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from .model import EdgeDecision, EdgeEvidence, SourceGraph

SOURCE_WEIGHTS = {
    "npm-lock": 0.99,
    "pnpm-resolution": 0.99,
    "yarn-resolution": 0.99,
    "pip-resolution": 0.99,
    "maven-resolution": 0.99,
    "poetry-lock": 0.99,
    "runtime": 0.98,
    "build-graph": 0.97,
    "cyclonedx": 0.80,
    "spdx": 0.80,
    "sbom": 0.75,
}


def combine_confidence(weights: list[float]) -> float:
    miss = 1.0
    for w in weights:
        miss *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - miss


def state_for(confidence: float) -> str:
    if confidence >= 0.95:
        return "confirmed"
    if confidence >= 0.60:
        return "probable"
    return "unknown"


def graph_quality(graph: SourceGraph) -> dict:
    n = len(graph.components)
    m = len(graph.edges)
    participating = set()
    for a, b in graph.edges:
        participating.add(a); participating.add(b)
    orphan_count = max(0, n - len(participating))
    orphan_ratio = orphan_count / n if n else 1.0
    degenerate = n > 1 and (m == 0 or orphan_ratio >= 0.8)
    return {"components": n, "edges": m, "orphan_count": orphan_count, "orphan_ratio": round(orphan_ratio, 6), "degenerate": degenerate}


@dataclass
class FusionResult:
    components: dict[str, dict]
    edges: dict[tuple[str, str], EdgeDecision]
    sources: list[dict]
    roots: set[str]

    @property
    def adjacency(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = defaultdict(set)
        for (a, b), decision in self.edges.items():
            if decision.state in {"confirmed", "probable"}:
                out[a].add(b)
        return out


def fuse(graphs: list[SourceGraph]) -> FusionResult:
    components: dict[str, dict] = {}
    evidence: dict[tuple[str, str], list[EdgeEvidence]] = defaultdict(list)
    roots: set[str] = set()
    source_summaries = []
    for graph in graphs:
        components.update(graph.components)
        roots.update(graph.roots)
        q = graph_quality(graph)
        source_summaries.append({"source_id": graph.source_id, "source_type": graph.source_type, **q, **graph.metadata})
        weight = SOURCE_WEIGHTS.get(graph.source_type, 0.70)
        for parent, child in graph.edges:
            evidence[(parent, child)].append(EdgeEvidence(graph.source_id, graph.source_type, parent, child, weight, graph.metadata.get("path", "")))
    decisions: dict[tuple[str, str], EdgeDecision] = {}
    for edge, items in evidence.items():
        conf = combine_confidence([i.weight for i in items])
        decisions[edge] = EdgeDecision(edge[0], edge[1], conf, state_for(conf), items)
    return FusionResult(components, decisions, source_summaries, roots)


def overall_completeness(result: FusionResult) -> float:
    if not result.components:
        return 0.0
    nondegenerate = [s for s in result.sources if not s["degenerate"]]
    structural = min(1.0, len(result.edges) / max(1, len(result.components) - 1))
    source_factor = min(1.0, len(nondegenerate) / 2.0)
    authoritative = any(s["source_type"] in {"npm-lock", "pnpm-resolution", "yarn-resolution", "pip-resolution", "maven-resolution", "poetry-lock", "runtime", "build-graph"} and not s["degenerate"] for s in result.sources)
    auth_factor = 1.0 if authoritative else 0.55
    return round(0.45 * structural + 0.25 * source_factor + 0.30 * auth_factor, 6)


def reachability(result: FusionResult, source: str, target: str) -> dict:
    adj = result.adjacency
    q = deque([(source, [source])])
    visited = {source}
    while q:
        node, path = q.popleft()
        if node == target:
            return {"verdict": "reachable", "path": path, "completeness": overall_completeness(result)}
        for nxt in sorted(adj.get(node, ())):
            if nxt not in visited:
                visited.add(nxt); q.append((nxt, path + [nxt]))
    completeness = overall_completeness(result)
    if completeness >= 0.85:
        return {"verdict": "unreachable", "path": [], "completeness": completeness}
    return {"verdict": "unknown", "path": [], "completeness": completeness, "reason": "Insufficient dependency evidence for a safe closed-world unreachable conclusion."}
