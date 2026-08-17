from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from .identity import register_component
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
        return self.adjacency_for("all")

    def adjacency_for(self, context: str) -> dict[str, set[str]]:
        if context not in {"all", "compile", "runtime", "test"}:
            raise ValueError("context must be all, compile, runtime, or test")
        out: dict[str, set[str]] = defaultdict(set)
        for (a, b), decision in self.edges.items():
            eligible = context == "all" or any(_evidence_in_context(item, context) for item in decision.evidence)
            if decision.state in {"confirmed", "probable"} and eligible:
                out[a].add(b)
        return out


def _evidence_in_context(item: EdgeEvidence, context: str) -> bool:
    if item.source_type != "maven-resolution" or not item.relationship.get("scope"):
        return True
    scope = item.relationship["scope"]
    allowed = {
        "compile": {"compile", "provided", "system"},
        "runtime": {"compile", "runtime"},
        "test": {"compile", "provided", "runtime", "system", "test"},
    }
    return scope in allowed[context]


def fuse(graphs: list[SourceGraph]) -> FusionResult:
    components: dict[str, dict] = {}
    evidence: dict[tuple[str, str], list[EdgeEvidence]] = defaultdict(list)
    roots: set[str] = set()
    source_summaries = []
    for graph in graphs:
        for key, component in graph.components.items():
            register_component(components, key, component)
        roots.update(graph.roots)
        q = graph_quality(graph)
        source_summaries.append({"source_id": graph.source_id, "source_type": graph.source_type, **q, **graph.metadata})
        weight = SOURCE_WEIGHTS.get(graph.source_type, 0.70)
        for parent, child in graph.edges:
            relationships = graph.edge_metadata.get((parent, child)) or [{}]
            for relationship in relationships:
                evidence[(parent, child)].append(EdgeEvidence(graph.source_id, graph.source_type, parent, child, weight, graph.metadata.get("path", ""), relationship=relationship))
    decisions: dict[tuple[str, str], EdgeDecision] = {}
    for edge, items in evidence.items():
        # Multiple relationship variants from one source are useful semantic
        # evidence, but are not independent confidence observations.
        source_weights: dict[str, float] = {}
        for item in items:
            source_weights[item.source_id] = max(source_weights.get(item.source_id, 0.0), item.weight)
        conf = combine_confidence(list(source_weights.values()))
        conflicted=[node for node in edge if components.get(node,{}).get("material_identity")=="conflicted"]
        if conflicted:
            decisions[edge]=EdgeDecision(edge[0],edge[1],conf,"quarantined",items,
                "conflicting strong artifact hashes for " + ", ".join(conflicted))
        else:
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


def reachability(result: FusionResult, source: str, target: str, context: str = "all") -> dict:
    adj = result.adjacency_for(context)
    q = deque([(source, [source])])
    visited = {source}
    while q:
        node, path = q.popleft()
        if node == target:
            return {"verdict": "reachable", "path": path, "context": context, "completeness": overall_completeness(result)}
        for nxt in sorted(adj.get(node, ())):
            if nxt not in visited:
                visited.add(nxt); q.append((nxt, path + [nxt]))
    completeness = overall_completeness(result)
    if completeness >= 0.85:
        return {"verdict": "unreachable", "path": [], "context": context, "completeness": completeness}
    return {"verdict": "unknown", "path": [], "context": context, "completeness": completeness, "reason": "Insufficient dependency evidence for a safe closed-world unreachable conclusion."}
