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


MAVEN_SCOPE_CONTEXTS = {
    "compile": {"compile", "provided", "system"},
    "runtime": {"compile", "runtime"},
    "test": {"compile", "provided", "runtime", "system", "test"},
}

# npm resolution roles. A peer dependency states a host-compatibility requirement
# rather than an owned runtime child, so it is never treated as ordinary
# reachability without an explicit "all" query.
NPM_ROLE_CONTEXTS = {
    "compile": {"runtime", "optional", "development"},
    "runtime": {"runtime", "optional"},
    "test": {"runtime", "optional", "development"},
}


def _evidence_in_context(item: EdgeEvidence, context: str) -> bool:
    if item.source_type == "maven-resolution" and item.relationship.get("scope"):
        return item.relationship["scope"] in MAVEN_SCOPE_CONTEXTS[context]
    if item.source_type == "npm-lock" and item.relationship.get("role"):
        return item.relationship["role"] in NPM_ROLE_CONTEXTS[context]
    return True


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


AUTHORITATIVE_SOURCES = {"npm-lock", "pnpm-resolution", "yarn-resolution", "pip-resolution",
                         "maven-resolution", "poetry-lock", "runtime", "build-graph"}


def overall_completeness(result: FusionResult) -> float:
    if not result.components:
        return 0.0
    nondegenerate = [s for s in result.sources if not s["degenerate"]]
    structural = min(1.0, len(result.edges) / max(1, len(result.components) - 1))
    source_factor = min(1.0, len(nondegenerate) / 2.0)
    authoritative = any(s["source_type"] in AUTHORITATIVE_SOURCES and not s["degenerate"] for s in result.sources)
    auth_factor = 1.0 if authoritative else 0.55
    return round(0.45 * structural + 0.25 * source_factor + 0.30 * auth_factor, 6)


def _nodes_with_declared_adjacency(result: FusionResult) -> set[str]:
    """Nodes whose outgoing dependency set an authoritative resolution source enumerated.

    Context filtering is deliberately not applied: a source that declared a node's
    dependencies still knows them even when none of them apply to this context.
    """
    declared: set[str] = set()
    for (parent, _), decision in result.edges.items():
        if any(item.source_type in AUTHORITATIVE_SOURCES for item in decision.evidence):
            declared.add(parent)
    return declared


def closure_certificate(result: FusionResult, source: str, context: str = "all") -> dict:
    """Prove (or refuse) that everything reachable from `source` has a known adjacency.

    A graph-wide density score cannot justify a negative security answer: unrelated
    dense components can mask the fact that the queried subgraph itself is opaque.
    """
    adj = result.adjacency_for(context)
    declared = _nodes_with_declared_adjacency(result)
    # Only an authoritative parent proves a childless node really has no dependencies.
    enumerated = {
        child for (_, child), decision in result.edges.items()
        if any(item.source_type in AUTHORITATIVE_SOURCES for item in decision.evidence)
    }
    visited, frontier, opaque = {source}, [source], []
    while frontier:
        node = frontier.pop()
        if node not in declared and node not in enumerated:
            opaque.append(node)
        for nxt in adj.get(node, ()):
            if nxt not in visited:
                visited.add(nxt); frontier.append(nxt)
    return {"source": source, "context": context, "visited": sorted(visited),
            "opaque_nodes": sorted(opaque), "closed": not opaque}


def reachability(result: FusionResult, source: str, target: str, context: str = "all") -> dict:
    if source not in result.components or target not in result.components:
        missing = sorted({source, target} - set(result.components))
        return {"verdict": "unknown", "path": [], "context": context,
                "completeness": overall_completeness(result),
                "reason": f"query endpoint(s) absent from the fused graph: {missing}"}
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
    certificate = closure_certificate(result, source, context)
    if certificate["closed"]:
        return {"verdict": "unreachable", "path": [], "context": context,
                "completeness": completeness, "closure": certificate}
    return {"verdict": "unknown", "path": [], "context": context, "completeness": completeness,
            "closure": certificate,
            "reason": ("cannot prove unreachable: these nodes reachable from the query source have no "
                       f"authoritative outgoing dependency evidence: {certificate['opaque_nodes']}")}
