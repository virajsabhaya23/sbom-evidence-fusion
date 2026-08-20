from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True, order=True)
class ComponentKey:
    ecosystem: str
    name: str
    version: str = ""
    purl: str = ""

    @property
    def canonical(self) -> str:
        from .identity import canonical_component

        return canonical_component(self.name, self.version, self.purl, self.ecosystem)


@dataclass(frozen=True)
class EdgeEvidence:
    source_id: str
    source_type: str
    parent: str
    child: str
    weight: float
    locator: str = ""
    note: str = ""
    relationship: dict[str, Any] = field(default_factory=dict)


@dataclass
class EdgeDecision:
    parent: str
    child: str
    confidence: float
    state: str
    evidence: list[EdgeEvidence] = field(default_factory=list)
    quarantine_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent": self.parent,
            "child": self.child,
            "confidence": round(self.confidence, 6),
            "state": self.state,
            "evidence": [asdict(e) for e in self.evidence],
            "quarantine_reason": self.quarantine_reason,
        }


@dataclass
class SourceGraph:
    source_id: str
    source_type: str
    components: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)
    roots: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Appended to preserve the v0.1 positional constructor contract.
    edge_metadata: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    # Parents for which an authoritative source declared at least one required
    # dependency that it could not resolve to a component.
    incomplete_adjacency: set[str] = field(default_factory=set)
