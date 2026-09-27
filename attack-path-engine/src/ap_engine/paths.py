"""Shortest-path search from attacker-controlled principals to Tier 0."""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .graph import high_value_nodes
from .scoring import EDGE_TO_MITRE, PathScore


@dataclass
class PathStep:
    source: str
    target: str
    kind: str
    weight: float
    source_label: str
    target_label: str

    def describe(self) -> str:
        return f"{self.source_label} --[{self.kind}]--> {self.target_label}"


@dataclass
class AttackPath:
    source: str
    target: str
    steps: list[PathStep]
    score: float
    label: str
    hops: int
    mitre: list[str] = field(default_factory=list)

    @property
    def source_label(self) -> str:
        return self.steps[0].source_label if self.steps else self.source

    @property
    def target_label(self) -> str:
        return self.steps[-1].target_label if self.steps else self.target

    def node_sequence(self) -> tuple[str, ...]:
        if not self.steps:
            return (self.source,)
        return (self.steps[0].source,) + tuple(step.target for step in self.steps)

    def to_dict(self) -> dict:
        return {
            "source": self.source_label,
            "target": self.target_label,
            "score": self.score,
            "rating": self.label,
            "hops": self.hops,
            "mitre": self.mitre,
            "steps": [
                {
                    "from": step.source_label,
                    "to": step.target_label,
                    "technique": step.kind,
                    "weight": round(step.weight, 3),
                }
                for step in self.steps
            ],
        }


def _label(graph: nx.DiGraph, sid: str) -> str:
    data = graph.nodes.get(sid, {})
    return data.get("label") or sid


def default_owned(graph: nx.DiGraph) -> list[str]:
    """Every enabled, non-high-value user is a plausible starting point."""
    owned = []
    for sid, data in graph.nodes(data=True):
        if data.get("kind") != "User":
            continue
        if data.get("highvalue") or not data.get("enabled", True):
            continue
        owned.append(sid)
    return owned


def _resolve_owned(graph: nx.DiGraph, owned: list[str]) -> list[str]:
    if not owned:
        return default_owned(graph)
    resolved: list[str] = []
    by_sam = {
        (data.get("label") or "").lower(): sid
        for sid, data in graph.nodes(data=True)
        if data.get("kind") == "User"
    }
    for token in owned:
        if graph.has_node(token):
            resolved.append(token)
            continue
        key = token.lower()
        if graph.has_node(key):
            resolved.append(key)
        elif key in by_sam:
            resolved.append(by_sam[key])
    return resolved


def find_paths(
    graph: nx.DiGraph,
    owned: list[str] | None = None,
    max_depth: int = 12,
    top_n: int = 15,
    per_target: int = 2,
) -> list[AttackPath]:
    """Rank escalation paths from any owned principal to a high-value target.

    ``per_target`` caps how many distinct routes to the same target are kept, so
    the report shows breadth instead of ten variations of the same hop.
    """

    owned_sids = _resolve_owned(graph, owned or [])
    targets = set(high_value_nodes(graph))
    if not owned_sids or not targets:
        return []

    # Never treat an owned node as its own target.
    targets -= set(owned_sids)

    candidates: list[AttackPath] = []
    seen: set[tuple[str, ...]] = set()

    for source in owned_sids:
        try:
            lengths, paths = nx.single_source_dijkstra(
                graph, source, cutoff=max_depth, weight="weight"
            )
        except nx.NodeNotFound:
            continue
        for target, node_path in paths.items():
            if target not in targets:
                continue
            steps: list[PathStep] = []
            for src, dst in zip(node_path, node_path[1:]):
                data = graph[src][dst]
                steps.append(
                    PathStep(
                        source=src,
                        target=dst,
                        kind=data.get("kind", "Unknown"),
                        weight=float(data.get("weight", 1.0)),
                        source_label=_label(graph, src),
                        target_label=_label(graph, dst),
                    )
                )
            key = tuple(node_path)
            if key in seen:
                continue
            seen.add(key)
            score = PathScore.from_edges(steps)
            mitre = sorted({EDGE_TO_MITRE[step.kind] for step in steps if step.kind in EDGE_TO_MITRE})
            candidates.append(
                AttackPath(
                    source=source,
                    target=target,
                    steps=steps,
                    score=score.score,
                    label=score.label,
                    hops=score.hops,
                    mitre=mitre,
                )
            )

    # Keep the cheapest few routes per target, then the cheapest overall.
    by_target: dict[str, list[AttackPath]] = {}
    for path in candidates:
        by_target.setdefault(path.target, []).append(path)

    trimmed: list[AttackPath] = []
    for group in by_target.values():
        group.sort(key=lambda p: (p.score, p.hops))
        trimmed.extend(group[:per_target])

    trimmed.sort(key=lambda p: (p.score, p.hops, p.source_label))
    return trimmed[:top_n]
