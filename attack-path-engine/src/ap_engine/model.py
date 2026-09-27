"""Normalized graph model shared by the ingest and graph layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Node:
    """A single Active Directory principal or structural object."""

    sid: str
    name: str
    kind: str
    domain: str | None = None
    sam: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    highvalue: bool = False
    enabled: bool = True

    def display(self) -> str:
        return self.sam or self.name or self.sid


@dataclass
class Edge:
    """A directed relationship between two nodes."""

    source: str
    target: str
    kind: str
    label: str | None = None
    weight: float = 1.0
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class Dataset:
    """Everything parsed out of a BloodHound export."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        existing = self.nodes.get(node.sid)
        if existing is None:
            self.nodes[node.sid] = node
            return
        # Merge: keep the first non-empty field, but allow enrichment.
        if not existing.sam and node.sam:
            existing.sam = node.sam
        if not existing.domain and node.domain:
            existing.domain = node.domain
        existing.highvalue = existing.highvalue or node.highvalue
        existing.properties.update({k: v for k, v in node.properties.items() if v is not None})
