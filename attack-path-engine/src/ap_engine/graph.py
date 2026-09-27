"""Build the traversal graph from a parsed dataset.

Responsibilities:
  * materialise nodes and edges into a ``networkx.DiGraph``
  * resolve SPN delegation targets to hosts
  * propagate ACEs granted on an OU/container down to its children
  * mark high-value targets (Domain Admins, Tier 0, DCs, domains)
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

from .model import Dataset, Edge, Node
from .scoring import CONTAINMENT_PENALTY, edge_weight

HIGH_VALUE_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "domain controllers",
    "tier0-admins",
    "tier1_admins",
    "backup operators",
    "account operators",
    "server operators",
    "print operators",
    "certificate authority administrators",
}

# ACE rights that should flow from a container to its children.
PROPAGATABLE = {
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "AllExtendedRights",
    "ForceChangePassword",
    "AddMember",
    "WriteAccountRestrictions",
}

_STRUCTURAL_KINDS = {"OU", "Container", "Domain"}
_CHILD_KINDS = {"User", "Computer", "Group"}


def _ensure_node(graph: nx.DiGraph, sid: str, dataset: Dataset) -> None:
    if graph.has_node(sid):
        return
    node = dataset.nodes.get(sid)
    if node is None:
        node = Node(sid=sid, name=sid, kind="Unknown")
        dataset.nodes[sid] = node
    graph.add_node(
        sid,
        label=node.display(),
        kind=node.kind,
        domain=node.domain,
        highvalue=node.highvalue,
        enabled=node.enabled,
        props=node.properties,
    )


def _add_edge(graph: nx.DiGraph, edge: Edge) -> None:
    """Keep the cheapest edge between any ordered pair (best primitive)."""
    if graph.has_edge(edge.source, edge.target):
        existing = graph[edge.source][edge.target]
        if existing["weight"] <= edge.weight:
            return
    graph.add_edge(
        edge.source,
        edge.target,
        kind=edge.kind,
        weight=edge.weight,
        label=edge.label or edge.kind,
        props=edge.props,
        via=edge.props.get("via"),
    )


def _resolve_spn_targets(graph: nx.DiGraph, dataset: Dataset) -> None:
    """Map ``spn:HOST/service`` delegation targets onto real computer nodes."""
    host_index: dict[str, str] = {}
    for node in dataset.nodes.values():
        if node.kind != "Computer":
            continue
        candidates = [node.sam, node.name, node.properties.get("dnshostname")]
        for value in candidates:
            if value:
                host_index[str(value).lower()] = node.sid

    for edge in list(dataset.edges):
        if edge.kind != "AllowedToDelegate" or not edge.target.startswith("spn:"):
            continue
        spn = edge.props.get("spn", "")
        host = spn.split("/", 1)[1].split(":", 1)[0] if "/" in spn else spn
        host = host.lower()
        target = host_index.get(host) or host_index.get(host.split(".", 1)[0])
        if target and target != edge.source:
            spn_node = f"spn:{spn.lower()}"
            existing = dataset.nodes.get(spn_node)
            if existing is None:
                dataset.nodes[spn_node] = Node(sid=spn_node, name=spn, kind="SPN", domain=None)
            else:
                existing.kind = "SPN"
                existing.name = spn
            _ensure_node(graph, spn_node, dataset)
            graph.nodes[spn_node]["label"] = spn
            graph.nodes[spn_node]["kind"] = "SPN"
            _add_edge(graph, Edge(source=edge.source, target=spn_node, kind="AllowedToDelegate", weight=edge.weight, props=edge.props))
            _add_edge(graph, Edge(source=spn_node, target=target, kind="HostsService", weight=edge_weight("HostsService")))


def _dn_parent(dn: str) -> str | None:
    parts = [p.strip() for p in dn.split(",")]
    if len(parts) <= 1:
        return None
    return ",".join(parts[1:])


def _containment_children(dataset: Dataset) -> dict[str, list[str]]:
    """Map container SID -> direct child SIDs using distinguishedName."""
    dn_to_sid: dict[str, str] = {}
    for node in dataset.nodes.values():
        dn = node.properties.get("distinguishedname")
        if dn:
            dn_to_sid[str(dn).lower()] = node.sid

    children: dict[str, list[str]] = defaultdict(list)
    for node in dataset.nodes.values():
        dn = node.properties.get("distinguishedname")
        if not dn:
            continue
        current = _dn_parent(str(dn)).lower() if _dn_parent(str(dn)) else None
        while current:
            parent_sid = dn_to_sid.get(current)
            if parent_sid and dataset.nodes[parent_sid].kind in _STRUCTURAL_KINDS:
                children[parent_sid].append(node.sid)
                break
            current = _dn_parent(current).lower() if _dn_parent(current) else None
    return children


def _propagate_container_aces(graph: nx.DiGraph, dataset: Dataset, children: dict[str, list[str]]) -> None:
    """Apply ``principal -> OU`` ACEs to every descendant object."""
    descendants: dict[str, set[str]] = {}

    def collect(sid: str) -> set[str]:
        if sid in descendants:
            return descendants[sid]
        found: set[str] = set()
        for child in children.get(sid, []):
            found.add(child)
            found |= collect(child)
        descendants[sid] = found
        return found

    for sid in list(children):
        collect(sid)

    for edge in list(dataset.edges):
        target_node = dataset.nodes.get(edge.target)
        if target_node is None or target_node.kind not in _STRUCTURAL_KINDS:
            continue
        if edge.kind not in PROPAGATABLE:
            continue
        for child_sid in descendants.get(edge.target, set()):
            child = dataset.nodes.get(child_sid)
            if child is None or child.kind not in _CHILD_KINDS:
                continue
            _add_edge(
                graph,
                Edge(
                    source=edge.source,
                    target=child_sid,
                    kind=edge.kind,
                    weight=edge.weight * CONTAINMENT_PENALTY,
                    props={"via": "containment", "container": edge.target},
                ),
            )


def _mark_high_value(graph: nx.DiGraph, dataset: Dataset) -> None:
    for node in dataset.nodes.values():
        if node.kind == "Domain":
            node.highvalue = True
        if node.kind == "Group" and (node.sam or node.name or "").lower() in HIGH_VALUE_GROUPS:
            node.highvalue = True
        if node.kind == "Computer" and (node.properties.get("isdc") or node.properties.get("is_dc")):
            node.highvalue = True

    # Users/computers that are members of a high-value group are themselves
    # high value (resetting their password is game over).
    for edge in dataset.edges:
        if edge.kind != "MemberOf":
            continue
        group = dataset.nodes.get(edge.target)
        member = dataset.nodes.get(edge.source)
        if group and member and group.highvalue and member.kind in {"User", "Computer"}:
            member.highvalue = True

    for sid, node in dataset.nodes.items():
        if graph.has_node(sid):
            graph.nodes[sid]["highvalue"] = node.highvalue
            graph.nodes[sid]["kind"] = node.kind
            graph.nodes[sid]["label"] = node.display()
            graph.nodes[sid]["props"] = node.properties


def build_graph(dataset: Dataset) -> nx.DiGraph:
    """Return a directed graph ready for shortest-path analysis."""

    graph = nx.DiGraph()

    for node in dataset.nodes.values():
        graph.add_node(
            node.sid,
            label=node.display(),
            kind=node.kind,
            domain=node.domain,
            highvalue=node.highvalue,
            enabled=node.enabled,
            props=node.properties,
        )

    for edge in dataset.edges:
        _ensure_node(graph, edge.source, dataset)
        _ensure_node(graph, edge.target, dataset)
        _add_edge(graph, edge)

    _resolve_spn_targets(graph, dataset)

    children = _containment_children(dataset)
    _propagate_container_aces(graph, dataset, children)

    _mark_high_value(graph, dataset)
    return graph


def high_value_nodes(graph: nx.DiGraph) -> list[str]:
    return [sid for sid, data in graph.nodes(data=True) if data.get("highvalue")]


def summarize(graph: nx.DiGraph) -> dict:
    kinds: dict[str, int] = defaultdict(int)
    for _, data in graph.nodes(data=True):
        kinds[data.get("kind", "Unknown")] += 1
    edge_kinds: dict[str, int] = defaultdict(int)
    for _, _, data in graph.edges(data=True):
        edge_kinds[data.get("kind", "Unknown")] += 1
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "node_kinds": dict(sorted(kinds.items())),
        "edge_kinds": dict(sorted(edge_kinds.items())),
        "high_value": len(high_value_nodes(graph)),
    }
