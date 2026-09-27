"""BloodHound / SharpHound JSON ingestion.

Tolerant by design: SharpHound has shipped several JSON shapes over the years
(``{"data": [...]}``, ``{"users": [...]}``, bare lists, SID-keyed dicts) and
BloodHound CE adds more object types. This module normalises them all into the
:mod:`ap_engine.model` types.
"""

from __future__ import annotations

import glob
import json
import os
import zipfile
from typing import Any, Iterable

from .model import Dataset, Edge, Node
from .scoring import CONTAINMENT_PENALTY, edge_weight

COLLECTIONS = (
    "users",
    "computers",
    "groups",
    "domains",
    "ous",
    "gpos",
    "containers",
    "certtemplates",
    "enterprisecas",
    "cas",
)

COLLECTION_KIND = {
    "users": "User",
    "computers": "Computer",
    "groups": "Group",
    "domains": "Domain",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
    "certtemplates": "CertTemplate",
    "enterprisecas": "EnterpriseCA",
    "cas": "EnterpriseCA",
}

ACE_RIGHT_MAP: dict[str, str] = {
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",
    "Owns": "Owns",
    "AddMember": "AddMember",
    "AddSelf": "AddSelf",
    "ForceChangePassword": "ForceChangePassword",
    "AllExtendedRights": "AllExtendedRights",
    "WriteAccountRestrictions": "WriteAccountRestrictions",
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword",
    "ExecuteDCOM": "ExecuteDCOM",
    "CanRDP": "CanRDP",
    "CanPSRemote": "CanPSRemote",
    "DCSync": "DCSync",
    "GetChanges": "DCSync",
    "GetChangesAll": "DCSync",
    "AllowedToAct": "AllowedToAct",
    "Enroll": "Enroll",
    "AutoEnroll": "Enroll",
}

# Container-ish targets whose ACEs propagate to their children.
PROPAGATABLE_TARGET_KINDS = {"OU", "Container", "Domain"}

_ACL_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "AddMember",
    "AddSelf",
    "ForceChangePassword",
    "AllExtendedRights",
    "WriteAccountRestrictions",
    "ReadLAPSPassword",
    "ReadGMSAPassword",
    "DCSync",
    "AllowedToAct",
    "Enroll",
}


class IngestError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Payload discovery / shape handling
# ---------------------------------------------------------------------------


def _collection_from_name(filename: str, payload: Any) -> str:
    base = os.path.basename(filename).lower()
    for collection in COLLECTIONS:
        if collection in base:
            return collection
    singular = base.replace(".json", "").rstrip("s")
    for collection in COLLECTIONS:
        if collection.rstrip("s") == singular:
            return collection
    if isinstance(payload, dict):
        for collection in COLLECTIONS:
            if collection in payload:
                return collection
    return "unknown"


def _records_from_payload(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        for collection in COLLECTIONS:
            value = payload.get(collection)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        keyed = [
            v
            for v in payload.values()
            if isinstance(v, dict)
            and any(k in v for k in ("ObjectIdentifier", "objectid", "Properties", "props"))
        ]
        if keyed:
            return keyed
        if any(k in payload for k in ("ObjectIdentifier", "objectid", "Properties", "props")):
            return [payload]
    return []


def _iter_payloads(path: str) -> Iterable[tuple[str, Any]]:
    if os.path.isdir(path):
        for filename in sorted(glob.glob(os.path.join(path, "*.json"))):
            with open(filename, encoding="utf-8") as handle:
                yield filename, json.load(handle)
        return
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.lower().endswith(".json"):
                    yield name, json.loads(archive.read(name))
        return
    with open(path, encoding="utf-8") as handle:
        yield path, json.load(handle)


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _props(record: dict) -> dict:
    for key in ("Properties", "props"):
        value = record.get(key)
        if isinstance(value, dict):
            return value
    return record


def _sid(record: dict) -> str | None:
    for key in ("ObjectIdentifier", "objectid", "SID", "sid"):
        value = record.get(key)
        if value:
            return str(value)
    return None


def _is_highvalue(props: dict, kind: str) -> bool:
    if kind == "Domain":
        return True
    if props.get("highvalue") is True:
        return True
    if kind == "Computer" and (props.get("isdc") or props.get("is_dc")):
        return True
    return False


def _node_from_record(record: dict, kind: str, domain: str | None) -> Node | None:
    sid = _sid(record)
    props = _props(record)
    if not sid:
        return None
    sam = props.get("samaccountname") or props.get("sam")
    name = props.get("name") or sam or sid
    return Node(
        sid=sid,
        name=str(name),
        kind=kind,
        domain=props.get("domain") or domain,
        sam=str(sam).lower() if sam else None,
        properties=dict(props),
        highvalue=_is_highvalue(props, kind),
        enabled=bool(props.get("enabled", True)),
    )


def _edge(source: str, target: str, kind: str, **props: Any) -> Edge:
    return Edge(
        source=source,
        target=target,
        kind=kind,
        weight=edge_weight(kind),
        props=props or {},
    )


# ---------------------------------------------------------------------------
# Per-collection relationship extraction
# ---------------------------------------------------------------------------


def _extract_aces(record: dict, node: Node, edges: list[Edge]) -> None:
    for ace in record.get("Aces") or []:
        principal = ace.get("PrincipalSID")
        right = ace.get("RightName")
        if not principal or not right:
            continue
        mapped = ACE_RIGHT_MAP.get(right)
        if not mapped:
            continue
        edges.append(
            _edge(
                str(principal),
                node.sid,
                mapped,
                inherited_from=ace.get("InheritedFrom"),
                is_inherited=bool(ace.get("IsInherited")),
                object_type=ace.get("ObjectType"),
            )
        )


def _extract_members(record: dict, node: Node, edges: list[Edge]) -> None:
    for member in record.get("Members") or []:
        member_sid = member.get("ObjectIdentifier") or member.get("MemberId")
        if member_sid:
            edges.append(_edge(str(member_sid), node.sid, "MemberOf"))


def _extract_sessions(record: dict, node: Node, edges: list[Edge]) -> None:
    for key, privileged in (
        ("Sessions", False),
        ("PrivilegedSessions", True),
        ("RegistrySessions", False),
    ):
        block = record.get(key)
        if not isinstance(block, dict):
            continue
        for item in block.get("Results") or []:
            user_sid = item.get("UserSID") or item.get("ObjectIdentifier")
            if user_sid:
                edges.append(_edge(str(user_sid), node.sid, "HasSession", privileged=privileged))


def _extract_remote_access(record: dict, node: Node, edges: list[Edge]) -> None:
    mapping = {
        "LocalAdmins": "AdminTo",
        "RemoteDesktopUsers": "CanRDP",
        "DcomUsers": "ExecuteDCOM",
        "PSRemoteUsers": "CanPSRemote",
    }
    for key, kind in mapping.items():
        block = record.get(key)
        if not isinstance(block, dict):
            continue
        for item in block.get("Results") or []:
            sid = item.get("ObjectIdentifier") or item.get("MemberId")
            if sid:
                edges.append(_edge(str(sid), node.sid, kind))


def _extract_delegation(record: dict, node: Node, edges: list[Edge]) -> None:
    props = _props(record)
    targets = props.get("allowedtodelegate") or props.get("allowed_to_delegate") or []
    if isinstance(targets, str):
        targets = [targets]
    for spn in targets:
        spn = str(spn).strip()
        if not spn:
            continue
        spn_node = f"spn:{spn.lower()}"
        edges.append(_edge(node.sid, spn_node, "AllowedToDelegate", spn=spn))


def _extract_trusts(record: dict, node: Node, edges: list[Edge], dataset: Dataset) -> None:
    for trust in record.get("Trusts") or []:
        target_sid = trust.get("TargetDomainSid") or trust.get("TargetDomainName")
        if not target_sid:
            continue
        target_sid = str(target_sid)
        if target_sid not in dataset.nodes:
            dataset.nodes[target_sid] = Node(
                sid=target_sid,
                name=trust.get("TargetDomainName", target_sid),
                kind="Domain",
                domain=trust.get("TargetDomainName"),
                highvalue=True,
            )
        direction = trust.get("TrustDirection", "Unknown")
        edges.append(_edge(target_sid, node.sid, "TrustedBy", direction=direction))


def _extract_gpo_links(record: dict, node: Node, edges: list[Edge]) -> None:
    for link in record.get("Links") or []:
        guid = link.get("GUID") or link.get("GpoIdentifier") or link.get("ObjectIdentifier")
        if guid:
            edges.append(_edge(str(guid), node.sid, "GpLink", enforced=bool(link.get("IsEnforced"))))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load(path: str) -> Dataset:
    """Parse a BloodHound JSON file, a directory of them, or a SharpHound zip."""

    if not os.path.exists(path):
        raise IngestError(f"BloodHound input not found: {path}")

    dataset = Dataset(meta={"source": path})
    domain_by_sid: dict[str, str] = {}

    raw_collections: list[tuple[str, list[dict]]] = []
    for filename, payload in _iter_payloads(path):
        collection = _collection_from_name(filename, payload)
        records = _records_from_payload(payload)
        if records:
            raw_collections.append((collection, records))

    if not raw_collections:
        raise IngestError(
            f"No recognisable BloodHound records found in {path}. "
            "Expected SharpHound JSON/zip output."
        )

    # First pass: nodes (domains before others so domain attribution works).
    ordered = sorted(raw_collections, key=lambda item: item[0] != "domains")
    for collection, records in ordered:
        kind = COLLECTION_KIND.get(collection, "Base")
        for record in records:
            props = _props(record)
            domain = props.get("domain")
            node = _node_from_record(record, kind, domain)
            if node is None:
                continue
            if kind == "Domain":
                domain_by_sid[node.sid] = node.name
                dataset.meta.setdefault("domains", []).append(node.name)
            dataset.add_node(node)

    # Second pass: edges.
    for collection, records in raw_collections:
        kind = COLLECTION_KIND.get(collection, "Base")
        for record in records:
            sid = _sid(record)
            if not sid or sid not in dataset.nodes:
                continue
            node = dataset.nodes[sid]
            _extract_aces(record, node, dataset.edges)
            _extract_members(record, node, dataset.edges)
            _extract_sessions(record, node, dataset.edges)
            _extract_remote_access(record, node, dataset.edges)
            _extract_delegation(record, node, dataset.edges)
            _extract_gpo_links(record, node, dataset.edges)
            if kind == "Domain":
                _extract_trusts(record, node, dataset.edges, dataset)

    return dataset
