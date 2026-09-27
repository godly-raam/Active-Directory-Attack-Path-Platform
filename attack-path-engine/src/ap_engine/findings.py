"""Attribute-based findings.

These are weaknesses that do not necessarily form a graph path (you cannot
"walk" to a weak password), but they are exactly what makes a foothold turn
into a full compromise. They are reported alongside the path analysis so the
narrative is complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx


@dataclass
class Finding:
    category: str
    severity: str
    principals: list[str] = field(default_factory=list)
    detail: str = ""
    mitre: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "principals": self.principals,
            "detail": self.detail,
            "mitre": self.mitre,
        }


def _enabled(node: dict) -> bool:
    return node.get("enabled", True)


def collect_findings(graph: nx.DiGraph) -> list[Finding]:
    findings: list[Finding] = []

    kerberoastable: list[str] = []
    asrep: list[str] = []
    unconstrained: list[str] = []
    constrained: list[str] = []
    protocol_transition: list[str] = []
    shadow_cred: list[str] = []
    adcs_templates: list[str] = []
    web_enrollment: list[str] = []

    for sid, data in graph.nodes(data=True):
        props = data.get("props") or {}
        label = data.get("label", sid)
        kind = data.get("kind")

        if kind == "User" and _enabled(data):
            spns = props.get("serviceprincipalnames") or props.get("service_principal_names") or []
            if spns and label.lower() != "krbtgt":
                kerberoastable.append(label)
            if props.get("dontreqpreauth") or props.get("dont_require_preauth"):
                asrep.append(label)
            if props.get("unconstraineddelegation"):
                unconstrained.append(label)
            if props.get("trustedtoauth"):
                protocol_transition.append(label)
            if props.get("allowedtodelegate"):
                constrained.append(label)

        if kind == "Computer":
            if props.get("unconstraineddelegation"):
                unconstrained.append(label)
            if props.get("trustedtoauth"):
                protocol_transition.append(label)
            if props.get("allowedtodelegate"):
                constrained.append(label)

        if kind == "CertTemplate":
            name_flag = props.get("mspki-certificate-name-flag")
            if name_flag in (1, "1", 0x1) or props.get("enrollee_supplies_subject"):
                adcs_templates.append(label)

        if kind == "EnterpriseCA":
            if props.get("web_enrollment") or props.get("httpenrollment"):
                web_enrollment.append(label)

    # GenericAll / WriteAccountRestrictions on a user enables shadow credentials
    # (msDS-KeyCredentialLink) or password reset without knowing the old value.
    for src, dst, data in graph.edges(data=True):
        if data.get("kind") in {"GenericAll", "GenericWrite", "WriteAccountRestrictions"}:
            if graph.nodes.get(dst, {}).get("kind") == "User":
                shadow_cred.append(
                    f"{graph.nodes[src].get('label', src)} -> {graph.nodes[dst].get('label', dst)}"
                )

    if kerberoastable:
        findings.append(Finding("Kerberoastable service accounts", "high", sorted(set(kerberoastable)),
                                "Enabled accounts with an SPN and a crackable password. Request a service ticket and crack it offline.",
                                "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting"))
    if asrep:
        findings.append(Finding("AS-REP roastable accounts", "high", sorted(set(asrep)),
                                "Kerberos pre-authentication disabled; the AS-REP can be cracked offline.",
                                "T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting"))
    if unconstrained:
        findings.append(Finding("Unconstrained delegation", "critical", sorted(set(unconstrained)),
                                "Hosts/accounts that cache reusable TGTs. Coerce a privileged authentication to capture one.",
                                "T1558 - Steal or Forge Kerberos Tickets"))
    if constrained:
        findings.append(Finding("Constrained delegation targets", "medium", sorted(set(constrained)),
                                "Accounts permitted to delegate to specific SPNs; combined with protocol transition this is abusable.",
                                "T1558 - Steal or Forge Kerberos Tickets"))
    if protocol_transition:
        findings.append(Finding("Protocol transition delegation", "high", sorted(set(protocol_transition)),
                                "TrustedToAuthForDelegation lets a service obtain a ticket for any user without their password.",
                                "T1550.003 - Use Alternate Authentication Material: Pass the Ticket"))
    if adcs_templates:
        findings.append(Finding("AD CS vulnerable template (ESC1-style)", "critical", sorted(set(adcs_templates)),
                                "Template allows an enrollee-supplied subject with a Client Authentication EKU and low-priv enrol rights.",
                                "T1649 - Steal or Forge Authentication Certificates"))
    if web_enrollment:
        findings.append(Finding("AD CS web enrollment exposed", "high", sorted(set(web_enrollment)),
                                "HTTP enrollment endpoint enables NTLM relay to the CA (ESC8).",
                                "T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"))
    if shadow_cred:
        findings.append(Finding("Write access over user objects", "high", sorted(set(shadow_cred))[:25],
                                "GenericAll/WriteAccountRestrictions over users permits password reset or shadow credentials.",
                                "T1098 - Account Manipulation"))

    return findings
