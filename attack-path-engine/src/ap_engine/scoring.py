"""Deterministic exploitability scoring.

Edge weights are "effort" values: lower means easier to abuse. They are not
CVE scores - they encode how much friction a competent operator expects when
traversing that edge, and they make the shortest-path search prefer realistic
routes over theoretically-short ones.
"""

from __future__ import annotations

from dataclasses import dataclass

# Effort to traverse a single edge. Lower = easier.
EDGE_WEIGHTS: dict[str, float] = {
    # Session / group material - often just reuse a token or add a member.
    "HasSession": 0.5,
    "AdminTo": 0.4,
    "MemberOf": 0.6,
    # Direct credential/identity takeover primitives.
    "ForceChangePassword": 0.7,
    "AddMember": 0.7,
    "AddSelf": 0.7,
    "DCSync": 0.3,
    "GenericAll": 0.8,
    "AllExtendedRights": 0.9,
    "WriteAccountRestrictions": 1.0,
    "ReadLAPSPassword": 0.8,
    "ReadGMSAPassword": 0.9,
    "AllowedToAct": 1.0,
    "AllowedToDelegate": 1.6,
    "Owns": 1.8,
    "WriteOwner": 1.7,
    "WriteDacl": 2.0,
    "GenericWrite": 1.4,
    # Remote access primitives - need valid creds and configuration.
    "CanPSRemote": 2.0,
    "ExecuteDCOM": 2.2,
    "CanRDP": 2.6,
    # Traversal helpers.
    "TrustedBy": 2.5,
    "GpLink": 1.5,
    "Contains": 0.0,  # containment itself is free; weight is added on propagation
    "Enroll": 1.2,
    "HostsService": 0.9,
    "Unknown": 3.0,
}

# Multiplier applied when an ACE is inherited through OU/container containment
# rather than directly on the target.
CONTAINMENT_PENALTY = 1.25

# Techniques keyed by edge kind, for the MITRE ATT&CK column of the report.
EDGE_TO_MITRE: dict[str, str] = {
    "DCSync": "T1003.006 - OS Credential Dumping: DCSync",
    "ForceChangePassword": "T1098 - Account Manipulation",
    "AddMember": "T1098 - Account Manipulation",
    "AddSelf": "T1098 - Account Manipulation",
    "GenericAll": "T1222 - File and Directory Permissions Modification",
    "GenericWrite": "T1222 - File and Directory Permissions Modification",
    "WriteDacl": "T1222 - File and Directory Permissions Modification",
    "WriteOwner": "T1222 - File and Directory Permissions Modification",
    "AllExtendedRights": "T1098 - Account Manipulation",
    "ReadLAPSPassword": "T1555 - Credentials from Password Stores",
    "ReadGMSAPassword": "T1555 - Credentials from Password Stores",
    "AllowedToDelegate": "T1558 - Steal or Forge Kerberos Tickets",
    "AllowedToAct": "T1550 - Use Alternate Authentication Material",
    "HasSession": "T1550 - Use Alternate Authentication Material",
    "AdminTo": "T1078 - Valid Accounts",
    "CanPSRemote": "T1021.006 - Remote Services: Windows Remote Management",
    "ExecuteDCOM": "T1021.003 - Remote Services: Distributed Component Object Model",
    "CanRDP": "T1021.001 - Remote Services: Remote Desktop Protocol",
    "Enroll": "T1649 - Steal or Forge Authentication Certificates",
}


@dataclass
class PathScore:
    score: float
    hops: int
    label: str

    @staticmethod
    def from_edges(edges: list) -> "PathScore":
        score = sum(getattr(e, "weight", 1.0) for e in edges)
        hops = len(edges)
        if score <= 1.5:
            label = "trivial"
        elif score <= 3.0:
            label = "easy"
        elif score <= 6.0:
            label = "moderate"
        else:
            label = "hard"
        return PathScore(score=round(score, 3), hops=hops, label=label)


def edge_weight(kind: str) -> float:
    return EDGE_WEIGHTS.get(kind, EDGE_WEIGHTS["Unknown"])
