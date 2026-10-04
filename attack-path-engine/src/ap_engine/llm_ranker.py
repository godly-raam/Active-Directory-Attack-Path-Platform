"""LLM-assisted ranking and explanation of attack paths.

The deterministic layer (this module's ``_offline_rank``) always runs, so the
engine is useful with no API key. When a key is configured we ask the model to
re-rank the candidate paths by *real-world* exploitability and explain them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .config import Config
from .findings import Finding
from .paths import AttackPath

_SYSTEM = (
    "You are a senior Active Directory red-team lead reviewing an attack-path "
    "report for an isolated training lab that the operator owns. You rank paths "
    "by real-world exploitability, not theoretical length. Prefer paths that "
    "need no special tooling, survive patching, and yield reusable credentials. "
    "Return ONLY valid JSON."
)

_INSTRUCTIONS = """\
Rank the candidate escalation paths below from most to least practically
exploitable for a competent operator with a foothold as one of the listed
sources. Consider: reliability, tooling required, number of prerequisites,
detection risk, and whether the final step yields Domain Admin or equivalent.

Return a JSON array, one object per path, in ranked order, with exactly these
keys:
  rank (int, 1-based)
  source (string)
  target (string)
  exploitability (int 1-10, 10 = trivial)
  explanation (2-4 sentences of plain English, describing the chain)
  prerequisites (short string)
  mitigation (short string, concrete and specific)
  mitigation_complexity (one of: low, medium, high)

Do not invent paths that are not in the input. Do not wrap the JSON in prose.
"""


@dataclass
class RankedPath:
    path: AttackPath
    rank: int
    exploitability: int
    explanation: str
    prerequisites: str
    mitigation: str
    mitigation_complexity: str
    origin: str  # "llm" | "deterministic"

    def to_dict(self) -> dict:
        return {
            "rank": self.rank,
            "source": self.path.source_label,
            "target": self.path.target_label,
            "score": self.path.score,
            "rating": self.path.label,
            "exploitability": self.exploitability,
            "explanation": self.explanation,
            "prerequisites": self.prerequisites,
            "mitigation": self.mitigation,
            "mitigation_complexity": self.mitigation_complexity,
            "mitre": self.path.mitre,
            "origin": self.origin,
            "steps": self.path.to_dict()["steps"],
        }


# ---------------------------------------------------------------------------
# Deterministic fallback
# ---------------------------------------------------------------------------

_MITIGATIONS = {
    "DCSync": "Remove the replication extended rights from non-Tier-0 principals.",
    "GenericAll": "Remove the GenericAll ACE and apply tiered admin delegation.",
    "GenericWrite": "Remove the ACE; use scoped delegation instead of broad writes.",
    "WriteDacl": "Remove the WriteDACL ACE; audit ACL changes with SACL logging.",
    "WriteOwner": "Remove ownership rights; monitor object ownership changes.",
    "Owns": "Reassign ownership to a Tier-0 admin group.",
    "ForceChangePassword": "Remove the reset-password delegation on the target.",
    "AddMember": "Restrict who can modify privileged group membership.",
    "AddSelf": "Remove self-membership rights on privileged groups.",
    "AllExtendedRights": "Remove inherited extended rights; re-ACL the OU.",
    "HasSession": "Enforce tiered administration and clean up privileged sessions.",
    "AdminTo": "Remove unnecessary local admin; use LAPS and tiered admin.",
    "AllowedToDelegate": "Remove constrained delegation or scope it to Tier 1 only.",
    "CanPSRemote": "Restrict WinRM access with group-managed policy.",
    "CanRDP": "Restrict RDP access; enforce jump hosts for admins.",
    "ExecuteDCOM": "Remove DCOM access for non-admins.",
    "Enroll": "Tighten enrollment rights and template subject settings.",
    "TrustedBy": "Review and tighten the forest trust; enable SID filtering.",
    "HostsService": "Run the service account as a managed service account.",
}


def _exploitability_from_score(score: float) -> int:
    value = int(round(10 - score))
    return max(1, min(10, value))


def _offline_rank(paths: list[AttackPath], findings: list[Finding]) -> list[RankedPath]:
    ranked: list[RankedPath] = []
    for index, path in enumerate(paths, start=1):
        chain = " then ".join(
            f"{step.kind} on {step.target_label}" for step in path.steps
        )
        explanation = (
            f"Starting as {path.source_label} with no privileges, the operator "
            f"can {chain}. This reaches {path.target_label} in {path.hops} step(s). "
            f"The chain relies on {' , '.join(sorted({s.kind for s in path.steps}))} "
            "and does not require writing custom tooling."
        )
        mitigations = sorted({_MITIGATIONS.get(step.kind, "Remove the misconfigured ACE.")
                              for step in path.steps})
        ranked.append(
            RankedPath(
                path=path,
                rank=index,
                exploitability=_exploitability_from_score(path.score),
                explanation=explanation,
                prerequisites=f"Foothold as {path.source_label}; network access to the targets.",
                mitigation=" ".join(mitigations),
                mitigation_complexity="medium" if path.score < 4 else "high",
                origin="deterministic",
            )
        )
    ranked.sort(key=lambda item: (-item.exploitability, item.path.hops))
    for position, item in enumerate(ranked, start=1):
        item.rank = position
    return ranked


# ---------------------------------------------------------------------------
# LLM path
# ---------------------------------------------------------------------------


def _build_payload(paths: list[AttackPath], findings: list[Finding]) -> str:
    payload = {
        "candidate_paths": [path.to_dict() for path in paths],
        "supporting_findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)


def _extract_json(text: str) -> list[dict]:
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        raise ValueError("no JSON array in model response")
    return json.loads(text[start : end + 1])


def rank_paths(
    paths: list[AttackPath],
    findings: list[Finding],
    config: Config,
) -> tuple[list[RankedPath], bool, str]:
    """Return ``(ranked, used_llm, model_label)``."""

    if not paths:
        return [], False, "none"

    if not config.llm_enabled:
        return _offline_rank(paths, findings), False, "deterministic"

    try:
        from litellm import completion
    except ImportError:
        return _offline_rank(paths, findings), False, "deterministic (litellm not installed)"

    try:
        response = completion(
            model=config.model,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {
                    "role": "user",
                    "content": f"{_INSTRUCTIONS}\n\nINPUT:\n{_build_payload(paths, findings)}",
                },
            ],
            api_key=config.api_key,
            base_url=config.base_url,
            custom_llm_provider=config.provider,
            max_tokens=4000,
        )
        text = response.choices[0].message.content
        items = _extract_json(text)
    except Exception as exc:  # noqa: BLE001 - degrade gracefully to deterministic
        fallback = _offline_rank(paths, findings)
        for item in fallback:
            item.explanation += f" (LLM ranking unavailable: {exc})"
        return fallback, False, "deterministic (llm error)"

    by_key = {(path.source_label, path.target_label, path.score): path for path in paths}
    ranked: list[RankedPath] = []
    for item in items:
        key = (item.get("source"), item.get("target"), item.get("score"))
        path = by_key.get(key)
        if path is None:
            # Fall back to matching on source+target only.
            for candidate in paths:
                if candidate.source_label == item.get("source") and candidate.target_label == item.get("target"):
                    path = candidate
                    break
        if path is None:
            continue
        ranked.append(
            RankedPath(
                path=path,
                rank=int(item.get("rank", len(ranked) + 1)),
                exploitability=int(item.get("exploitability", _exploitability_from_score(path.score))),
                explanation=str(item.get("explanation", "")).strip(),
                prerequisites=str(item.get("prerequisites", "")).strip(),
                mitigation=str(item.get("mitigation", "")).strip(),
                mitigation_complexity=str(item.get("mitigation_complexity", "medium")).strip(),
                origin="llm",
            )
        )

    if not ranked:
        return _offline_rank(paths, findings), False, "deterministic (empty llm parse)"

    ranked.sort(key=lambda item: item.rank)
    return ranked, True, config.model
