"""Top-level analysis orchestration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import __version__
from .config import Config
from .findings import Finding, collect_findings
from .graph import build_graph, high_value_nodes, summarize
from .ingest import load
from .llm_ranker import RankedPath, rank_paths
from .paths import AttackPath, find_paths


@dataclass
class AnalysisResult:
    generated_at: str
    engine_version: str
    source: str
    summary: dict
    findings: list[Finding]
    paths: list[AttackPath]
    ranked: list[RankedPath]
    llm_used: bool
    llm_model: str
    owned: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "engine_version": self.engine_version,
            "source": self.source,
            "summary": self.summary,
            "llm_used": self.llm_used,
            "llm_model": self.llm_model,
            "findings": [finding.to_dict() for finding in self.findings],
            "ranked_paths": [item.to_dict() for item in self.ranked],
        }


def analyze(bloodhound_path: str, config: Config, owned: list[str] | None = None) -> AnalysisResult:
    dataset = load(bloodhound_path)
    graph = build_graph(dataset)
    findings = collect_findings(graph)

    owned_tokens = owned if owned is not None else config.owned
    paths = find_paths(graph, owned=owned_tokens, max_depth=config.max_depth, top_n=config.top_n)
    ranked, used_llm, model_label = rank_paths(paths, findings, config)

    summary = summarize(graph)
    summary["high_value_labels"] = sorted(
        graph.nodes[sid].get("label", sid) for sid in high_value_nodes(graph)
    )[:25]

    resolved_owned = sorted({item.path.source_label for item in ranked}) or [
        graph.nodes[sid].get("label", sid)
        for sid in (owned_tokens or [])
        if graph.has_node(sid)
    ]

    return AnalysisResult(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        engine_version=__version__,
        source=bloodhound_path,
        summary=summary,
        findings=findings,
        paths=paths,
        ranked=ranked,
        llm_used=used_llm,
        llm_model=model_label,
        owned=resolved_owned,
    )
