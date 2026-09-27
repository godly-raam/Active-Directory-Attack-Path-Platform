"""Shared pytest fixtures and path setup for the engine tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "bloodhound"


@pytest.fixture()
def bloodhound_dir() -> str:
    return str(FIXTURE_DIR)


@pytest.fixture()
def dataset(bloodhound_dir):
    from ap_engine.ingest import load

    return load(bloodhound_dir)


@pytest.fixture()
def graph(dataset):
    from ap_engine.graph import build_graph

    return build_graph(dataset)


def dataset_sid(dataset, *, sam: str | None = None, name: str | None = None, kind: str | None = None) -> str:
    for sid, node in dataset.nodes.items():
        if sam is not None and (node.sam or "").lower() != sam.lower():
            continue
        if name is not None and (node.name or "").lower() != name.lower():
            continue
        if kind is not None and node.kind != kind:
            continue
        return sid
    raise KeyError(f"no dataset node matching sam={sam!r} name={name!r} kind={kind!r}")


def graph_sid(graph, label: str) -> str:
    for sid, data in graph.nodes(data=True):
        if (data.get("label") or "").lower() == label.lower():
            return sid
    raise KeyError(f"no graph node labelled {label!r}")
