import json
import sys
from types import SimpleNamespace

from ap_engine.config import Config
from ap_engine.llm_ranker import rank_paths
from ap_engine.paths import find_paths


def test_offline_ranking_is_sorted_and_numbered(graph):
    paths = find_paths(graph)
    ranked, used_llm, model = rank_paths(paths, [], Config(offline=True))
    assert used_llm is False
    assert model == "deterministic"
    assert ranked
    assert [item.rank for item in ranked] == list(range(1, len(ranked) + 1))
    assert all(item.origin == "deterministic" for item in ranked)
    exploitability = [item.exploitability for item in ranked]
    assert exploitability == sorted(exploitability, reverse=True)


def test_no_paths_returns_empty():
    ranked, used_llm, model = rank_paths([], [], Config(offline=True))
    assert ranked == []
    assert used_llm is False
    assert model == "none"


def test_llm_enabled_requires_key():
    assert Config().llm_enabled is False
    assert Config(api_key="sk-test").llm_enabled is True
    assert Config(api_key="sk-test", offline=True).llm_enabled is False


def _fake_anthropic(text):
    class _Messages:
        def create(self, **_kwargs):
            block = SimpleNamespace(type="text", text=text)
            return SimpleNamespace(content=[block])

    class _Client:
        def __init__(self, **_kwargs):
            self.messages = _Messages()

    return SimpleNamespace(Anthropic=_Client)


def test_llm_response_is_used_when_parseable(monkeypatch, graph):
    paths = find_paths(graph)
    payload = json.dumps(
        [
            {
                "rank": 1,
                "source": path.source_label,
                "target": path.target_label,
                "score": path.score,
                "exploitability": 9,
                "explanation": "model explanation",
                "prerequisites": "foothold",
                "mitigation": "fix the ACL",
                "mitigation_complexity": "low",
            }
            for path in paths
        ]
    )
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic(payload))
    ranked, used_llm, model = rank_paths(paths, [], Config(api_key="sk-test", model="claude-test"))
    assert used_llm is True
    assert model == "claude-test"
    assert all(item.origin == "llm" for item in ranked)
    assert ranked[0].explanation == "model explanation"


def test_llm_failure_degrades_to_deterministic(monkeypatch, graph):
    paths = find_paths(graph)

    class _Boom:
        def __init__(self, **_kwargs):
            raise RuntimeError("network down")

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=_Boom))
    ranked, used_llm, model = rank_paths(paths, [], Config(api_key="sk-test", model="claude-test"))
    assert used_llm is False
    assert model == "deterministic (llm error)"
    assert ranked
    assert any("LLM ranking unavailable" in item.explanation for item in ranked)


def test_llm_empty_parse_degrades(monkeypatch, graph):
    paths = find_paths(graph)
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic("no json here"))
    ranked, used_llm, model = rank_paths(paths, [], Config(api_key="sk-test", model="claude-test"))
    assert used_llm is False
    assert model == "deterministic (llm error)"
    assert ranked
