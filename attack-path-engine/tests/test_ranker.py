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


def test_missing_litellm_degrades_to_deterministic(monkeypatch, graph):
    paths = find_paths(graph)
    monkeypatch.setitem(sys.modules, "litellm", None)
    ranked, used_llm, model = rank_paths(paths, [], Config(api_key="sk-test"))
    assert used_llm is False
    assert model == "deterministic (litellm not installed)"
    assert ranked


def _fake_litellm(text, calls=None):
    def completion(**kwargs):
        if calls is not None:
            calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])

    return SimpleNamespace(completion=completion)


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
    calls = []
    monkeypatch.setitem(sys.modules, "litellm", _fake_litellm(payload, calls))
    ranked, used_llm, model = rank_paths(
        paths, [], Config(api_key="sk-test", model="gpt-4o", provider="openai")
    )
    assert used_llm is True
    assert model == "gpt-4o"
    assert calls[0]["model"] == "gpt-4o"
    assert calls[0]["custom_llm_provider"] == "openai"
    assert all(item.origin == "llm" for item in ranked)
    assert ranked[0].explanation == "model explanation"


def test_llm_failure_degrades_to_deterministic(monkeypatch, graph):
    paths = find_paths(graph)

    def boom(**_kwargs):
        raise RuntimeError("network down")

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=boom))
    ranked, used_llm, model = rank_paths(paths, [], Config(api_key="sk-test", model="claude-test"))
    assert used_llm is False
    assert model == "deterministic (llm error)"
    assert ranked
    assert any("LLM ranking unavailable" in item.explanation for item in ranked)


def test_llm_empty_parse_degrades(monkeypatch, graph):
    paths = find_paths(graph)
    monkeypatch.setitem(sys.modules, "litellm", _fake_litellm("no json here"))
    ranked, used_llm, model = rank_paths(paths, [], Config(api_key="sk-test", model="claude-test"))
    assert used_llm is False
    assert model == "deterministic (llm error)"
    assert ranked
