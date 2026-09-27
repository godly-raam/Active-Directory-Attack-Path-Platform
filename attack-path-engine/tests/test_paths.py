from conftest import graph_sid

from ap_engine.paths import default_owned, find_paths


def _domain_sid(graph):
    return next(sid for sid, d in graph.nodes(data=True) if d.get("kind") == "Domain")


def test_default_owned_excludes_high_value(graph):
    owned = set(default_owned(graph))
    assert graph_sid(graph, "carolclark") in owned
    assert graph_sid(graph, "aliceanderson") not in owned
    assert graph_sid(graph, "bobbrown") not in owned


def test_paths_from_carol_reach_tier_zero(graph):
    carol = graph_sid(graph, "carolclark")
    paths = find_paths(graph, owned=[carol])
    assert paths
    targets = {p.target_label for p in paths}
    assert {"aliceanderson", "bobbrown"} & targets
    assert all(p.source_label == "carolclark" for p in paths)


def test_default_analysis_finds_dcsync_shortcut(graph):
    paths = find_paths(graph)
    assert paths
    top = paths[0]
    assert top.score == 0.3
    assert top.target == _domain_sid(graph)
    assert any("T1003.006" in item for item in top.mitre)


def test_owned_token_resolution_by_sam(graph):
    paths = find_paths(graph, owned=["carolclark"])
    assert paths
    assert paths[0].source == graph_sid(graph, "carolclark")


def test_per_target_cap_limits_duplicate_routes(graph):
    carol = graph_sid(graph, "carolclark")
    paths = find_paths(graph, owned=[carol], per_target=1, top_n=50)
    targets = [p.target for p in paths]
    assert len(targets) == len(set(targets))


def test_path_serialisation_has_steps(graph):
    path = find_paths(graph)[0]
    payload = path.to_dict()
    assert payload["steps"]
    assert {"from", "to", "technique", "weight"} <= set(payload["steps"][0])
    assert path.node_sequence()[0] == path.source
