from conftest import graph_sid


def test_high_value_marking(graph):
    alice = graph_sid(graph, "aliceanderson")
    assert graph.nodes[alice]["highvalue"] is True

    domain = next(sid for sid, d in graph.nodes(data=True) if d.get("kind") == "Domain")
    assert graph.nodes[domain]["highvalue"] is True

    dc01 = next(
        sid
        for sid, d in graph.nodes(data=True)
        if d.get("kind") == "Computer" and d.get("highvalue")
    )
    assert dc01


def test_domain_admins_group_is_high_value(graph):
    da = graph_sid(graph, "Domain Admins")
    assert graph.nodes[da]["highvalue"] is True


def test_container_ace_propagation(graph):
    carol = graph_sid(graph, "carolclark")
    alice = graph_sid(graph, "aliceanderson")
    bob = graph_sid(graph, "bobbrown")
    assert graph.has_edge(carol, alice)
    assert graph.has_edge(carol, bob)
    assert graph[carol][alice]["kind"] == "GenericAll"
    assert graph[carol][alice].get("via") == "containment"


def test_container_ace_does_not_leak_outside_ou(graph):
    carol = graph_sid(graph, "carolclark")
    svc = graph_sid(graph, "svc_sql")
    # svc_sql lives under OU=ServiceAccounts, so carol's OU ACE must not reach it.
    assert not graph.has_edge(carol, svc)


def test_spn_delegation_resolves_to_host(graph):
    iis = graph_sid(graph, "SRV-IIS01$")
    spn_nodes = [sid for sid, d in graph.nodes(data=True) if d.get("kind") == "SPN"]
    assert spn_nodes, "expected an SPN node for the constrained delegation target"
    assert any(graph.has_edge(iis, spn) for spn in spn_nodes)
    host_edges = [d for _, _, d in graph.edges(data=True) if d.get("kind") == "HostsService"]
    assert host_edges


def test_node_properties_are_carried_into_graph(graph):
    svc = graph_sid(graph, "svc_sql")
    assert graph.nodes[svc]["props"].get("serviceprincipalnames")


def test_summary_counts(graph):
    from ap_engine.graph import summarize

    summary = summarize(graph)
    assert summary["nodes"] > 0
    assert summary["edges"] > 0
    assert summary["high_value"] >= 1
    assert "User" in summary["node_kinds"]
