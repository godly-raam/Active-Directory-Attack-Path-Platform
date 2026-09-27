from ap_engine.findings import collect_findings


def test_detects_seeded_misconfigurations(graph):
    findings = collect_findings(graph)
    categories = {f.category for f in findings}
    assert "Kerberoastable service accounts" in categories
    assert "AS-REP roastable accounts" in categories
    assert "Unconstrained delegation" in categories
    assert "Protocol transition delegation" in categories
    assert "Constrained delegation targets" in categories
    assert "Write access over user objects" in categories


def test_kerberoastable_lists_svc_sql(graph):
    findings = {f.category: f for f in collect_findings(graph)}
    assert "svc_sql" in findings["Kerberoastable service accounts"].principals
    assert "nopreauth_svc" in findings["AS-REP roastable accounts"].principals


def test_finding_shape_and_serialisation(graph):
    for finding in collect_findings(graph):
        assert finding.severity in {"low", "medium", "high", "critical"}
        payload = finding.to_dict()
        assert set(payload) == {"category", "severity", "principals", "detail", "mitre"}
