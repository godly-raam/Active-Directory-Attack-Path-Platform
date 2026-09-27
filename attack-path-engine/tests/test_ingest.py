from conftest import dataset_sid


def test_loads_all_collections(dataset):
    sams = {(n.sam or "").lower() for n in dataset.nodes.values()}
    assert {"aliceanderson", "bobbrown", "carolclark", "svc_sql", "svc_dcsync"} <= sams
    kinds = {n.kind for n in dataset.nodes.values()}
    assert {"User", "Group", "Computer", "Domain", "OU"} <= kinds


def test_ace_edge_is_normalised(dataset):
    carol = dataset_sid(dataset, sam="carolclark")
    ou = dataset_sid(dataset, name="Engineering", kind="OU")
    assert any(
        e.source == carol and e.target == ou and e.kind == "GenericAll"
        for e in dataset.edges
    )


def test_dcsync_rights_are_mapped(dataset):
    svc = dataset_sid(dataset, sam="svc_dcsync")
    domain = dataset_sid(dataset, kind="Domain")
    dcsync_edges = [e for e in dataset.edges if e.kind == "DCSync" and e.source == svc]
    assert dcsync_edges
    assert all(e.target == domain for e in dcsync_edges)


def test_group_membership_edges(dataset):
    alice = dataset_sid(dataset, sam="aliceanderson")
    da = dataset_sid(dataset, sam="Domain Admins")
    assert any(e.source == alice and e.target == da and e.kind == "MemberOf" for e in dataset.edges)


def test_session_edges(dataset):
    alice = dataset_sid(dataset, sam="aliceanderson")
    dc01 = dataset_sid(dataset, sam="DC01$")
    assert any(e.source == alice and e.target == dc01 and e.kind == "HasSession" for e in dataset.edges)


def test_delegation_and_trust_edges(dataset):
    iis = dataset_sid(dataset, sam="SRV-IIS01$")
    assert any(e.kind == "AllowedToDelegate" and e.source == iis for e in dataset.edges)
    domain = dataset_sid(dataset, kind="Domain")
    assert any(e.kind == "TrustedBy" for e in dataset.edges)
    assert domain


def test_missing_input_raises():
    from ap_engine.ingest import IngestError, load

    try:
        load("/nonexistent/path/to/bloodhound.json")
    except IngestError:
        return
    raise AssertionError("expected IngestError")


def test_tolerates_alternate_shapes(tmp_path):
    import json

    from ap_engine.ingest import load

    payload = {"users": [{"ObjectIdentifier": "S-1-5-21-9-1", "Properties": {"samaccountname": "solo", "name": "Solo"}}]}
    path = tmp_path / "users.json"
    path.write_text(json.dumps(payload))
    ds = load(str(path))
    assert any((n.sam or "") == "solo" for n in ds.nodes.values())


def test_loads_sharphound_zip(tmp_path):
    import zipfile
    from pathlib import Path

    from ap_engine.ingest import load

    src = Path(__file__).resolve().parent / "fixtures" / "bloodhound"
    archive = tmp_path / "collection.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for json_file in sorted(src.glob("*.json")):
            zf.write(json_file, arcname=json_file.name)
    ds = load(str(archive))
    assert any((n.sam or "") == "aliceanderson" for n in ds.nodes.values())
