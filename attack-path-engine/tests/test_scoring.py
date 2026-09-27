from types import SimpleNamespace

from ap_engine.scoring import EDGE_TO_MITRE, EDGE_WEIGHTS, PathScore, edge_weight


def _edges(*weights):
    return [SimpleNamespace(weight=w) for w in weights]


def test_rating_bands():
    assert PathScore.from_edges(_edges(0.5)).label == "trivial"
    assert PathScore.from_edges(_edges(1.5)).label == "trivial"
    assert PathScore.from_edges(_edges(2.0)).label == "easy"
    assert PathScore.from_edges(_edges(3.0)).label == "easy"
    assert PathScore.from_edges(_edges(5.0)).label == "moderate"
    assert PathScore.from_edges(_edges(6.0)).label == "moderate"
    assert PathScore.from_edges(_edges(6.1)).label == "hard"


def test_score_accumulates_and_rounds():
    score = PathScore.from_edges(_edges(0.3333, 0.3333, 0.3333))
    assert score.score == 1.0
    assert score.hops == 3


def test_edge_weight_lookup_and_default():
    assert edge_weight("DCSync") == EDGE_WEIGHTS["DCSync"]
    assert edge_weight("not-a-real-edge") == EDGE_WEIGHTS["Unknown"]


def test_mitre_map_covers_key_edges():
    for kind in ("DCSync", "GenericAll", "AllowedToDelegate", "HasSession", "Enroll"):
        assert kind in EDGE_TO_MITRE
